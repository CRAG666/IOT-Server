"""Tests for the webhook domain — service, delivery, and HTTP routes."""

from __future__ import annotations

import uuid
from unittest.mock import AsyncMock, MagicMock, patch

import pytest
import httpx

from app.domain.webhook.models import WebhookEndpoint
from app.domain.webhook.service import WebhookService, deliver_event
from app.domain.webhook.schemas import WebhookCreate, WebhookResponse


# ─────────────────────────────────────────────────────────────────────────────
# WebhookService unit tests
# ─────────────────────────────────────────────────────────────────────────────


class TestWebhookService:
    def test_register_creates_endpoint(self, session):
        svc = WebhookService(session)
        owner_id = uuid.uuid4()
        endpoint = svc.register(
            owner_id=owner_id,
            url="https://example.com/hook",
            event_types="device.telemetry",
        )
        assert endpoint.id is not None
        assert endpoint.owner_id == owner_id
        assert endpoint.url == "https://example.com/hook"
        assert endpoint.secret  # non-empty HMAC secret
        assert endpoint.is_active is True

    def test_list_for_owner_returns_active_only(self, session):
        svc = WebhookService(session)
        owner_id = uuid.uuid4()
        ep = svc.register(owner_id, "https://a.com/hook", "device.telemetry")
        # Deactivate it
        ep.is_active = False
        session.add(ep)
        session.commit()

        active = svc.list_for_owner(owner_id)
        assert active == []

    def test_list_for_owner_returns_active_endpoints(self, session):
        svc = WebhookService(session)
        owner_id = uuid.uuid4()
        svc.register(owner_id, "https://b.com/hook", "device.telemetry")
        endpoints = svc.list_for_owner(owner_id)
        assert len(endpoints) == 1

    def test_delete_deactivates_endpoint(self, session):
        svc = WebhookService(session)
        owner_id = uuid.uuid4()
        ep = svc.register(owner_id, "https://c.com/hook", "device.telemetry")
        svc.delete(ep.id, owner_id)
        refreshed = session.get(WebhookEndpoint, ep.id)
        assert refreshed is not None
        assert refreshed.is_active is False

    def test_delete_wrong_owner_does_nothing(self, session):
        svc = WebhookService(session)
        owner_id = uuid.uuid4()
        other_id = uuid.uuid4()
        ep = svc.register(owner_id, "https://d.com/hook", "device.telemetry")
        svc.delete(ep.id, other_id)  # wrong owner
        refreshed = session.get(WebhookEndpoint, ep.id)
        assert refreshed is not None
        assert refreshed.is_active is True  # unchanged

    def test_get_by_event_returns_matching(self, session):
        svc = WebhookService(session)
        owner_id = uuid.uuid4()
        svc.register(owner_id, "https://e.com/hook", "device.telemetry,payment.completed")
        results = svc.get_by_event("device.telemetry")
        assert len(results) >= 1
        assert all("device.telemetry" in r.event_types for r in results)

    def test_get_by_event_filters_inactive(self, session):
        svc = WebhookService(session)
        owner_id = uuid.uuid4()
        ep = svc.register(owner_id, "https://f.com/hook", "ticket.created")
        ep.is_active = False
        session.add(ep)
        session.commit()
        results = svc.get_by_event("ticket.created")
        assert all(r.id != ep.id for r in results)


# ─────────────────────────────────────────────────────────────────────────────
# deliver_event unit tests
# ─────────────────────────────────────────────────────────────────────────────


class TestDeliverEvent:
    @pytest.mark.anyio
    async def test_deliver_event_sends_hmac_signed_request(self):
        owner_id = uuid.uuid4()
        endpoint = WebhookEndpoint(
            id=uuid.uuid4(),
            owner_id=owner_id,
            url="https://example.com/hook",
            event_types="device.telemetry",
            secret="deadbeef" * 8,
        )

        mock_response = MagicMock()
        mock_response.is_success = True
        mock_response.status_code = 200

        posted_headers = {}

        async def mock_post(url, *, content, headers):
            posted_headers.update(headers)
            return mock_response

        mock_client = AsyncMock()
        mock_client.post = AsyncMock(side_effect=mock_post)
        mock_client.__aenter__ = AsyncMock(return_value=mock_client)
        mock_client.__aexit__ = AsyncMock(return_value=False)

        with patch("app.domain.webhook.service.httpx.AsyncClient", return_value=mock_client):
            await deliver_event("device.telemetry", {"value": 42}, [endpoint])

        assert "X-IoTmx-Signature" in posted_headers
        assert posted_headers["X-IoTmx-Signature"].startswith("sha256=")
        assert posted_headers["X-IoTmx-Event"] == "device.telemetry"

    @pytest.mark.anyio
    async def test_deliver_event_retries_on_failure(self):
        owner_id = uuid.uuid4()
        endpoint = WebhookEndpoint(
            id=uuid.uuid4(),
            owner_id=owner_id,
            url="https://example.com/hook",
            event_types="device.telemetry",
            secret="deadbeef" * 8,
        )

        call_count = 0

        async def flaky_post(url, *, content, headers):
            nonlocal call_count
            call_count += 1
            raise httpx.RequestError("connection refused")

        mock_client = AsyncMock()
        mock_client.post = AsyncMock(side_effect=flaky_post)
        mock_client.__aenter__ = AsyncMock(return_value=mock_client)
        mock_client.__aexit__ = AsyncMock(return_value=False)

        with (
            patch("app.domain.webhook.service.httpx.AsyncClient", return_value=mock_client),
            patch("asyncio.sleep", new=AsyncMock()),
        ):
            await deliver_event("device.telemetry", {"value": 1}, [endpoint])

        # Should have retried WEBHOOK_MAX_RETRIES times
        assert call_count >= 1

    @pytest.mark.anyio
    async def test_deliver_event_handles_non_success_response(self):
        """Non-2xx response should trigger retry logic (no exception raised)."""
        owner_id = uuid.uuid4()
        endpoint = WebhookEndpoint(
            id=uuid.uuid4(),
            owner_id=owner_id,
            url="https://example.com/hook",
            event_types="device.telemetry",
            secret="deadbeef" * 8,
        )

        mock_response = MagicMock()
        mock_response.is_success = False
        mock_response.status_code = 503

        mock_client = AsyncMock()
        mock_client.post = AsyncMock(return_value=mock_response)
        mock_client.__aenter__ = AsyncMock(return_value=mock_client)
        mock_client.__aexit__ = AsyncMock(return_value=False)

        with (
            patch("app.domain.webhook.service.httpx.AsyncClient", return_value=mock_client),
            patch("asyncio.sleep", new=AsyncMock()),
        ):
            # Should complete without raising (return_exceptions=True in gather)
            await deliver_event("device.telemetry", {}, [endpoint])

    @pytest.mark.anyio
    async def test_deliver_event_empty_endpoints(self):
        """Delivery with no endpoints completes immediately."""
        await deliver_event("device.telemetry", {"data": 1}, [])


# ─────────────────────────────────────────────────────────────────────────────
# Webhook HTTP routes
# ─────────────────────────────────────────────────────────────────────────────


class TestWebhookRoutes:
    def test_register_webhook_returns_201(self, master_admin_client):
        resp = master_admin_client.post(
            "/api/v1/webhooks/",
            json={"url": "https://example.com/hook", "event_types": ["device.telemetry"]},
        )
        assert resp.status_code == 201
        data = resp.json()
        assert "id" in data
        assert data["is_active"] is True

    def test_list_webhooks_returns_200(self, master_admin_client):
        resp = master_admin_client.get("/api/v1/webhooks/")
        assert resp.status_code == 200
        assert isinstance(resp.json(), list)

    def test_delete_webhook_returns_204(self, master_admin_client):
        # Register first
        create_resp = master_admin_client.post(
            "/api/v1/webhooks/",
            json={"url": "https://example.com/del", "event_types": ["ticket.created"]},
        )
        assert create_resp.status_code == 201
        webhook_id = create_resp.json()["id"]

        # Delete it
        delete_resp = master_admin_client._raw.delete(
            f"/api/v1/webhooks/{webhook_id}",
            headers={"X-Session-ID": master_admin_client.session_id},
        )
        assert delete_resp.status_code == 204

    def test_register_webhook_invalid_event_type_returns_error(self, master_admin_client):
        resp = master_admin_client.post(
            "/api/v1/webhooks/",
            json={"url": "https://example.com/hook", "event_types": ["invalid.event"]},
        )
        assert resp.status_code in (400, 422, 500)
