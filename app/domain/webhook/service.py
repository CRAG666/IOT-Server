"""Webhook registration and HMAC-signed delivery."""

from __future__ import annotations

import asyncio
import hashlib
import hmac
import json
import logging
import secrets
from datetime import datetime, timezone
from typing import Any
from uuid import UUID

import httpx
from sqlmodel import Session, select

from app.config import settings
from app.domain.webhook.models import WebhookEndpoint

logger = logging.getLogger(__name__)


class WebhookService:
    def __init__(self, session: Session) -> None:
        self._session = session

    def register(self, owner_id: UUID, url: str, event_types: str) -> WebhookEndpoint:
        endpoint = WebhookEndpoint(
            owner_id=owner_id,
            url=url,
            event_types=event_types,
            secret=secrets.token_hex(32),
        )
        self._session.add(endpoint)
        self._session.commit()
        self._session.refresh(endpoint)
        return endpoint

    def list_for_owner(self, owner_id: UUID) -> list[WebhookEndpoint]:
        return list(self._session.exec(
            select(WebhookEndpoint).where(
                WebhookEndpoint.owner_id == owner_id,
                WebhookEndpoint.is_active == True,  # noqa: E712
            )
        ).all())

    def delete(self, webhook_id: UUID, owner_id: UUID) -> None:
        endpoint = self._session.get(WebhookEndpoint, webhook_id)
        if endpoint and endpoint.owner_id == owner_id:
            endpoint.is_active = False
            self._session.add(endpoint)
            self._session.commit()

    def get_by_event(self, event_type: str) -> list[WebhookEndpoint]:
        """Return all active endpoints subscribed to *event_type*."""
        all_active = self._session.exec(
            select(WebhookEndpoint).where(WebhookEndpoint.is_active == True)  # noqa: E712
        ).all()
        return [w for w in all_active if event_type in w.event_types.split(",")]


async def deliver_event(event_type: str, payload: dict[str, Any], endpoints: list[WebhookEndpoint]) -> None:
    """Fire-and-forget delivery of an event to all matching webhook endpoints."""
    body = json.dumps({"event": event_type, "timestamp": datetime.now(timezone.utc).isoformat(), "data": payload})

    async def _deliver(endpoint: WebhookEndpoint) -> None:
        sig = hmac.new(endpoint.secret.encode(), body.encode(), hashlib.sha256).hexdigest()
        headers = {
            "Content-Type": "application/json",
            "X-IoTmx-Event": event_type,
            "X-IoTmx-Signature": f"sha256={sig}",
        }
        for attempt in range(1, settings.WEBHOOK_MAX_RETRIES + 1):
            try:
                async with httpx.AsyncClient(timeout=settings.WEBHOOK_TIMEOUT_SECONDS) as client:
                    resp = await client.post(str(endpoint.url), content=body, headers=headers)
                    if resp.is_success:
                        return
                    logger.warning("Webhook %s attempt %d returned %d", endpoint.url, attempt, resp.status_code)
            except Exception as exc:
                logger.warning("Webhook %s attempt %d failed: %s", endpoint.url, attempt, exc)
            await asyncio.sleep(2 ** attempt)

    await asyncio.gather(*[_deliver(ep) for ep in endpoints], return_exceptions=True)
