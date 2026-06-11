"""Tests for the self-service onboarding flow (register + email verification)."""

from __future__ import annotations

from datetime import datetime
from unittest.mock import AsyncMock, patch

import fakeredis
import pytest
from sqlmodel import Session

from app.domain.onboarding.service import OnboardingService, _TOKEN_PREFIX
from app.database.model import Administrator, NonCriticalPersonalData, SensitiveData
from app.shared.exceptions import AlreadyExistsException


# ─────────────────────────────────────────────────────────────────────────────
# Helpers
# ─────────────────────────────────────────────────────────────────────────────


def _valkey_mock():
    """Return a (client, patcher) pair for patching valkey.from_url."""
    fake = fakeredis.FakeAsyncValkey(decode_responses=True)
    return fake


# ─────────────────────────────────────────────────────────────────────────────
# OnboardingService.register
# ─────────────────────────────────────────────────────────────────────────────


class TestOnboardingRegister:
    @pytest.mark.anyio
    async def test_register_creates_inactive_admin(self, session):
        fake_valkey = _valkey_mock()

        async def fake_from_url(*args, **kwargs):
            return fake_valkey

        with (
            patch("app.domain.onboarding.service.send_verification_email", new=AsyncMock()),
            patch("valkey.asyncio.from_url", new=fake_from_url),
        ):
            svc = OnboardingService(session)
            token = await svc.register(
                first_name="Alice",
                last_name="Smith",
                email="alice@example.com",
                password="TestPass123!",
            )

        assert token  # non-empty token returned
        # The token should be stored in fakeredis
        raw = await fake_valkey.get(f"{_TOKEN_PREFIX}{token}")
        assert raw is not None  # stored

        # Admin is inactive until verified
        admin = session.exec(
            __import__("sqlmodel", fromlist=["select"]).select(Administrator)
        ).first()
        assert admin is not None
        # NonCriticalPersonalData should be inactive
        nc = session.get(NonCriticalPersonalData, admin.sensitive_data.non_critical_data_id)
        assert nc is None or nc.is_active is False

    @pytest.mark.anyio
    async def test_register_duplicate_email_raises(self, session):
        """Second registration with the same email raises AlreadyExistsException."""
        fake_valkey = _valkey_mock()

        async def fake_from_url(*args, **kwargs):
            return fake_valkey

        with (
            patch("app.domain.onboarding.service.send_verification_email", new=AsyncMock()),
            patch("valkey.asyncio.from_url", new=fake_from_url),
        ):
            svc = OnboardingService(session)
            await svc.register(
                first_name="Bob",
                last_name="Jones",
                email="bob@example.com",
                password="TestPass123!",
            )
            with pytest.raises(AlreadyExistsException):
                await svc.register(
                    first_name="Bob2",
                    last_name="Jones2",
                    email="bob@example.com",
                    password="Other123!",
                )

    @pytest.mark.anyio
    async def test_register_sends_verification_email(self, session):
        fake_valkey = _valkey_mock()
        mock_email = AsyncMock()

        async def fake_from_url(*args, **kwargs):
            return fake_valkey

        with (
            patch("app.domain.onboarding.service.send_verification_email", new=mock_email),
            patch("valkey.asyncio.from_url", new=fake_from_url),
        ):
            svc = OnboardingService(session)
            await svc.register(
                first_name="Carol",
                last_name="White",
                email="carol@example.com",
                password="TestPass123!",
            )

        mock_email.assert_awaited_once()
        args = mock_email.call_args[0]
        assert args[0] == "carol@example.com"


# ─────────────────────────────────────────────────────────────────────────────
# OnboardingService.verify
# ─────────────────────────────────────────────────────────────────────────────


class TestOnboardingVerify:
    @pytest.mark.anyio
    async def test_verify_valid_token_activates_account(self, session):
        fake_valkey = _valkey_mock()

        async def fake_from_url(*args, **kwargs):
            return fake_valkey

        # Create an inactive account and store token
        with Session(session.bind) as s:
            nc = NonCriticalPersonalData(first_name="Dave", last_name="Test", is_active=False)
            s.add(nc)
            s.flush()
            sd = SensitiveData(
                non_critical_data_id=nc.id,
                email="dave@example.com",
                password="TestPass123!",
            )
            s.add(sd)
            s.flush()
            adm = Administrator(sensitive_data_id=sd.id)
            s.add(adm)
            s.commit()
            nc_id = nc.id

        token = "test-verify-token-abc"
        await fake_valkey.setex(f"{_TOKEN_PREFIX}{token}", 86400, str(nc_id))

        with patch("valkey.asyncio.from_url", new=fake_from_url):
            svc = OnboardingService(session)
            await svc.verify(token)

        refreshed_nc = session.get(NonCriticalPersonalData, nc_id)
        assert refreshed_nc is not None
        assert refreshed_nc.is_active is True
        # Token should be consumed (deleted from Valkey)
        leftover = await fake_valkey.get(f"{_TOKEN_PREFIX}{token}")
        assert leftover is None

    @pytest.mark.anyio
    async def test_verify_invalid_token_raises_400(self, session):
        from fastapi import HTTPException

        fake_valkey = _valkey_mock()

        async def fake_from_url(*args, **kwargs):
            return fake_valkey

        with patch("valkey.asyncio.from_url", new=fake_from_url):
            svc = OnboardingService(session)
            with pytest.raises(HTTPException) as exc_info:
                await svc.verify("no-such-token")

        assert exc_info.value.status_code == 400


# ─────────────────────────────────────────────────────────────────────────────
# HTTP routes
# ─────────────────────────────────────────────────────────────────────────────


class TestOnboardingRoutes:
    def test_register_returns_202(self, client):
        fake_valkey = _valkey_mock()

        async def fake_from_url(*args, **kwargs):
            return fake_valkey

        with (
            patch("app.domain.onboarding.service.send_verification_email", new=AsyncMock()),
            patch("valkey.asyncio.from_url", new=fake_from_url),
        ):
            resp = client.post(
                "/api/v1/onboarding/register",
                json={
                    "first_name": "Eve",
                    "last_name": "Adams",
                    "email": "eve@example.com",
                    "password": "TestPass123!",
                },
            )
        assert resp.status_code == 202
        data = resp.json()
        assert "message" in data
        assert data["email"] == "eve@example.com"

    def test_register_duplicate_still_returns_202(self, client, master_admin_account):
        """Duplicate registration must swallow the error and still return 202."""
        fake_valkey = _valkey_mock()

        async def fake_from_url(*args, **kwargs):
            return fake_valkey

        # Reuse the existing master admin email
        with (
            patch("app.domain.onboarding.service.send_verification_email", new=AsyncMock()),
            patch("valkey.asyncio.from_url", new=fake_from_url),
        ):
            resp = client.post(
                "/api/v1/onboarding/register",
                json={
                    "first_name": "Dup",
                    "last_name": "User",
                    "email": master_admin_account["email"],
                    "password": "TestPass123!",
                },
            )
        assert resp.status_code == 202

    def test_verify_invalid_token_returns_400(self, client):
        fake_valkey = _valkey_mock()

        async def fake_from_url(*args, **kwargs):
            return fake_valkey

        with patch("valkey.asyncio.from_url", new=fake_from_url):
            resp = client.get("/api/v1/onboarding/verify?token=bad-token")

        assert resp.status_code == 400
