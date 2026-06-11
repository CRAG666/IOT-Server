"""Business logic for self-service registration and email verification."""

from __future__ import annotations

import secrets
from uuid import UUID

from sqlmodel import Session, select

from app.config import settings
from app.database.model import Administrator, NonCriticalPersonalData, SensitiveData
from app.shared.email import send_verification_email
from app.shared.exceptions import AlreadyExistsException

# Valkey key prefix and TTL (24 hours)
_TOKEN_PREFIX = "onboarding:verify:"
_TOKEN_TTL = 86_400


class OnboardingService:
    def __init__(self, session: Session) -> None:
        self._session = session

    async def register(self, first_name: str, last_name: str, email: str, password: str, phone: str | None = None) -> str:
        """Create a pending (inactive) admin account and send verification email.

        Returns the raw verification token so it can be logged when MAIL_ENABLED=False.
        """
        existing = self._session.exec(select(SensitiveData).where(SensitiveData.email == email)).first()
        if existing:
            raise AlreadyExistsException("Account", "email", email)

        non_critical = NonCriticalPersonalData(
            first_name=first_name,
            last_name=last_name,
            phone=phone,
            is_active=False,  # inactive until verified
        )
        self._session.add(non_critical)
        self._session.flush()

        sensitive = SensitiveData(
            non_critical_data_id=non_critical.id,
            email=email,
            password=password,
        )
        self._session.add(sensitive)
        self._session.flush()

        admin = Administrator(sensitive_data_id=sensitive.id)
        self._session.add(admin)
        self._session.commit()

        token = secrets.token_urlsafe(32)
        await self._store_token(token, str(non_critical.id))
        await send_verification_email(email, token)
        return token

    async def verify(self, token: str) -> None:
        """Activate the account associated with *token*."""
        import valkey.asyncio as _valkey

        client = await _valkey.from_url(settings.VALKEY_URL, decode_responses=True)
        try:
            key = _TOKEN_PREFIX + token
            nc_id_raw = await client.get(key)
            if nc_id_raw is None:
                from fastapi import HTTPException, status
                raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Invalid or expired verification token")

            nc_id = UUID(nc_id_raw)
            nc = self._session.get(NonCriticalPersonalData, nc_id)
            if nc is None:
                from fastapi import HTTPException, status
                raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Account not found")

            nc.is_active = True
            self._session.add(nc)
            self._session.commit()
            await client.delete(key)
        finally:
            await client.aclose()

    async def _store_token(self, token: str, non_critical_id: str) -> None:
        import valkey.asyncio as _valkey

        client = await _valkey.from_url(settings.VALKEY_URL, decode_responses=True)
        try:
            await client.setex(_TOKEN_PREFIX + token, _TOKEN_TTL, non_critical_id)
        finally:
            await client.aclose()
