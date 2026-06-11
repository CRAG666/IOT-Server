"""Valkey-backed E2E session storage for the AES-256-CBC session protocol."""

import json
import logging
from datetime import datetime, timezone
from typing import Any
from uuid import uuid4

import valkey.asyncio as valkey

from app.config import settings

logger = logging.getLogger(__name__)

_SESSION_PREFIX = "e2e_session:"


class E2ESessionRepository:
    """Thin Valkey adapter that stores and retrieves E2E session records."""

    def __init__(self, valkey_url: str):
        self.valkey_url = valkey_url
        self.client: valkey.Valkey | None = None
        self._external_client = False

    @property
    def _c(self) -> valkey.Valkey:
        assert self.client is not None, "E2ESessionRepository.connect() not called"
        return self.client

    async def connect(self) -> None:
        if self.client is None:
            self.client = await valkey.from_url(
                self.valkey_url,
                encoding="utf-8",
                decode_responses=True,
            )

    async def close(self) -> None:
        if self._external_client:
            return
        if self.client is not None:
            await self._c.aclose()
            self.client = None

    def _key(self, session_id: str) -> str:
        return f"{_SESSION_PREFIX}{session_id}"

    async def create_session(
        self,
        *,
        session_key_hex: str,
        account: dict[str, Any],
        ttl_seconds: int | None = None,
    ) -> str:
        """Persist a new session and return its UUID."""
        await self.connect()
        session_id = str(uuid4())
        ttl = ttl_seconds if ttl_seconds is not None else settings.SESSION_TTL_SECONDS
        now = datetime.now(timezone.utc)
        record = {
            "session_id": session_id,
            "session_key": session_key_hex,
            "account": account,
            "created_at": now.isoformat(),
        }
        await self._c.setex(self._key(session_id), ttl, json.dumps(record))
        return session_id

    async def get_session(self, session_id: str) -> dict[str, Any] | None:
        """Return the session record, or ``None`` if it does not exist / expired."""
        await self.connect()
        raw = await self._c.get(self._key(session_id))
        if not raw:
            return None
        try:
            return json.loads(raw)
        except json.JSONDecodeError:
            logger.warning("Corrupted e2e session deleted: %s", session_id)
            await self._c.delete(self._key(session_id))
            return None

    async def delete_session(self, session_id: str) -> None:
        """Delete a session (logout)."""
        await self.connect()
        await self._c.delete(self._key(session_id))

    async def renew_session(
        self,
        session_id: str,
        ttl_seconds: int | None = None,
    ) -> str | None:
        """Extend an existing session TTL, return new session_id (old is deleted).

        Returns ``None`` if the original session no longer exists.
        """
        await self.connect()
        record = await self.get_session(session_id)
        if not record:
            return None
        ttl = ttl_seconds if ttl_seconds is not None else settings.SESSION_TTL_SECONDS
        await self.delete_session(session_id)
        new_id = str(uuid4())
        record["session_id"] = new_id
        await self._c.setex(self._key(new_id), ttl, json.dumps(record))
        return new_id
