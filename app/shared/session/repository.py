import json
import logging
from datetime import datetime, timezone

import valkey.asyncio as valkey

from app.config import settings

from .models import EntitySessionData, SessionData


logger = logging.getLogger(__name__)


class SessionRepository:
    def __init__(self, valkey_url: str):
        self.valkey_url = valkey_url
        self.client: valkey.Valkey | None = None

    @property
    def _c(self) -> valkey.Valkey:
        """Return connected client; call connect() before using any repository method."""
        assert self.client is not None, "SessionRepository.connect() not called"
        return self.client

    @staticmethod
    def _rate_limit_storage_key(rate_limit_key: str) -> str:
        return f"rate_limit:{rate_limit_key}"

    async def connect(self):
        if not self.client:
            self.client = await valkey.from_url(
                self.valkey_url,
                encoding="utf-8",
                decode_responses=True,
            )

    async def close(self) -> None:
        if self.client:
            await self._c.aclose()
            self.client = None

    # ==============================================================
    # Legacy user session (JWT-based) - kept for existing auth flow
    # ==============================================================

    async def store_session(
        self,
        user_id: str,
        session_data: SessionData,
        ttl_seconds: int = settings.SESSION_TTL_SECONDS,
    ) -> None:
        await self.connect()

        key = f"user_session:{user_id}"
        value = session_data.model_dump_json()

        await self._c.setex(key, ttl_seconds, value)

        refresh_key = f"refresh_token:{session_data.refresh_token}"
        await self._c.setex(refresh_key, ttl_seconds, user_id)

    async def get_session(self, user_id: str) -> SessionData | None:
        await self.connect()

        key = f"user_session:{user_id}"
        data = await self._c.get(key)

        if not data:
            return None

        try:
            session_dict = json.loads(data)
            return SessionData(**session_dict)
        except (json.JSONDecodeError, ValueError):
            await self._c.delete(key)
            return None

    async def delete_session(self, user_id: str) -> None:
        await self.connect()

        session = await self.get_session(user_id)

        key = f"user_session:{user_id}"
        await self._c.delete(key)

        if session:
            refresh_key = f"refresh_token:{session.refresh_token}"
            await self._c.delete(refresh_key)

    async def update_last_activity(self, user_id: str) -> None:
        await self.connect()

        session = await self.get_session(user_id)
        if session:
            session.last_activity = datetime.now(timezone.utc)

            key = f"user_session:{user_id}"
            remaining_ttl = await self._c.ttl(key)
            ttl = remaining_ttl if remaining_ttl > 0 else settings.SESSION_TTL_SECONDS
            await self.store_session(user_id, session, ttl_seconds=ttl)

    async def get_user_by_refresh_token(self, refresh_token: str) -> str | None:
        await self.connect()

        refresh_key = f"refresh_token:{refresh_token}"
        return await self._c.get(refresh_key)

    async def add_to_blacklist(self, token_id: str, ttl_seconds: int = 1800) -> None:
        await self.connect()

        key = f"blacklist:{token_id}"
        await self._c.setex(key, ttl_seconds, "1")

    async def is_blacklisted(self, token_id: str) -> bool:
        await self.connect()

        key = f"blacklist:{token_id}"
        exists = await self._c.exists(key)
        return bool(exists)

    async def increment_rate_limit(
        self,
        rate_limit_key: str,
        window_seconds: int = 900,
    ) -> int:
        await self.connect()

        key = self._rate_limit_storage_key(rate_limit_key)
        count = await self._c.incr(key)

        if count == 1:
            await self._c.expire(key, int(window_seconds))

        return count

    async def get_rate_limit(self, rate_limit_key: str) -> int:
        await self.connect()

        key = self._rate_limit_storage_key(rate_limit_key)
        count = await self._c.get(key)

        return int(count) if count else 0

    async def get_rate_limit_ttl(self, rate_limit_key: str) -> int:
        await self.connect()

        key = self._rate_limit_storage_key(rate_limit_key)
        ttl = await self._c.ttl(key)
        return max(int(ttl), 0)

    async def reset_rate_limit(self, rate_limit_key: str) -> None:
        await self.connect()

        key = self._rate_limit_storage_key(rate_limit_key)
        await self._c.delete(key)

    async def is_rate_limited(self, rate_limit_key: str, max_attempts: int = 3) -> bool:
        count = await self.get_rate_limit(rate_limit_key)
        return count >= max_attempts

    # ==============================================================
    # Entity sessions (per-key encryption, Valkey-backed stateful)
    # ==============================================================

    async def entity_session_exists(self, entity_id: str) -> bool:
        await self.connect()
        key = f"entity_session:{entity_id}"
        return bool(await self._c.exists(key))

    async def store_entity_session(
        self,
        session_data: EntitySessionData,
        ttl_seconds: int = settings.SESSION_TTL_SECONDS,
    ) -> bool:
        """Store entity session atomically. Returns True if created, False if already exists."""
        await self.connect()

        entity_key = f"entity_session:{session_data.entity_id}"
        index_key = f"session_id_index:{session_data.session_id}"
        value = session_data.model_dump_json()

        # Atomic SET NX (set if not exists) to prevent race condition
        entity_created = await self._c.set(
            entity_key, value, ex=ttl_seconds, nx=True
        )
        
        if not entity_created:
            return False
        
        # If entity session was created, also create the index
        await self._c.setex(index_key, ttl_seconds, session_data.entity_id)
        return True

    async def get_entity_session(self, entity_id: str) -> EntitySessionData | None:
        await self.connect()

        key = f"entity_session:{entity_id}"
        data = await self._c.get(key)

        if not data:
            return None

        try:
            return EntitySessionData(**json.loads(data))
        except (json.JSONDecodeError, ValueError):
            logger.warning("Corrupted entity session deleted: entity_id=%s", entity_id)
            await self._c.delete(key)
            return None

    async def get_entity_session_by_id(
        self,
        session_id: str,
    ) -> EntitySessionData | None:
        await self.connect()

        index_key = f"session_id_index:{session_id}"
        entity_id = await self._c.get(index_key)

        if not entity_id:
            return None

        return await self.get_entity_session(entity_id)

    async def delete_entity_session(self, entity_id: str) -> None:
        await self.connect()

        existing = await self.get_entity_session(entity_id)

        pipeline = self._c.pipeline()
        pipeline.delete(f"entity_session:{entity_id}")
        if existing:
            pipeline.delete(f"session_id_index:{existing.session_id}")
        await pipeline.execute()

    async def touch_entity_session(self, session_data: EntitySessionData) -> None:
        """Update session last_activity without modifying TTL."""
        await self.connect()

        session_data.last_activity = datetime.now(timezone.utc)
        entity_key = f"entity_session:{session_data.entity_id}"

        # Use keepttl=True to preserve original expiration time
        await self._c.set(
            entity_key,
            session_data.model_dump_json(),
            keepttl=True,
        )
