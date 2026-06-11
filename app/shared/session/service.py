import base64
import binascii
import ipaddress
import json
import logging
import secrets
from datetime import datetime, timezone
from functools import lru_cache
from typing import Annotated, Any
from uuid import UUID, uuid4

from fastapi import Depends

from app.config import settings

from .exceptions import (
    InvalidEntityIdException,
    InvalidIpAddressException,
    InvalidKeySessionException,
    InvalidMetadataException,
    InvalidTagException,
    SessionAlreadyExistsException,
    SessionNotFoundException,
)
from .models import (
    EntitySessionData,
    EntitySessionResponse,
    SessionData,
    SessionTokens,
)
from .repository import SessionRepository
from .security import JWEHandler, SessionHMAC


logger = logging.getLogger(__name__)

_KEY_SESSION_EXPECTED_BYTES = 32

METADATA_FORBIDDEN_KEYS: frozenset[str] = frozenset({
    "password",
    "password_hash",
    "secret",
    "private_key",
    "key_session",
    "api_key",
})


class SessionService:
    def __init__(
        self,
        valkey_url: str | None = None,
        encryption_key: str | None = None,
    ):
        self._repository = SessionRepository(valkey_url or settings.VALKEY_URL)
        self._encryption_key = encryption_key or settings.ENCRYPTION_KEY
        self._jwe_handler: JWEHandler | None = None

    def _get_jwe_handler(self) -> JWEHandler:
        """Lazy initialization of JWE handler (only for legacy flow)."""
        if self._jwe_handler is None:
            self._jwe_handler = JWEHandler(self._encryption_key)
        return self._jwe_handler

    async def close(self) -> None:
        await self._repository.close()

    async def check_active_session(self, entity_id: UUID) -> bool:
        entity_id_str = self._validate_entity_id(entity_id)
        return await self._repository.entity_session_exists(entity_id_str)

    async def create_entity_session(
        self,
        entity_id: UUID,
        key_session: str,
        ip_address: str,
        metadata: dict[str, Any] | None = None,
    ) -> EntitySessionResponse:
        entity_id_str = self._validate_entity_id(entity_id)
        self._validate_key_session(key_session)
        self._validate_ip_address(ip_address)
        safe_metadata = self._validate_metadata(metadata)

        if await self._repository.entity_session_exists(entity_id_str):
            raise SessionAlreadyExistsException()

        session_id = secrets.token_urlsafe(32)
        now = datetime.now(timezone.utc)

        session_data = EntitySessionData(
            session_id=session_id,
            entity_id=entity_id_str,
            key_session=key_session,
            ip_address=ip_address,
            metadata=safe_metadata,
            created_at=now,
            last_activity=now,
        )

        created = await self._repository.store_entity_session(
            session_data=session_data,
            ttl_seconds=settings.SESSION_TTL_SECONDS,
        )

        if not created:
            raise SessionAlreadyExistsException()

        logger.info(
            "Entity session created: entity_id=%s metadata_keys=%d",
            entity_id_str,
            len(safe_metadata),
        )

        return EntitySessionResponse(session_id=session_id)

    async def process_encrypted_request(
        self,
        session_id: str,
        tag: str,
        payload: str,
    ) -> str:
        if not session_id or not tag or not payload:
            raise InvalidTagException()

        session_data = await self._repository.get_entity_session_by_id(session_id)
        if not session_data:
            raise SessionNotFoundException()

        is_valid = SessionHMAC.verify_hmac(
            session_id=session_id,
            payload=payload,
            tag=tag,
            key_session=session_data.key_session,
        )
        if not is_valid:
            logger.warning(
                "HMAC verification failed: session_id=%s entity_id=%s",
                session_id,
                session_data.entity_id,
            )
            raise InvalidTagException()

        await self._repository.touch_entity_session(session_data)

        logger.info(
            "Encrypted request verified: session_id=%s entity_id=%s",
            session_id,
            session_data.entity_id,
        )

        return session_data.key_session

    async def invalidate_entity_session(self, entity_id: UUID) -> None:
        entity_id_str = self._validate_entity_id(entity_id)
        await self._repository.delete_entity_session(entity_id_str)
        logger.info("Entity session invalidated: entity_id=%s", entity_id_str)

    async def invalidate_user_session(self, user_id: str) -> None:
        await self._repository.delete_session(user_id)
        logger.info("User session invalidated: user_id=%s", user_id)

    @staticmethod
    def _validate_entity_id(entity_id: UUID) -> str:
        if isinstance(entity_id, UUID):
            return str(entity_id)
        try:
            return str(UUID(str(entity_id)))
        except (ValueError, TypeError) as e:
            raise InvalidEntityIdException() from e

    @staticmethod
    def _validate_key_session(key_session: str) -> None:
        if not key_session:
            logger.warning("key_session validation failed: empty value")
            raise InvalidKeySessionException()
        try:
            key_bytes = base64.urlsafe_b64decode(key_session)
        except (binascii.Error, ValueError) as e:
            logger.warning("key_session validation failed: not valid urlsafe base64")
            raise InvalidKeySessionException() from e

        if len(key_bytes) != _KEY_SESSION_EXPECTED_BYTES:
            logger.warning(
                "key_session validation failed: expected %d bytes, got %d",
                _KEY_SESSION_EXPECTED_BYTES,
                len(key_bytes),
            )
            raise InvalidKeySessionException()

    @staticmethod
    def _validate_ip_address(ip_address: str) -> None:
        if not ip_address or not ip_address.strip():
            logger.warning("ip_address validation failed: empty value")
            raise InvalidIpAddressException()

        try:
            ipaddress.ip_address(ip_address.strip())
        except (ValueError, AttributeError) as e:
            logger.warning("ip_address validation failed: malformed value")
            raise InvalidIpAddressException() from e

    @staticmethod
    def _validate_metadata(
        metadata: dict[str, Any] | None,
    ) -> dict[str, Any]:
        if metadata is None:
            return {}

        if not isinstance(metadata, dict):
            logger.warning("metadata validation failed: not a dict")
            raise InvalidMetadataException()

        if len(metadata) > settings.METADATA_MAX_KEYS:
            logger.warning(
                "metadata validation failed: too many keys (%d > %d)",
                len(metadata),
                settings.METADATA_MAX_KEYS,
            )
            raise InvalidMetadataException()

        metadata_keys_lower = {k.casefold() for k in metadata.keys()}
        forbidden_keys_lower = {k.casefold() for k in METADATA_FORBIDDEN_KEYS}
        forbidden = metadata_keys_lower & forbidden_keys_lower
        if forbidden:
            logger.warning(
                "metadata validation failed: forbidden keys present (%s)",
                sorted(forbidden),
            )
            raise InvalidMetadataException()

        try:
            serialized = json.dumps(metadata)
        except (TypeError, ValueError) as e:
            logger.warning("metadata validation failed: not JSON-serializable")
            raise InvalidMetadataException() from e

        if len(serialized.encode("utf-8")) > settings.METADATA_MAX_SIZE_BYTES:
            logger.warning(
                "metadata validation failed: payload exceeds %d bytes",
                settings.METADATA_MAX_SIZE_BYTES,
            )
            raise InvalidMetadataException()

        return metadata

    async def create_session_with_tokens(
        self,
        user_id: str,
        claims: dict[str, Any],
        request_info: dict[str, str],
    ) -> SessionTokens:
        await self._repository.delete_session(user_id)

        token_id = str(uuid4())
        refresh_token = secrets.token_urlsafe(32)

        access_token = self._get_jwe_handler().encrypt(
            claims={**claims, "jti": token_id},
            ttl_minutes=30,
        )

        now = datetime.now(timezone.utc)
        session_data = SessionData(
            user_id=user_id,
            token_id=token_id,
            refresh_token=refresh_token,
            email=claims.get("email", ""),
            account_type=claims.get("type", ""),
            is_master=claims.get("is_master", False),
            ip_address=request_info.get("ip_address", "unknown"),
            user_agent=request_info.get("user_agent", "unknown"),
            created_at=now,
            last_activity=now,
        )

        await self._repository.store_session(
            user_id=user_id,
            session_data=session_data,
            ttl_seconds=settings.SESSION_TTL_SECONDS,
        )

        return SessionTokens(
            access_token=access_token,
            refresh_token=refresh_token,
            token_type="bearer",
        )

    async def check_rate_limit(self, ip_address: str, max_attempts: int = 3) -> bool:
        return await self._repository.is_rate_limited(ip_address, max_attempts)

    async def increment_rate_limit(
        self,
        ip_address: str,
        max_attempts: int = 3,
        window_seconds: int = 900,
    ) -> int:
        return await self._repository.increment_rate_limit(
            ip_address,
            window_seconds,
        )

    async def reset_rate_limit(self, ip_address: str) -> None:
        await self._repository.reset_rate_limit(ip_address)

    async def get_session(self, user_id: str) -> SessionData | None:
        return await self._repository.get_session(user_id)


@lru_cache
def get_session_service() -> SessionService:
    """
    Get or create a singleton SessionService instance.
    
    Using @lru_cache ensures that the same instance is reused across
    all dependency injections, preventing connection pool exhaustion.
    """
    return SessionService()


SessionServiceDep = Annotated[SessionService, Depends(get_session_service)]
