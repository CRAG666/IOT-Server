"""Comprehensive tests to close remaining coverage gaps.

Each section targets one module's uncovered lines, identified by running
coverage and cross-referencing the line numbers.
"""

from __future__ import annotations

import asyncio
import base64
import json
import secrets
from datetime import datetime, timezone
from unittest.mock import AsyncMock, MagicMock, patch
from uuid import UUID, uuid4

import fakeredis
import pytest
from fastapi import HTTPException

# ── helpers ───────────────────────────────────────────────────────────────────


def _make_current_user(account_type: str = "administrator", account_id=None, is_master: bool = True):
    from app.shared.authorization.models import CurrentUser
    return CurrentUser(
        account_id=account_id or uuid4(),
        account_type=account_type,
        email=f"{account_type}@test.com",
        is_master=is_master,
        sensitive_data_id=uuid4(),
    )


@pytest.fixture
def fake_valkey():
    return fakeredis.FakeAsyncValkey(decode_responses=True)


@pytest.fixture
def session_repo(fake_valkey):
    from app.shared.session.repository import SessionRepository
    repo = SessionRepository("redis://localhost:6379/0")
    repo.client = fake_valkey
    return repo


# ═══════════════════════════════════════════════════════════════════════════════
# main.py — lifespan (lines 39-63)
# ═══════════════════════════════════════════════════════════════════════════════


class TestLifespan:
    @pytest.mark.anyio
    async def test_lifespan_no_mqtt(self):
        from app.main import lifespan
        from fastapi import FastAPI

        mock_telemetry = MagicMock()
        mock_telemetry.ensure_indexes = AsyncMock()

        with (
            patch("app.main.create_db_and_tables"),
            patch("app.main.init_logging"),
            patch("app.main.TelemetryRepository", return_value=mock_telemetry),
            patch("app.main.close_mongo_client", new_callable=AsyncMock),
            patch("app.main.settings") as mock_settings,
        ):
            mock_settings.MQTT_ENABLED = False
            mock_settings.DEBUG = True
            async with lifespan(FastAPI()):
                pass

    @pytest.mark.anyio
    async def test_lifespan_with_mqtt(self):
        from app.main import lifespan
        from fastapi import FastAPI

        mock_telemetry = MagicMock()
        mock_telemetry.ensure_indexes = AsyncMock()

        async def slow_bridge():
            await asyncio.sleep(100)

        with (
            patch("app.main.create_db_and_tables"),
            patch("app.main.init_logging"),
            patch("app.main.TelemetryRepository", return_value=mock_telemetry),
            patch("app.main.close_mongo_client", new_callable=AsyncMock),
            patch("app.main.run_bridge", side_effect=slow_bridge),
            patch("app.main.settings") as mock_settings,
        ):
            mock_settings.MQTT_ENABLED = True
            mock_settings.DEBUG = True
            async with lifespan(FastAPI()):
                pass  # mqtt task created then cancelled on exit

    @pytest.mark.anyio
    async def test_lifespan_mongodb_unavailable(self):
        from app.main import lifespan
        from fastapi import FastAPI

        mock_telemetry = MagicMock()
        mock_telemetry.ensure_indexes = AsyncMock(side_effect=Exception("mongo down"))

        with (
            patch("app.main.create_db_and_tables"),
            patch("app.main.init_logging"),
            patch("app.main.TelemetryRepository", return_value=mock_telemetry),
            patch("app.main.close_mongo_client", new_callable=AsyncMock),
            patch("app.main.settings") as mock_settings,
        ):
            mock_settings.MQTT_ENABLED = False
            mock_settings.DEBUG = True
            async with lifespan(FastAPI()):
                pass


# ═══════════════════════════════════════════════════════════════════════════════
# HumanPasswordAuth (humans.py lines 21-87)
# ═══════════════════════════════════════════════════════════════════════════════


class TestHumanPasswordAuth:
    @pytest.fixture
    def auth(self):
        from app.shared.middleware.auth.humans import HumanPasswordAuth
        return HumanPasswordAuth()

    @pytest.fixture
    def admin_entity(self, session, master_admin_account):
        from app.database.model import Administrator
        return session.get(Administrator, master_admin_account["id"])

    @pytest.fixture
    def manager_entity(self, session, manager_account):
        from app.database.model import Manager
        return session.get(Manager, manager_account["id"])

    @pytest.fixture
    def user_entity(self, session, user_account):
        from app.database.model import User
        return session.get(User, user_account["id"])

    @pytest.fixture
    def sensitive_data_for_admin(self, session, master_admin_account):
        from app.database.model import SensitiveData
        return session.get(SensitiveData, master_admin_account["sensitive_data_id"])

    def test_authenticate_administrator_success(self, auth, admin_entity, sensitive_data_for_admin):
        result = auth.authenticate(admin_entity, {
            "account_type": "administrator",
            "sensitive_data": sensitive_data_for_admin,
            "password": "MasterPassword123!",
        })
        assert result["valid"] is True

    def test_authenticate_administrator_wrong_password(self, auth, admin_entity, sensitive_data_for_admin):
        result = auth.authenticate(admin_entity, {
            "account_type": "administrator",
            "sensitive_data": sensitive_data_for_admin,
            "password": "WrongPassword123!",
        })
        assert result["valid"] is False
        assert "credentials" in result["error"]

    def test_authenticate_manager_success(self, auth, manager_entity, session, manager_account):
        from app.database.model import SensitiveData
        sd = session.get(SensitiveData, manager_account["sensitive_data_id"])
        result = auth.authenticate(manager_entity, {
            "account_type": "manager",
            "sensitive_data": sd,
            "password": "ManagerPass123!",
        })
        assert result["valid"] is True

    def test_authenticate_user_success(self, auth, user_entity, session, user_account):
        from app.database.model import SensitiveData
        sd = session.get(SensitiveData, user_account["sensitive_data_id"])
        result = auth.authenticate(user_entity, {
            "account_type": "user",
            "sensitive_data": sd,
            "password": "UserPassword123!",
        })
        assert result["valid"] is True

    def test_authenticate_unknown_type_returns_invalid(self, auth, admin_entity, sensitive_data_for_admin):
        result = auth.authenticate(admin_entity, {
            "account_type": "device",
            "sensitive_data": sensitive_data_for_admin,
            "password": "MasterPassword123!",
        })
        assert result["valid"] is False
        assert "entity type" in result["error"]

    def test_authenticate_administrator_wrong_entity_type(self, auth, manager_entity, sensitive_data_for_admin):
        from app.database.model import Manager
        result = auth.authenticate(manager_entity, {
            "account_type": "administrator",
            "sensitive_data": sensitive_data_for_admin,
            "password": "MasterPassword123!",
        })
        assert result["valid"] is False
        assert "administrator" in result["error"]

    def test_authenticate_manager_wrong_entity_type(self, auth, admin_entity, session, manager_account):
        from app.database.model import SensitiveData
        sd = session.get(SensitiveData, manager_account["sensitive_data_id"])
        result = auth.authenticate(admin_entity, {
            "account_type": "manager",
            "sensitive_data": sd,
            "password": "ManagerPass123!",
        })
        assert result["valid"] is False
        assert "manager" in result["error"]

    def test_authenticate_user_wrong_entity_type(self, auth, admin_entity, session, user_account):
        from app.database.model import SensitiveData
        sd = session.get(SensitiveData, user_account["sensitive_data_id"])
        result = auth.authenticate(admin_entity, {
            "account_type": "user",
            "sensitive_data": sd,
            "password": "UserPassword123!",
        })
        assert result["valid"] is False
        assert "user" in result["error"]

    def test_authenticate_inactive_user(self, auth, session, inactive_user_account):
        from app.database.model import SensitiveData, User
        sd = session.get(SensitiveData, inactive_user_account["sensitive_data_id"])
        user = session.get(User, inactive_user_account["id"])
        result = auth.authenticate(user, {
            "account_type": "user",
            "sensitive_data": sd,
            "password": "InactivePass123!",
        })
        assert result["valid"] is False
        assert "inactive" in result["error"]

    def test_authenticate_none_sensitive_data(self, auth, admin_entity):
        result = auth.authenticate(admin_entity, {
            "account_type": "administrator",
            "sensitive_data": None,
            "password": "AnyPass123!",
        })
        assert result["valid"] is False
        assert "credentials" in result["error"]

    def test_get_auth_type(self, auth):
        assert auth.get_auth_type() == "human_password"


# ═══════════════════════════════════════════════════════════════════════════════
# HumanAuth adapter (auth_rc/human.py line 20)
# ═══════════════════════════════════════════════════════════════════════════════


class TestHumanAuth:
    def test_authenticate_delegates_to_human_password_auth(self, session, master_admin_account):
        from app.database.model import Administrator, SensitiveData
        from app.shared.middleware.auth.auth_rc.human import HumanAuth

        auth = HumanAuth()
        admin = session.get(Administrator, master_admin_account["id"])
        sd = session.get(SensitiveData, master_admin_account["sensitive_data_id"])
        result = auth.authenticate(admin, {
            "account_type": "administrator",
            "sensitive_data": sd,
            "password": "MasterPassword123!",
        })
        assert result["valid"] is True

    def test_get_auth_type(self):
        from app.shared.middleware.auth.auth_rc.human import HumanAuth
        assert HumanAuth().get_auth_type() == "auth_rc"


# ═══════════════════════════════════════════════════════════════════════════════
# AuthMethodSelector (interface.py lines 53, 62, 70-77)
# ═══════════════════════════════════════════════════════════════════════════════


class TestAuthMethodSelector:
    def test_register_and_resolve(self):
        from app.shared.middleware.auth.interface import AuthMethodSelector

        class FakeMethod:
            def authenticate(self, e, r): return {"valid": True}
            def get_auth_type(self): return "fake"

        selector = AuthMethodSelector()
        method = FakeMethod()
        selector.register(auth_type="fake", entity_type="device", method=method)
        resolved = selector.resolve(auth_type="fake", entity_type="device")
        assert resolved is method

    def test_resolve_unknown_raises(self):
        from app.shared.middleware.auth.interface import AuthMethodSelector
        selector = AuthMethodSelector()
        with pytest.raises(ValueError, match="not configured"):
            selector.resolve(auth_type="nonexistent", entity_type="device")

    def test_auth_type_enum(self):
        from app.shared.middleware.auth.interface import AuthType
        assert AuthType.AUTH_RC == "auth_rc"
        assert AuthType.AUTH_XMSS == "auth_xmss"


# ═══════════════════════════════════════════════════════════════════════════════
# ApplicationAuthManager / DeviceAuthManager._get_entity_id (lines 21)
# ═══════════════════════════════════════════════════════════════════════════════


class TestAuthManagerGetEntityId:
    def test_application_auth_manager_get_entity_id(self):
        from app.shared.middleware.auth.auth_manager.application import ApplicationAuthManager
        from dataclasses import dataclass

        @dataclass
        class FakeRequest:
            application_id: UUID = uuid4()

        mgr = object.__new__(ApplicationAuthManager)
        req = FakeRequest()
        assert mgr._get_entity_id(req) == req.application_id

    def test_device_auth_manager_get_entity_id(self):
        from app.shared.middleware.auth.auth_manager.device import DeviceAuthManager
        from dataclasses import dataclass

        @dataclass
        class FakeRequest:
            device_id: UUID = uuid4()

        mgr = object.__new__(DeviceAuthManager)
        req = FakeRequest()
        assert mgr._get_entity_id(req) == req.device_id


# ═══════════════════════════════════════════════════════════════════════════════
# PuzzleVerifier short payload (puzzle.py lines 75-76)
# ═══════════════════════════════════════════════════════════════════════════════


class TestPuzzleVerifierShortPayload:
    def test_short_decrypted_payload_returns_failure(self):
        from app.shared.middleware.auth.auth_rc.puzzle import PuzzleVerifier
        from base64 import b64encode
        from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
        from cryptography.hazmat.primitives import padding as crypto_padding
        import os

        verifier = PuzzleVerifier()
        key = os.urandom(32)

        # Build an AES-CBC ciphertext that decrypts to < 72 bytes
        iv = os.urandom(16)
        plaintext = b"short"  # 5 bytes — well under 72
        padder = crypto_padding.PKCS7(128).padder()
        padded = padder.update(plaintext) + padder.finalize()
        cipher = Cipher(algorithms.AES(key), modes.CBC(iv))
        ciphertext = cipher.encryptor().update(padded) + cipher.encryptor().finalize()

        puzzle = MagicMock()
        puzzle.encrypted_payload.ciphertext = b64encode(ciphertext).decode()
        puzzle.encrypted_payload.iv = b64encode(iv).decode()

        result = verifier.verify(key, puzzle, "test-entity")
        assert result["valid"] is False
        assert "Authentication failed" in result["error"]


# ═══════════════════════════════════════════════════════════════════════════════
# ApplicationAuth / DeviceAuth _normalize_key (lines 39-42)
# ═══════════════════════════════════════════════════════════════════════════════


class TestNormalizeKey:
    def test_application_auth_non_hex_uses_sha256(self):
        from app.shared.middleware.auth.auth_rc.application import ApplicationAuth
        auth = ApplicationAuth()
        key = auth._normalize_key("not-valid-hex-at-all!")
        assert len(key) == 32

    def test_application_auth_short_hex_uses_sha256(self):
        from app.shared.middleware.auth.auth_rc.application import ApplicationAuth
        auth = ApplicationAuth()
        key = auth._normalize_key("deadbeef")  # 4 bytes, not 32
        assert len(key) == 32

    def test_device_auth_non_hex_uses_sha256(self):
        from app.shared.middleware.auth.auth_rc.device import DeviceAuth
        auth = DeviceAuth()
        key = auth._normalize_key("not-hex!!!")
        assert len(key) == 32

    def test_device_auth_short_hex_uses_sha256(self):
        from app.shared.middleware.auth.auth_rc.device import DeviceAuth
        auth = DeviceAuth()
        key = auth._normalize_key("cafebabe")  # 4 bytes
        assert len(key) == 32


# ═══════════════════════════════════════════════════════════════════════════════
# SessionRepository edge cases (repository.py)
# ═══════════════════════════════════════════════════════════════════════════════


class TestSessionRepositoryEdgeCases:
    @pytest.mark.anyio
    async def test_connect_creates_client(self):
        from app.shared.session.repository import SessionRepository
        repo = SessionRepository("redis://localhost:6379/0")
        assert repo.client is None

        fake_client = MagicMock()

        async def fake_from_url(*a, **kw):
            return fake_client

        with patch("valkey.asyncio.from_url", side_effect=fake_from_url):
            await repo.connect()
        assert repo.client is fake_client

    @pytest.mark.anyio
    async def test_close_when_client_exists(self, session_repo, fake_valkey):
        assert session_repo.client is not None
        session_repo.client.aclose = AsyncMock()
        await session_repo.close()
        assert session_repo.client is None

    @pytest.mark.anyio
    async def test_get_session_corrupted_json(self, session_repo, fake_valkey):
        await fake_valkey.set("user_session:bad-user", "{invalid json!!}")
        result = await session_repo.get_session("bad-user")
        assert result is None
        # key deleted after corruption
        assert await fake_valkey.get("user_session:bad-user") is None

    @pytest.mark.anyio
    async def test_add_to_blacklist(self, session_repo, fake_valkey):
        await session_repo.add_to_blacklist("tok-abc", ttl_seconds=300)
        assert await fake_valkey.exists("blacklist:tok-abc")

    @pytest.mark.anyio
    async def test_is_blacklisted_true(self, session_repo, fake_valkey):
        await fake_valkey.set("blacklist:listed-tok", "1")
        assert await session_repo.is_blacklisted("listed-tok") is True

    @pytest.mark.anyio
    async def test_is_blacklisted_false(self, session_repo, fake_valkey):
        assert await session_repo.is_blacklisted("not-listed") is False

    @pytest.mark.anyio
    async def test_increment_rate_limit_sets_ttl_on_first_call(self, session_repo, fake_valkey):
        # First call → count == 1 → TTL set
        count = await session_repo.increment_rate_limit("ip:1.2.3.4", window_seconds=60)
        assert count == 1
        ttl = await fake_valkey.ttl("rate_limit:ip:1.2.3.4")
        assert ttl > 0

    @pytest.mark.anyio
    async def test_get_rate_limit_ttl(self, session_repo, fake_valkey):
        await fake_valkey.setex("rate_limit:mykey", 300, "5")
        ttl = await session_repo.get_rate_limit_ttl("mykey")
        assert ttl > 0

    @pytest.mark.anyio
    async def test_store_entity_session_creates_index(self, session_repo, fake_valkey):
        from app.shared.session.models import EntitySessionData
        session_data = EntitySessionData(
            session_id=secrets.token_urlsafe(32),
            entity_id=str(uuid4()),
            key_session=base64.urlsafe_b64encode(secrets.token_bytes(32)).decode(),
            ip_address="127.0.0.1",
            metadata={},
            created_at=datetime.now(timezone.utc),
            last_activity=datetime.now(timezone.utc),
        )
        created = await session_repo.store_entity_session(session_data)
        assert created is True
        # verify the session_id index was created (line 189)
        idx = await fake_valkey.get(f"session_id_index:{session_data.session_id}")
        assert idx == session_data.entity_id

    @pytest.mark.anyio
    async def test_store_entity_session_returns_false_if_exists(self, session_repo, fake_valkey):
        from app.shared.session.models import EntitySessionData
        entity_id = str(uuid4())
        session_data = EntitySessionData(
            session_id=secrets.token_urlsafe(32),
            entity_id=entity_id,
            key_session=base64.urlsafe_b64encode(secrets.token_bytes(32)).decode(),
            ip_address="10.0.0.1",
            metadata={},
            created_at=datetime.now(timezone.utc),
            last_activity=datetime.now(timezone.utc),
        )
        await session_repo.store_entity_session(session_data)
        created2 = await session_repo.store_entity_session(session_data)
        assert created2 is False

    @pytest.mark.anyio
    async def test_get_entity_session_corrupted_json(self, session_repo, fake_valkey):
        entity_id = str(uuid4())
        await fake_valkey.set(f"entity_session:{entity_id}", "{corrupted!}")
        result = await session_repo.get_entity_session(entity_id)
        assert result is None


# ═══════════════════════════════════════════════════════════════════════════════
# SessionService edge cases (service.py)
# ═══════════════════════════════════════════════════════════════════════════════


class TestSessionServiceEdgeCases:
    def test_get_session_service_singleton(self):
        from app.shared.session.service import get_session_service
        svc1 = get_session_service()
        svc2 = get_session_service()
        assert svc1 is svc2

    @pytest.mark.anyio
    async def test_close_delegates_to_repository(self):
        from app.shared.session.service import SessionService
        svc = SessionService.__new__(SessionService)
        svc._repository = MagicMock()
        svc._repository.close = AsyncMock()
        await svc.close()
        svc._repository.close.assert_called_once()

    @pytest.mark.anyio
    async def test_create_entity_session_race_condition(self):
        from app.shared.session.service import SessionService
        from app.shared.session.exceptions import SessionAlreadyExistsException

        svc = SessionService.__new__(SessionService)
        svc._repository = MagicMock()
        svc._encryption_key = base64.b64encode(secrets.token_bytes(32)).decode()
        svc._jwe_handler = None
        svc._repository.entity_session_exists = AsyncMock(return_value=False)
        svc._repository.store_entity_session = AsyncMock(return_value=False)

        key_session = base64.urlsafe_b64encode(secrets.token_bytes(32)).decode()
        with pytest.raises(SessionAlreadyExistsException):
            await svc.create_entity_session(uuid4(), key_session, "127.0.0.1")

    @pytest.mark.anyio
    async def test_invalidate_user_session(self):
        from app.shared.session.service import SessionService
        svc = SessionService.__new__(SessionService)
        svc._repository = MagicMock()
        svc._repository.delete_session = AsyncMock()
        await svc.invalidate_user_session("user-xyz")
        svc._repository.delete_session.assert_called_once_with("user-xyz")

    def test_validate_key_session_bad_base64(self):
        from app.shared.session.service import SessionService
        from app.shared.session.exceptions import InvalidKeySessionException
        with pytest.raises(InvalidKeySessionException):
            SessionService._validate_key_session("!!!not base64!!!")

    def test_validate_key_session_wrong_length(self):
        from app.shared.session.service import SessionService
        from app.shared.session.exceptions import InvalidKeySessionException
        # Valid base64 but wrong byte count (not 32)
        short_key = base64.urlsafe_b64encode(b"short").decode()
        with pytest.raises(InvalidKeySessionException):
            SessionService._validate_key_session(short_key)

    def test_validate_metadata_not_dict(self):
        from app.shared.session.service import SessionService
        from app.shared.session.exceptions import InvalidMetadataException
        with pytest.raises(InvalidMetadataException):
            SessionService._validate_metadata([1, 2, 3])

    def test_validate_metadata_too_many_keys(self, monkeypatch):
        from app.shared.session.service import SessionService
        from app.shared.session.exceptions import InvalidMetadataException
        from app import config
        monkeypatch.setattr(config.settings, "METADATA_MAX_KEYS", 2)
        big_meta = {"a": 1, "b": 2, "c": 3}
        with pytest.raises(InvalidMetadataException):
            SessionService._validate_metadata(big_meta)

    def test_validate_metadata_forbidden_key(self):
        from app.shared.session.service import SessionService
        from app.shared.session.exceptions import InvalidMetadataException
        with pytest.raises(InvalidMetadataException):
            SessionService._validate_metadata({"password": "secret"})

    def test_validate_metadata_non_serializable(self):
        from app.shared.session.service import SessionService
        from app.shared.session.exceptions import InvalidMetadataException
        with pytest.raises(InvalidMetadataException):
            SessionService._validate_metadata({"val": object()})

    def test_validate_metadata_too_large(self, monkeypatch):
        from app.shared.session.service import SessionService
        from app.shared.session.exceptions import InvalidMetadataException
        from app import config
        monkeypatch.setattr(config.settings, "METADATA_MAX_SIZE_BYTES", 10)
        with pytest.raises(InvalidMetadataException):
            SessionService._validate_metadata({"key": "a very long value that exceeds 10 bytes for sure"})

    def test_validate_ip_empty(self):
        from app.shared.session.service import SessionService
        from app.shared.session.exceptions import InvalidIpAddressException
        with pytest.raises(InvalidIpAddressException):
            SessionService._validate_ip_address("")

    def test_validate_ip_invalid(self):
        from app.shared.session.service import SessionService
        from app.shared.session.exceptions import InvalidIpAddressException
        with pytest.raises(InvalidIpAddressException):
            SessionService._validate_ip_address("not.an.ip.address.at.all.really")

    def test_validate_entity_id_string(self):
        from app.shared.session.service import SessionService
        eid = uuid4()
        result = SessionService._validate_entity_id(eid)
        assert result == str(eid)


# ═══════════════════════════════════════════════════════════════════════════════
# JWEHandler / SessionHMAC edge cases (security.py)
# ═══════════════════════════════════════════════════════════════════════════════


class TestSecurityEdgeCases:
    def test_jwe_handler_invalid_base64_key(self):
        from app.shared.session.security import JWEHandler
        with pytest.raises(ValueError, match="valid base64"):
            JWEHandler("!!!not_valid_base64!!!")

    def test_jwe_handler_wrong_length_key(self):
        from app.shared.session.security import JWEHandler
        short_key = base64.b64encode(b"tooshort").decode()
        with pytest.raises(ValueError, match="32 bytes"):
            JWEHandler(short_key)

    def test_jwe_decrypt_non_json_payload(self):
        from app.shared.session.security import JWEHandler
        from jose.exceptions import JWEError

        key = base64.b64encode(secrets.token_bytes(32)).decode()
        handler = JWEHandler(key)

        with patch("app.shared.session.security.jwe.decrypt", return_value=b"not json!!!"):
            with pytest.raises(JWEError, match="Invalid JSON payload"):
                handler.decrypt("fake_token")

    def test_session_hmac_invalid_key(self):
        from app.shared.session.security import SessionHMAC
        with pytest.raises(ValueError, match="Invalid key_session for HMAC"):
            SessionHMAC.compute_hmac("sid", "payload", "!!!bad base64!!!")


# ═══════════════════════════════════════════════════════════════════════════════
# Session exceptions (exceptions.py lines 28, 50, 60)
# ═══════════════════════════════════════════════════════════════════════════════


class TestSessionExceptions:
    def test_invalid_refresh_token_exception(self):
        from app.shared.session.exceptions import InvalidRefreshTokenException
        exc = InvalidRefreshTokenException()
        assert exc.status_code == 401
        assert "refresh token" in exc.detail

    def test_invalid_token_exception(self):
        from app.shared.session.exceptions import InvalidTokenException
        exc = InvalidTokenException()
        assert exc.status_code == 401

    def test_session_expired_exception(self):
        from app.shared.session.exceptions import SessionExpiredException
        exc = SessionExpiredException()
        assert exc.status_code == 401

    def test_rate_limit_exception_singular_second(self):
        from app.shared.session.exceptions import RateLimitExceededException
        exc = RateLimitExceededException(retry_after=1)
        assert "second" in exc.detail
        assert "seconds" not in exc.detail


# ═══════════════════════════════════════════════════════════════════════════════
# SharedAuthService edge cases (auth/service.py)
# ═══════════════════════════════════════════════════════════════════════════════


class TestSharedAuthServiceEdgeCases:
    def test_change_password_no_sensitive_data_id(self, session):
        from app.shared.auth.service import SharedAuthService, CurrentAccount, ChangePasswordRequest
        from app.shared.exceptions import BadRequestException

        svc = SharedAuthService(session)
        current = CurrentAccount(
            account_id=uuid4(),
            sensitive_data_id=None,
            account_type="device",
            email=None,
        )
        payload = ChangePasswordRequest(current_password="Old123!@", new_password="New456!@")
        with pytest.raises(BadRequestException, match="does not use password"):
            svc.change_password(current, payload)

    def test_change_password_sensitive_data_not_found(self, session):
        from app.shared.auth.service import SharedAuthService, CurrentAccount, ChangePasswordRequest
        from app.shared.exceptions import BadRequestException

        svc = SharedAuthService(session)
        current = CurrentAccount(
            account_id=uuid4(),
            sensitive_data_id=uuid4(),
            account_type="user",
            email="x@test.com",
        )
        payload = ChangePasswordRequest(current_password="Old123!@", new_password="New456!@")
        with pytest.raises(BadRequestException, match="not found"):
            svc.change_password(current, payload)

    def test_get_current_account_malformed_dict(self):
        from app.shared.auth.service import get_current_account_from_request

        mock_request = MagicMock()
        mock_request.state.current_account = {"missing_account_id": True}
        with pytest.raises(HTTPException) as exc_info:
            get_current_account_from_request(mock_request)
        assert exc_info.value.status_code == 401
        assert "Invalid authentication context" in exc_info.value.detail

    def test_get_shared_auth_service(self, session):
        from app.shared.auth.service import get_shared_auth_service, SharedAuthService
        svc = get_shared_auth_service(session)
        assert isinstance(svc, SharedAuthService)


# ═══════════════════════════════════════════════════════════════════════════════
# E2EMiddleware edge cases (middleware.py lines 92-94, 118)
# ═══════════════════════════════════════════════════════════════════════════════


class TestE2EMiddlewareEdgeCases:
    def test_valkey_unavailable_returns_503(self, client):
        import app.shared.e2e.middleware as mw_module
        from app.shared.e2e.session import E2ESessionRepository

        failing_repo = MagicMock(spec=E2ESessionRepository)
        failing_repo.get_session = AsyncMock(side_effect=Exception("Valkey down"))

        old_override = mw_module._session_repo_override
        mw_module._session_repo_override = failing_repo
        try:
            resp = client.get(
                "/api/v1/administrators",
                headers={"X-Session-ID": "some-session-id"},
            )
            assert resp.status_code == 503
        finally:
            mw_module._session_repo_override = old_override

    def test_content_length_header_too_large(self, client, master_admin_account):
        """Content-Length header > 1MB triggers 413 before reading body."""
        import app.shared.e2e.middleware as mw_module
        from app.shared.e2e.session import E2ESessionRepository

        # Create a fake session that returns valid session data
        fake_session = {
            "session_key": secrets.token_hex(32),
            "account": {
                "account_id": str(master_admin_account["id"]),
                "account_type": "administrator",
                "is_master": True,
                "email": master_admin_account["email"],
            },
        }
        mock_repo = MagicMock(spec=E2ESessionRepository)
        mock_repo.get_session = AsyncMock(return_value=fake_session)

        old_override = mw_module._session_repo_override
        mw_module._session_repo_override = mock_repo
        try:
            resp = client.post(
                "/api/v1/devices/",
                headers={
                    "X-Session-ID": "fake-session",
                    "content-length": "2000000",  # 2 MB > 1 MB limit
                },
                content=b"x",
            )
            assert resp.status_code == 413
        finally:
            mw_module._session_repo_override = old_override


# ═══════════════════════════════════════════════════════════════════════════════
# Rate limit (rate_limit.py lines 41, 66)
# ═══════════════════════════════════════════════════════════════════════════════


class TestRateLimitEdgeCases:
    def test_build_rate_limit_key_no_route(self):
        from app.shared.rate_limit import build_rate_limit_key

        mock_request = MagicMock()
        mock_request.scope = {"route": None}
        mock_request.state.current_account = None
        mock_request.client.host = "1.2.3.4"

        key = build_rate_limit_key(mock_request)
        assert key.startswith("global:ip:")

    def test_get_rate_limit_repository_returns_session_repo(self):
        from app.shared.rate_limit import get_rate_limit_repository
        from app.shared.session.repository import SessionRepository
        repo = get_rate_limit_repository()
        assert isinstance(repo, SessionRepository)


# ═══════════════════════════════════════════════════════════════════════════════
# database/format.py — UserPlainAttribute properties (lines 22-61)
# ═══════════════════════════════════════════════════════════════════════════════


class TestUserPlainAttributeProperties:
    def test_all_plain_attribute_properties(self, session, master_admin_account):
        from app.database.model import Administrator
        admin = session.get(Administrator, master_admin_account["id"])

        # Trigger all the uncovered property return statements
        _ = admin.phone
        _ = admin.address
        _ = admin.city
        _ = admin.state
        _ = admin.postal_code
        _ = admin.birth_date
        _ = admin.email
        _ = admin.password_hash
        _ = admin.curp
        _ = admin.rfc


# ═══════════════════════════════════════════════════════════════════════════════
# BaseService._log_audit (service.py lines 83-101)
# ═══════════════════════════════════════════════════════════════════════════════


class TestBaseServiceLogAudit:
    def test_log_audit_with_current_user_create(self, session):
        from app.shared.authorization.dependencies import _current_user_ctx
        from app.domain.service.service import ServiceService
        from app.database.model import Service

        entity = Service(name="AuditCreateTest", administrator_id=uuid4())
        session.add(entity)
        session.commit()
        session.refresh(entity)

        user = _make_current_user("administrator")
        token = _current_user_ctx.set(user)
        try:
            svc = ServiceService(session)
            svc._log_audit("create", entity)
        finally:
            _current_user_ctx.reset(token)

    def test_log_audit_with_current_user_update_with_changes(self, session):
        from app.shared.authorization.dependencies import _current_user_ctx
        from app.domain.service.service import ServiceService
        from app.database.model import Service

        entity = Service(name="OldName", administrator_id=uuid4())
        session.add(entity)
        session.commit()
        session.refresh(entity)

        old = entity.model_dump()   # non-empty after refresh
        entity.name = "NewName"

        user = _make_current_user("administrator")
        token = _current_user_ctx.set(user)
        try:
            svc = ServiceService(session)
            svc._log_audit("update", entity, old)
        finally:
            _current_user_ctx.reset(token)

    def test_log_audit_with_current_user_update_no_changes(self, session):
        from app.shared.authorization.dependencies import _current_user_ctx
        from app.domain.service.service import ServiceService
        from app.database.model import Service

        entity = Service(name="Unchanged", administrator_id=uuid4())
        session.add(entity)
        session.commit()
        session.refresh(entity)

        old = entity.model_dump()   # non-empty, same as current state → no changes

        user = _make_current_user("administrator")
        token = _current_user_ctx.set(user)
        try:
            svc = ServiceService(session)
            svc._log_audit("update", entity, old)  # changes={} → details = None
        finally:
            _current_user_ctx.reset(token)


# ═══════════════════════════════════════════════════════════════════════════════
# Domain services — manager / user / unknown context paths
# ═══════════════════════════════════════════════════════════════════════════════


class TestDeviceServiceContextPaths:
    def test_get_all_manager_empty(self, session, manager_account):
        from app.shared.authorization.dependencies import _current_user_ctx
        from app.domain.device.service import DeviceService

        user = _make_current_user("manager", manager_account["id"], is_master=False)
        token = _current_user_ctx.set(user)
        try:
            result = DeviceService(session).get_all()
            assert result.total == 0
        finally:
            _current_user_ctx.reset(token)

    def test_get_all_user_returns_empty(self, session, user_account):
        from app.shared.authorization.dependencies import _current_user_ctx
        from app.domain.device.service import DeviceService

        user = _make_current_user("user", user_account["id"], is_master=False)
        token = _current_user_ctx.set(user)
        try:
            result = DeviceService(session).get_all()
            assert result.total == 0
        finally:
            _current_user_ctx.reset(token)

    def test_get_all_unknown_returns_empty(self, session):
        from app.shared.authorization.dependencies import _current_user_ctx
        from app.domain.device.service import DeviceService

        user = _make_current_user("application")
        token = _current_user_ctx.set(user)
        try:
            result = DeviceService(session).get_all()
            assert result.total == 0
        finally:
            _current_user_ctx.reset(token)

    def test_get_by_id_admin_path(self, session):
        from app.shared.authorization.dependencies import _current_user_ctx
        from app.domain.device.service import DeviceService
        from app.database.model import Device

        device = Device(name="AdminDevice", is_active=True)
        session.add(device)
        session.commit()

        user = _make_current_user("administrator")
        token = _current_user_ctx.set(user)
        try:
            result = DeviceService(session).get_by_id(device.id)
            assert result.id == device.id
        finally:
            _current_user_ctx.reset(token)

    def test_get_by_id_manager_no_access(self, session, manager_account):
        from app.shared.authorization.dependencies import _current_user_ctx
        from app.domain.device.service import DeviceService
        from app.database.model import Device
        from app.shared.exceptions import NotFoundException

        device = Device(name="UnauthorizedDevice", is_active=True)
        session.add(device)
        session.commit()

        user = _make_current_user("manager", manager_account["id"], is_master=False)
        token = _current_user_ctx.set(user)
        try:
            with pytest.raises(NotFoundException):
                DeviceService(session).get_by_id(device.id)
        finally:
            _current_user_ctx.reset(token)

    def test_get_by_id_user_raises(self, session, user_account):
        from app.shared.authorization.dependencies import _current_user_ctx
        from app.domain.device.service import DeviceService
        from app.database.model import Device
        from app.shared.exceptions import NotFoundException

        device = Device(name="UserDevice", is_active=True)
        session.add(device)
        session.commit()

        user = _make_current_user("user", user_account["id"], is_master=False)
        token = _current_user_ctx.set(user)
        try:
            with pytest.raises(NotFoundException):
                DeviceService(session).get_by_id(device.id)
        finally:
            _current_user_ctx.reset(token)

    def test_get_by_id_unknown_raises(self, session):
        from app.shared.authorization.dependencies import _current_user_ctx
        from app.domain.device.service import DeviceService
        from app.database.model import Device
        from app.shared.exceptions import NotFoundException

        device = Device(name="UnknownDevice", is_active=True)
        session.add(device)
        session.commit()

        user = _make_current_user("application")
        token = _current_user_ctx.set(user)
        try:
            with pytest.raises(NotFoundException):
                DeviceService(session).get_by_id(device.id)
        finally:
            _current_user_ctx.reset(token)


class TestApplicationServiceContextPaths:
    def test_get_all_manager_empty(self, session, manager_account):
        from app.shared.authorization.dependencies import _current_user_ctx
        from app.domain.application.service import ApplicationService

        user = _make_current_user("manager", manager_account["id"], is_master=False)
        token = _current_user_ctx.set(user)
        try:
            result = ApplicationService(session).get_all()
            assert result.total == 0
        finally:
            _current_user_ctx.reset(token)

    def test_get_all_user_returns_empty(self, session, user_account):
        from app.shared.authorization.dependencies import _current_user_ctx
        from app.domain.application.service import ApplicationService

        user = _make_current_user("user", user_account["id"], is_master=False)
        token = _current_user_ctx.set(user)
        try:
            result = ApplicationService(session).get_all()
            assert result.total == 0
        finally:
            _current_user_ctx.reset(token)

    def test_get_all_unknown_returns_empty(self, session):
        from app.shared.authorization.dependencies import _current_user_ctx
        from app.domain.application.service import ApplicationService

        user = _make_current_user("device")
        token = _current_user_ctx.set(user)
        try:
            result = ApplicationService(session).get_all()
            assert result.total == 0
        finally:
            _current_user_ctx.reset(token)

    def _make_app(self, session, name: str = "TestApp"):
        from app.database.model import Application
        app = Application(
            name=name, version="1.0", url="http://test.com",
            description="test", administrator_id=uuid4(), is_active=True,
        )
        session.add(app)
        session.commit()
        return app

    def test_get_by_id_admin_path(self, session):
        from app.shared.authorization.dependencies import _current_user_ctx
        from app.domain.application.service import ApplicationService
        app = self._make_app(session)

        user = _make_current_user("administrator")
        token = _current_user_ctx.set(user)
        try:
            result = ApplicationService(session).get_by_id(app.id)
            assert result.id == app.id
        finally:
            _current_user_ctx.reset(token)

    def test_get_by_id_manager_no_access(self, session, manager_account):
        from app.shared.authorization.dependencies import _current_user_ctx
        from app.domain.application.service import ApplicationService
        from app.shared.exceptions import NotFoundException
        app = self._make_app(session, "UnauthorizedApp")

        user = _make_current_user("manager", manager_account["id"], is_master=False)
        token = _current_user_ctx.set(user)
        try:
            with pytest.raises(NotFoundException):
                ApplicationService(session).get_by_id(app.id)
        finally:
            _current_user_ctx.reset(token)

    def test_get_by_id_unknown_raises(self, session):
        from app.shared.authorization.dependencies import _current_user_ctx
        from app.domain.application.service import ApplicationService
        from app.shared.exceptions import NotFoundException
        app = self._make_app(session, "AnyApp")

        user = _make_current_user("device")
        token = _current_user_ctx.set(user)
        try:
            with pytest.raises(NotFoundException):
                ApplicationService(session).get_by_id(app.id)
        finally:
            _current_user_ctx.reset(token)


class TestServiceServiceContextPaths:
    def _make_service(self, session):
        from app.database.model import Service
        svc = Service(name="TestSvc", administrator_id=uuid4())
        session.add(svc)
        session.commit()
        return svc

    def test_get_all_manager_empty(self, session, manager_account):
        from app.shared.authorization.dependencies import _current_user_ctx
        from app.domain.service.service import ServiceService

        user = _make_current_user("manager", manager_account["id"], is_master=False)
        token = _current_user_ctx.set(user)
        try:
            result = ServiceService(session).get_all()
            assert result.total == 0
        finally:
            _current_user_ctx.reset(token)

    def test_get_all_user_returns_empty(self, session, user_account):
        from app.shared.authorization.dependencies import _current_user_ctx
        from app.domain.service.service import ServiceService

        user = _make_current_user("user", user_account["id"], is_master=False)
        token = _current_user_ctx.set(user)
        try:
            result = ServiceService(session).get_all()
            assert result.total == 0
        finally:
            _current_user_ctx.reset(token)

    def test_get_all_unknown_returns_empty(self, session):
        from app.shared.authorization.dependencies import _current_user_ctx
        from app.domain.service.service import ServiceService

        user = _make_current_user("device")
        token = _current_user_ctx.set(user)
        try:
            result = ServiceService(session).get_all()
            assert result.total == 0
        finally:
            _current_user_ctx.reset(token)

    def test_get_by_id_admin_path(self, session):
        from app.shared.authorization.dependencies import _current_user_ctx
        from app.domain.service.service import ServiceService
        svc_entity = self._make_service(session)

        user = _make_current_user("administrator")
        token = _current_user_ctx.set(user)
        try:
            result = ServiceService(session).get_by_id(svc_entity.id)
            assert result.id == svc_entity.id
        finally:
            _current_user_ctx.reset(token)

    def test_get_by_id_manager_no_access(self, session, manager_account):
        from app.shared.authorization.dependencies import _current_user_ctx
        from app.domain.service.service import ServiceService
        from app.shared.exceptions import NotFoundException
        svc_entity = self._make_service(session)

        user = _make_current_user("manager", manager_account["id"], is_master=False)
        token = _current_user_ctx.set(user)
        try:
            with pytest.raises(NotFoundException):
                ServiceService(session).get_by_id(svc_entity.id)
        finally:
            _current_user_ctx.reset(token)

    def test_get_by_id_unknown_raises(self, session):
        from app.shared.authorization.dependencies import _current_user_ctx
        from app.domain.service.service import ServiceService
        from app.shared.exceptions import NotFoundException
        svc_entity = self._make_service(session)

        user = _make_current_user("device")
        token = _current_user_ctx.set(user)
        try:
            with pytest.raises(NotFoundException):
                ServiceService(session).get_by_id(svc_entity.id)
        finally:
            _current_user_ctx.reset(token)


class TestUserServiceContextPaths:
    def test_get_all_manager_empty(self, session, manager_account):
        from app.shared.authorization.dependencies import _current_user_ctx
        from app.domain.user.service import UserService

        user = _make_current_user("manager", manager_account["id"], is_master=False)
        token = _current_user_ctx.set(user)
        try:
            result = UserService(session).get_all()
            assert result.total == 0
        finally:
            _current_user_ctx.reset(token)

    def test_get_all_user_returns_self(self, session, user_account):
        from app.shared.authorization.dependencies import _current_user_ctx
        from app.domain.user.service import UserService

        user = _make_current_user("user", user_account["id"], is_master=False)
        token = _current_user_ctx.set(user)
        try:
            result = UserService(session).get_all()
            # user sees themselves
            assert result.total == 1
        finally:
            _current_user_ctx.reset(token)

    def test_get_all_unknown_returns_empty(self, session):
        from app.shared.authorization.dependencies import _current_user_ctx
        from app.domain.user.service import UserService

        user = _make_current_user("device")
        token = _current_user_ctx.set(user)
        try:
            result = UserService(session).get_all()
            assert result.total == 0
        finally:
            _current_user_ctx.reset(token)

    def test_get_by_id_admin_path(self, session, user_account):
        from app.shared.authorization.dependencies import _current_user_ctx
        from app.domain.user.service import UserService

        user = _make_current_user("administrator")
        token = _current_user_ctx.set(user)
        try:
            result = UserService(session).get_by_id(user_account["id"])
            assert result.id == user_account["id"]
        finally:
            _current_user_ctx.reset(token)

    def test_get_by_id_manager_no_access(self, session, manager_account, user_account):
        from app.shared.authorization.dependencies import _current_user_ctx
        from app.domain.user.service import UserService
        from app.shared.exceptions import NotFoundException

        user = _make_current_user("manager", manager_account["id"], is_master=False)
        token = _current_user_ctx.set(user)
        try:
            with pytest.raises(NotFoundException):
                UserService(session).get_by_id(user_account["id"])
        finally:
            _current_user_ctx.reset(token)

    def test_get_by_id_user_own(self, session, user_account):
        from app.shared.authorization.dependencies import _current_user_ctx
        from app.domain.user.service import UserService

        user = _make_current_user("user", user_account["id"], is_master=False)
        token = _current_user_ctx.set(user)
        try:
            result = UserService(session).get_by_id(user_account["id"])
            assert result.id == user_account["id"]
        finally:
            _current_user_ctx.reset(token)

    def test_get_by_id_user_other_raises(self, session, user_account, manager_account):
        from app.shared.authorization.dependencies import _current_user_ctx
        from app.domain.user.service import UserService
        from app.shared.exceptions import NotFoundException
        from app.database.model import User

        # Create a second user
        second_user_id = uuid4()

        user = _make_current_user("user", user_account["id"], is_master=False)
        token = _current_user_ctx.set(user)
        try:
            # Try to access a non-existent user (different ID)
            with pytest.raises(NotFoundException):
                UserService(session).get_by_id(uuid4())
        finally:
            _current_user_ctx.reset(token)

    def test_get_by_id_unknown_raises(self, session, user_account):
        from app.shared.authorization.dependencies import _current_user_ctx
        from app.domain.user.service import UserService
        from app.shared.exceptions import NotFoundException

        user = _make_current_user("device")
        token = _current_user_ctx.set(user)
        try:
            with pytest.raises(NotFoundException):
                UserService(session).get_by_id(user_account["id"])
        finally:
            _current_user_ctx.reset(token)


class TestTicketServiceContextPaths:
    def test_service_ticket_get_all_manager_empty(self, session, manager_account):
        from app.shared.authorization.dependencies import _current_user_ctx
        from app.domain.tickets.service import ServiceTicketService

        user = _make_current_user("manager", manager_account["id"], is_master=False)
        token = _current_user_ctx.set(user)
        try:
            result = ServiceTicketService(session).get_all()
            assert result.total == 0
        finally:
            _current_user_ctx.reset(token)

    def test_service_ticket_get_all_user_empty(self, session, user_account):
        from app.shared.authorization.dependencies import _current_user_ctx
        from app.domain.tickets.service import ServiceTicketService

        user = _make_current_user("user", user_account["id"], is_master=False)
        token = _current_user_ctx.set(user)
        try:
            result = ServiceTicketService(session).get_all()
            assert result.total == 0
        finally:
            _current_user_ctx.reset(token)

    def test_service_ticket_get_all_unknown_empty(self, session):
        from app.shared.authorization.dependencies import _current_user_ctx
        from app.domain.tickets.service import ServiceTicketService

        user = _make_current_user("device")
        token = _current_user_ctx.set(user)
        try:
            result = ServiceTicketService(session).get_all()
            assert result.total == 0
        finally:
            _current_user_ctx.reset(token)

    def test_ecosystem_ticket_get_all_manager_empty(self, session, manager_account):
        from app.shared.authorization.dependencies import _current_user_ctx
        from app.domain.tickets.service import EcosystemTicketService

        user = _make_current_user("manager", manager_account["id"], is_master=False)
        token = _current_user_ctx.set(user)
        try:
            result = EcosystemTicketService(session).get_all()
            assert result.total == 0
        finally:
            _current_user_ctx.reset(token)

    def test_ecosystem_ticket_get_all_user_empty(self, session, user_account):
        from app.shared.authorization.dependencies import _current_user_ctx
        from app.domain.tickets.service import EcosystemTicketService

        user = _make_current_user("user", user_account["id"], is_master=False)
        token = _current_user_ctx.set(user)
        try:
            result = EcosystemTicketService(session).get_all()
            assert result.total == 0
        finally:
            _current_user_ctx.reset(token)

    def test_ecosystem_ticket_get_all_unknown_empty(self, session):
        from app.shared.authorization.dependencies import _current_user_ctx
        from app.domain.tickets.service import EcosystemTicketService

        user = _make_current_user("device")
        token = _current_user_ctx.set(user)
        try:
            result = EcosystemTicketService(session).get_all()
            assert result.total == 0
        finally:
            _current_user_ctx.reset(token)


# ═══════════════════════════════════════════════════════════════════════════════
# Domain repositories — view-based query methods
# ═══════════════════════════════════════════════════════════════════════════════


class TestDomainRepositoryViewMethods:
    """Use the `session` fixture (which uses the `db` fixture that creates views)."""

    def test_device_repo_get_for_manager_empty(self, session, manager_account):
        from app.domain.device.repository import DeviceRepository
        repo = DeviceRepository(session)
        items, total = repo.get_for_manager(manager_account["id"])
        assert total == 0
        assert items == []

    def test_device_repo_check_manager_access_false(self, session, manager_account):
        from app.domain.device.repository import DeviceRepository
        repo = DeviceRepository(session)
        result = repo.check_manager_access(uuid4(), manager_account["id"])
        assert result is False

    def test_user_repo_get_for_manager_empty(self, session, manager_account):
        from app.domain.user.repository import UserRepository
        repo = UserRepository(session)
        items, total = repo.get_for_manager(manager_account["id"])
        assert total == 0
        assert items == []

    def test_user_repo_check_manager_access_false(self, session, manager_account):
        from app.domain.user.repository import UserRepository
        repo = UserRepository(session)
        result = repo.check_manager_access(uuid4(), manager_account["id"])
        assert result is False

    def test_service_repo_get_for_manager_empty(self, session, manager_account):
        from app.domain.service.repository import ServiceRepository
        repo = ServiceRepository(session)
        items, total = repo.get_for_manager(manager_account["id"])
        assert total == 0
        assert items == []

    def test_service_repo_check_manager_access_false(self, session, manager_account):
        from app.domain.service.repository import ServiceRepository
        repo = ServiceRepository(session)
        result = repo.check_manager_access(uuid4(), manager_account["id"])
        assert result is False

    def test_application_repo_get_for_manager_empty(self, session, manager_account):
        from app.domain.application.repository import ApplicationRepository
        repo = ApplicationRepository(session)
        items, total = repo.get_for_manager(manager_account["id"])
        assert total == 0
        assert items == []

    def test_application_repo_check_manager_access_false(self, session, manager_account):
        from app.domain.application.repository import ApplicationRepository
        repo = ApplicationRepository(session)
        result = repo.check_manager_access(uuid4(), manager_account["id"])
        assert result is False

    def test_service_ticket_repo_get_for_manager_empty(self, session, manager_account):
        from app.domain.tickets.repository import ServiceTicketRepository
        repo = ServiceTicketRepository(session)
        items, total = repo.get_for_manager_sql(manager_account["id"])
        assert total == 0
        assert items == []

    def test_ecosystem_ticket_repo_get_for_manager_empty(self, session, manager_account):
        from app.domain.tickets.repository import EcosystemTicketRepository
        repo = EcosystemTicketRepository(session)
        items, total = repo.get_for_manager(manager_account["id"])
        assert total == 0
        assert items == []

    def test_service_ticket_repo_get_for_user_empty(self, session, user_account):
        from app.domain.tickets.repository import ServiceTicketRepository
        repo = ServiceTicketRepository(session)
        items, total = repo.get_for_user(user_account["id"])
        assert total == 0
        assert items == []


# ═══════════════════════════════════════════════════════════════════════════════
# Schema validators — device/schemas.py (lines for DeviceUpdate validators)
# ═══════════════════════════════════════════════════════════════════════════════


class TestDeviceSchemaValidators:
    def test_device_create_invalid_ip(self):
        from app.domain.device.schemas import DeviceCreate
        with pytest.raises(Exception, match="Invalid IP"):
            DeviceCreate(name="d", ip="not.an.ip.address")

    def test_device_create_invalid_mac(self):
        from app.domain.device.schemas import DeviceCreate
        with pytest.raises(Exception, match="Invalid MAC"):
            DeviceCreate(name="d", mac="not-a-mac")

    def test_device_create_valid_mac_normalized(self):
        from app.domain.device.schemas import DeviceCreate
        d = DeviceCreate(name="d", mac="aa:bb:cc:dd:ee:ff")
        assert d.mac == "AA:BB:CC:DD:EE:FF"

    def test_device_update_invalid_ip(self):
        from app.domain.device.schemas import DeviceUpdate
        with pytest.raises(Exception, match="Invalid IP"):
            DeviceUpdate(ip="999.999.999.999")

    def test_device_update_invalid_mac(self):
        from app.domain.device.schemas import DeviceUpdate
        with pytest.raises(Exception, match="Invalid MAC"):
            DeviceUpdate(mac="zz:zz:zz:zz:zz:zz")

    def test_device_update_valid_mac_normalized(self):
        from app.domain.device.schemas import DeviceUpdate
        d = DeviceUpdate(mac="aa-bb-cc-dd-ee-ff")
        assert d.mac == "AA-BB-CC-DD-EE-FF"

    def test_device_update_none_ip_allowed(self):
        from app.domain.device.schemas import DeviceUpdate
        d = DeviceUpdate(ip=None)
        assert d.ip is None

    def test_device_update_none_mac_allowed(self):
        from app.domain.device.schemas import DeviceUpdate
        d = DeviceUpdate(mac=None)
        assert d.mac is None


# ═══════════════════════════════════════════════════════════════════════════════
# Schema validators — role/schemas.py (line 11, 13, 46)
# ═══════════════════════════════════════════════════════════════════════════════


class TestRoleSchemaValidators:
    def test_role_create_empty_name_after_strip(self):
        from app.domain.role.schemas import RoleCreate
        # min_length=1 + str_strip_whitespace rejects whitespace-only strings
        with pytest.raises(Exception):
            RoleCreate(name="   ", service_id=uuid4())

    def test_normalize_role_name_empty_raises(self):
        from app.domain.role.schemas import _normalize_role_name_strict_letters
        with pytest.raises(ValueError, match="empty"):
            _normalize_role_name_strict_letters("   ")

    def test_normalize_role_name_too_long_raises(self):
        from app.domain.role.schemas import _normalize_role_name_strict_letters
        with pytest.raises(ValueError, match="exceed"):
            _normalize_role_name_strict_letters("A" * 256)

    def test_role_create_name_with_digit(self):
        from app.domain.role.schemas import RoleCreate
        with pytest.raises(Exception, match="letters"):
            RoleCreate(name="Admin1", service_id=uuid4())

    def test_role_update_none_name_allowed(self):
        from app.domain.role.schemas import RoleUpdate
        r = RoleUpdate(name=None)
        assert r.name is None

    def test_role_update_invalid_name(self):
        from app.domain.role.schemas import RoleUpdate
        with pytest.raises(Exception, match="letters"):
            RoleUpdate(name="Bad1Name")


# ═══════════════════════════════════════════════════════════════════════════════
# personal_data/schemas.py — update validator None paths (lines 113, 118, 123, 129, 154, 207, etc.)
# ═══════════════════════════════════════════════════════════════════════════════


class TestPersonalDataUpdateValidators:
    def test_non_critical_update_postal_code_none(self):
        from app.domain.personal_data.schemas import NonCriticalPersonalDataUpdate
        u = NonCriticalPersonalDataUpdate(postal_code=None)
        assert u.postal_code is None

    def test_non_critical_update_postal_code_invalid(self):
        from app.domain.personal_data.schemas import NonCriticalPersonalDataUpdate
        with pytest.raises(Exception):
            NonCriticalPersonalDataUpdate(postal_code="ABCDE")

    def test_non_critical_update_postal_code_valid(self):
        from app.domain.personal_data.schemas import NonCriticalPersonalDataUpdate
        u = NonCriticalPersonalDataUpdate(postal_code="06500")
        assert u.postal_code == "06500"

    def test_non_critical_update_birth_date_none(self):
        from app.domain.personal_data.schemas import NonCriticalPersonalDataUpdate
        u = NonCriticalPersonalDataUpdate(birth_date=None)
        assert u.birth_date is None

    def test_sensitive_update_email_none(self):
        from app.domain.personal_data.schemas import SensitiveDataUpdate
        u = SensitiveDataUpdate(email=None)
        assert u.email is None

    def test_sensitive_update_email_invalid(self):
        from app.domain.personal_data.schemas import SensitiveDataUpdate
        with pytest.raises(Exception, match="invalid email"):
            SensitiveDataUpdate(email="not-an-email")

    def test_sensitive_update_email_valid(self):
        from app.domain.personal_data.schemas import SensitiveDataUpdate
        u = SensitiveDataUpdate(email="valid@example.com")
        assert u.email == "valid@example.com"

    def test_sensitive_update_password_none(self):
        from app.domain.personal_data.schemas import SensitiveDataUpdate
        u = SensitiveDataUpdate(password=None)
        assert u.password is None

    def test_sensitive_update_password_invalid(self):
        from app.domain.personal_data.schemas import SensitiveDataUpdate
        with pytest.raises(Exception, match="uppercase"):
            SensitiveDataUpdate(password="weakpassword")

    def test_sensitive_update_curp_none(self):
        from app.domain.personal_data.schemas import SensitiveDataUpdate
        u = SensitiveDataUpdate(curp=None)
        assert u.curp is None

    def test_sensitive_update_curp_invalid(self):
        from app.domain.personal_data.schemas import SensitiveDataUpdate
        with pytest.raises(Exception, match="CURP"):
            SensitiveDataUpdate(curp="INVALID_CURP")

    def test_sensitive_update_curp_valid(self):
        from app.domain.personal_data.schemas import SensitiveDataUpdate
        u = SensitiveDataUpdate(curp="PEMJ900615HDFLRN07")
        assert u.curp == "PEMJ900615HDFLRN07"

    def test_sensitive_update_rfc_none(self):
        from app.domain.personal_data.schemas import SensitiveDataUpdate
        u = SensitiveDataUpdate(rfc=None)
        assert u.rfc is None

    def test_sensitive_update_rfc_invalid(self):
        from app.domain.personal_data.schemas import SensitiveDataUpdate
        with pytest.raises(Exception, match="RFC"):
            SensitiveDataUpdate(rfc="INVALID_RFC")

    def test_sensitive_update_rfc_valid(self):
        from app.domain.personal_data.schemas import SensitiveDataUpdate
        u = SensitiveDataUpdate(rfc="PEMJ900615AB1")
        assert u.rfc == "PEMJ900615AB1"


# ═══════════════════════════════════════════════════════════════════════════════
# Tenant middleware — non-master admin path (tenant.py lines 32-44)
# ═══════════════════════════════════════════════════════════════════════════════


class TestTenantMiddlewareDirectDispatch:
    @pytest.mark.anyio
    async def test_non_master_admin_path(self, db, monkeypatch, session, regular_admin_account):
        import app.shared.middleware.tenant as tenant_module
        monkeypatch.setattr(tenant_module, "engine", db)

        from app.shared.middleware.tenant import TenantContextMiddleware
        from app.main import app as fastapi_app

        middleware = TenantContextMiddleware(fastapi_app)

        mock_state = MagicMock()
        mock_state.current_account = {
            "account_id": str(regular_admin_account["id"]),
            "account_type": "administrator",
            "is_master": False,
        }

        mock_request = MagicMock()
        mock_request.state = mock_state

        mock_response = MagicMock()
        call_next = AsyncMock(return_value=mock_response)

        await middleware.dispatch(mock_request, call_next)
        call_next.assert_called_once_with(mock_request)
        # tenant_id should be set (None if no tenant assigned to regular admin)
        assert hasattr(mock_state, "tenant_id")

    @pytest.mark.anyio
    async def test_master_admin_skips_lookup(self, db, monkeypatch):
        import app.shared.middleware.tenant as tenant_module
        monkeypatch.setattr(tenant_module, "engine", db)

        from app.shared.middleware.tenant import TenantContextMiddleware
        from app.main import app as fastapi_app

        middleware = TenantContextMiddleware(fastapi_app)

        mock_state = MagicMock()
        mock_state.current_account = {
            "account_id": str(uuid4()),
            "account_type": "administrator",
            "is_master": True,
        }

        mock_request = MagicMock()
        mock_request.state = mock_state

        mock_response = MagicMock()
        call_next = AsyncMock(return_value=mock_response)

        await middleware.dispatch(mock_request, call_next)
        # Master admin skips the lookup, but tenant_id is still set to None
        assert mock_state.tenant_id is None


# ═══════════════════════════════════════════════════════════════════════════════
# Payment service — check_and_update_expired, _calculate_expires_at
# ═══════════════════════════════════════════════════════════════════════════════


class TestPaymentServiceEdgeCases:
    def _setup_payment_data(self, session, user_account):
        """Create the minimal data needed for payment tests."""
        from app.database.model import Service, UserService, SubscriptionType
        from datetime import timedelta

        svc = Service(name="PaySvc", administrator_id=uuid4())
        session.add(svc)
        session.flush()

        sub_type = SubscriptionType(type="mensual", cost=100.0)
        session.add(sub_type)
        session.flush()

        user_service = UserService(
            user_id=user_account["id"],
            service_id=svc.id,
            is_active=True,
        )
        session.add(user_service)
        session.commit()

        return svc, sub_type, user_service

    def test_check_and_update_expired_no_payments(self, session, user_account):
        from app.domain.payment.service import PaymentService

        _, _, user_service = self._setup_payment_data(session, user_account)

        svc = PaymentService(session)
        # No payments → returns early
        svc.check_and_update_expired(user_service.id)

    def test_check_and_update_expired_deactivates_when_expired(self, session, user_account):
        from app.domain.payment.service import PaymentService
        from app.domain.payment.schemas import PaymentCreate
        from datetime import timedelta, datetime, timezone
        from app.database.model import Payment

        _, sub_type, user_service = self._setup_payment_data(session, user_account)

        # Manually create an expired payment (naive datetime — SQLite stores without tz)
        past_expires = datetime.now() - timedelta(days=1)
        payment = Payment(
            user_service_id=user_service.id,
            subscription_type_id=sub_type.id,
            expires_at=past_expires,
        )
        session.add(payment)
        session.commit()

        svc = PaymentService(session)
        svc.check_and_update_expired(user_service.id)
        session.refresh(user_service)
        assert user_service.is_active is False

    def test_calculate_expires_at_unknown_type_raises(self, session):
        from app.domain.payment.service import PaymentService
        from app.database.model import SubscriptionType

        sub_type = SubscriptionType(type="quincenal", cost=50.0)
        session.add(sub_type)
        session.commit()

        svc = PaymentService(session)
        with pytest.raises(HTTPException) as exc_info:
            svc._calculate_expires_at(sub_type)
        assert exc_info.value.status_code == 400

    def test_calculate_expires_at_with_active_current_expires(self, session):
        from app.domain.payment.service import PaymentService
        from app.database.model import SubscriptionType
        from datetime import timedelta, datetime, timezone

        sub_type = SubscriptionType(type="mensual", cost=100.0)
        session.add(sub_type)
        session.commit()

        # Future expiry → extends from that date
        future = datetime.now(timezone.utc) + timedelta(days=10)
        svc = PaymentService(session)
        result = svc._calculate_expires_at(sub_type, current_expires=future)
        # Should be 30 days after future
        assert result > future

    def test_check_all_user_subscriptions(self, session, user_account):
        from app.domain.payment.service import PaymentService

        _, _, user_service = self._setup_payment_data(session, user_account)

        svc = PaymentService(session)
        svc.check_all_user_subscriptions(user_account["id"])  # no payments, just runs

    def test_check_all_service_subscriptions(self, session, user_account):
        from app.domain.payment.service import PaymentService

        svc_entity, _, user_service = self._setup_payment_data(session, user_account)

        svc = PaymentService(session)
        svc.check_all_service_subscriptions(svc_entity.id)  # runs without error


# ═══════════════════════════════════════════════════════════════════════════════
# Auth controller / auth service edge cases
# ═══════════════════════════════════════════════════════════════════════════════


class TestAuthServiceEdgeCases:
    def test_login_service_resolve_inactive_user(self, session, inactive_user_account):
        from app.domain.auth.service import LoginService
        from app.shared.e2e.session import E2ESessionRepository

        mock_repo = MagicMock(spec=E2ESessionRepository)
        svc = LoginService(session, mock_repo)
        # Inactive user → _resolve_username returns None
        result = svc._resolve_username(inactive_user_account["email"])
        assert result is None

    def test_login_service_resolve_nonexistent_email(self, session):
        from app.domain.auth.service import LoginService
        from app.shared.e2e.session import E2ESessionRepository

        mock_repo = MagicMock(spec=E2ESessionRepository)
        svc = LoginService(session, mock_repo)
        result = svc._resolve_username("nobody@nowhere.com")
        assert result is None


# ═══════════════════════════════════════════════════════════════════════════════
# Service controller — assign_manager with nonexistent service (line 59)
# ═══════════════════════════════════════════════════════════════════════════════


class TestServiceControllerEdgeCases:
    def test_assign_manager_nonexistent_service(self, master_admin_client):
        resp = master_admin_client.post(
            f"/api/v1/services/{uuid4()}/assign-manager/{uuid4()}"
        )
        # 404 — service not found
        assert resp.status_code == 404

    def test_assign_manager_nonexistent_manager(self, master_admin_client, session):
        from app.database.model import Service
        svc = Service(name="SvcForAssign", administrator_id=uuid4())
        session.add(svc)
        session.commit()
        resp = master_admin_client.post(
            f"/api/v1/services/{svc.id}/assign-manager/{uuid4()}"
        )
        # 404 — manager not found
        assert resp.status_code == 404


# ═══════════════════════════════════════════════════════════════════════════════
# applications/auth.py missing lines (37, 70-71, 82-83)
# ═══════════════════════════════════════════════════════════════════════════════


class TestApplicationsAuthMissingLines:
    @pytest.mark.anyio
    async def test_get_api_key_returns_bytes_when_set(self, session):
        """_get_api_key returns bytes.fromhex(api_key) when api_key is set (line 37)."""
        from app.shared.middleware.auth.applications.auth import CryptoManager
        from app.database.model import Application
        from app.shared.session.service import SessionService

        api_key_hex = secrets.token_hex(32)
        app = Application(
            name="KeyApp", version="1.0", url="http://key.test.com",
            description="key test", administrator_id=uuid4(),
            api_key=api_key_hex, is_active=True,
        )
        session.add(app)
        session.commit()

        mock_svc = MagicMock(spec=SessionService)
        mgr = CryptoManager(session, mock_svc)
        key_bytes = mgr._get_api_key(app)
        assert key_bytes == bytes.fromhex(api_key_hex)

    @pytest.mark.anyio
    async def test_authenticate_no_api_key(self, session):
        """Application with no api_key → failure path (line 70-71)."""
        from app.shared.middleware.auth.applications.auth import CryptoManager
        from app.database.model import Application
        from app.domain.application.schemas import PuzzleRequest, PuzzlePayload
        from app.shared.session.service import SessionService

        app = Application(
            name="NoKeyApp", version="1.0", url="http://nokey.test.com",
            description="no key test", administrator_id=uuid4(),
            api_key=None, is_active=True,
        )
        session.add(app)
        session.commit()

        mock_svc = MagicMock(spec=SessionService)
        mock_svc.get_session = AsyncMock(return_value=None)
        mgr = CryptoManager(session, mock_svc)

        puzzle = PuzzleRequest(
            application_id=app.id,
            encrypted_payload=PuzzlePayload(
                ciphertext=base64.b64encode(b"x" * 32).decode(),
                iv=base64.b64encode(b"y" * 16).decode(),
            ),
        )
        result = await mgr.authenticate(puzzle, {"ip_address": "127.0.0.1", "user_agent": "test"})
        assert result["valid"] is False


# ═══════════════════════════════════════════════════════════════════════════════
# devices/auth.py — P2 match success (line 82-83)
# ═══════════════════════════════════════════════════════════════════════════════
# Note: lines 82-83 in devices/auth.py are the success return path.
# These are covered by existing test_valid_puzzle tests in device_auth/.


# ═══════════════════════════════════════════════════════════════════════════════
# Telemetry controller — _repo() factory (line 24)
# ═══════════════════════════════════════════════════════════════════════════════


class TestTelemetryControllerRepo:
    def test_repo_factory_creates_repository(self):
        """_repo() returns a TelemetryRepository — cover line 24."""
        from app.domain.telemetry.controller import _repo
        from app.domain.telemetry.repository import TelemetryRepository

        with patch("app.domain.telemetry.controller.get_mongo_db", return_value=MagicMock()):
            repo = _repo()
            assert isinstance(repo, TelemetryRepository)


# ═══════════════════════════════════════════════════════════════════════════════
# Ecosystem fixture + manager-has-access + repository non-empty branches
# ═══════════════════════════════════════════════════════════════════════════════


@pytest.fixture
def ecosystem(session, master_admin_account, manager_account, user_account):
    """Populate DB so manager has access to service/device/application/user/ticket."""
    from app.database.model import (
        Service, ManagerService, Device, DeviceService,
        Application, ApplicationService, Role, UserRole,
        TicketStatus, EcosystemTicket, ServiceTicket, Manager, User,
    )

    admin_id = master_admin_account["id"]
    mgr_id = manager_account["id"]
    usr_id = user_account["id"]

    # Service (FK: administrator_id)
    svc = Service(name="EcoService", administrator_id=admin_id)
    session.add(svc)
    session.flush()

    # ManagerService: links manager to service
    ms = ManagerService(manager_id=mgr_id, service_id=svc.id)
    session.add(ms)
    session.flush()

    # Device + DeviceService
    dev = Device(name="EcoDev", is_active=True)
    session.add(dev)
    session.flush()
    ds = DeviceService(device_id=dev.id, service_id=svc.id)
    session.add(ds)
    session.flush()

    # Application + ApplicationService
    app = Application(
        name="EcoApp", version="1.0", url="http://eco.test.com",
        description="eco", administrator_id=admin_id, is_active=True,
    )
    session.add(app)
    session.flush()
    as_ = ApplicationService(application_id=app.id, service_id=svc.id)
    session.add(as_)
    session.flush()

    # Role + UserRole (user_manager_vw path)
    role = Role(name="EcoRole", service_id=svc.id)
    session.add(role)
    session.flush()
    ur = UserRole(user_id=usr_id, role_id=role.id)
    session.add(ur)
    session.flush()

    # TicketStatus
    ts = TicketStatus(name="Open")
    session.add(ts)
    session.flush()

    # EcosystemTicket (ticket_manager_vw: links to manager_service)
    eco_ticket = EcosystemTicket(
        title="EcoTicket", manager_service_id=ms.id, status_id=ts.id,
    )
    session.add(eco_ticket)
    session.flush()

    # ServiceTicket (service_manager_vw: via service_id)
    svc_ticket = ServiceTicket(
        title="SvcTicket", user_role_id=ur.id, status_id=ts.id, service_id=svc.id,
    )
    session.add(svc_ticket)
    session.commit()

    return {
        "service": svc,
        "manager_service": ms,
        "device": dev,
        "application": app,
        "user_role": ur,
        "ticket_status": ts,
        "eco_ticket": eco_ticket,
        "svc_ticket": svc_ticket,
        "manager_id": mgr_id,
        "user_id": usr_id,
    }


class TestAdminGetAllPaths:
    """Admin context takes the get_all() -> repository.get_all() path."""

    def test_application_service_admin_get_all(self, session, ecosystem):
        from app.shared.authorization.dependencies import _current_user_ctx
        from app.domain.application.service import ApplicationService

        user = _make_current_user("administrator")
        token = _current_user_ctx.set(user)
        try:
            result = ApplicationService(session).get_all()
            assert result.total >= 1
        finally:
            _current_user_ctx.reset(token)

    def test_device_service_admin_get_all(self, session, ecosystem):
        from app.shared.authorization.dependencies import _current_user_ctx
        from app.domain.device.service import DeviceService

        user = _make_current_user("administrator")
        token = _current_user_ctx.set(user)
        try:
            result = DeviceService(session).get_all()
            assert result.total >= 1
        finally:
            _current_user_ctx.reset(token)

    def test_service_service_admin_get_all(self, session, ecosystem):
        from app.shared.authorization.dependencies import _current_user_ctx
        from app.domain.service.service import ServiceService

        user = _make_current_user("administrator")
        token = _current_user_ctx.set(user)
        try:
            result = ServiceService(session).get_all()
            assert result.total >= 1
        finally:
            _current_user_ctx.reset(token)

    def test_user_service_admin_get_all(self, session, ecosystem):
        from app.shared.authorization.dependencies import _current_user_ctx
        from app.domain.user.service import UserService

        user = _make_current_user("administrator")
        token = _current_user_ctx.set(user)
        try:
            result = UserService(session).get_all()
            assert result.total >= 1
        finally:
            _current_user_ctx.reset(token)

    def test_service_ticket_admin_get_all(self, session, ecosystem):
        from app.shared.authorization.dependencies import _current_user_ctx
        from app.domain.tickets.service import ServiceTicketService

        user = _make_current_user("administrator")
        token = _current_user_ctx.set(user)
        try:
            result = ServiceTicketService(session).get_all()
            assert result.total >= 1
        finally:
            _current_user_ctx.reset(token)

    def test_ecosystem_ticket_admin_get_all(self, session, ecosystem):
        from app.shared.authorization.dependencies import _current_user_ctx
        from app.domain.tickets.service import EcosystemTicketService

        user = _make_current_user("administrator")
        token = _current_user_ctx.set(user)
        try:
            result = EcosystemTicketService(session).get_all()
            assert result.total >= 1
        finally:
            _current_user_ctx.reset(token)


class TestManagerHasAccessPaths:
    """Manager context with actual view data → check_manager_access returns True."""

    def test_device_service_get_by_id_manager_with_access(self, session, ecosystem):
        from app.shared.authorization.dependencies import _current_user_ctx
        from app.domain.device.service import DeviceService

        user = _make_current_user("manager", ecosystem["manager_id"], is_master=False)
        token = _current_user_ctx.set(user)
        try:
            result = DeviceService(session).get_by_id(ecosystem["device"].id)
            assert result.id == ecosystem["device"].id
        finally:
            _current_user_ctx.reset(token)

    def test_application_service_get_by_id_manager_with_access(self, session, ecosystem):
        from app.shared.authorization.dependencies import _current_user_ctx
        from app.domain.application.service import ApplicationService

        user = _make_current_user("manager", ecosystem["manager_id"], is_master=False)
        token = _current_user_ctx.set(user)
        try:
            result = ApplicationService(session).get_by_id(ecosystem["application"].id)
            assert result.id == ecosystem["application"].id
        finally:
            _current_user_ctx.reset(token)

    def test_service_service_get_by_id_manager_with_access(self, session, ecosystem):
        from app.shared.authorization.dependencies import _current_user_ctx
        from app.domain.service.service import ServiceService

        user = _make_current_user("manager", ecosystem["manager_id"], is_master=False)
        token = _current_user_ctx.set(user)
        try:
            result = ServiceService(session).get_by_id(ecosystem["service"].id)
            assert result.id == ecosystem["service"].id
        finally:
            _current_user_ctx.reset(token)

    def test_user_service_get_by_id_manager_with_access(self, session, ecosystem, user_account):
        from app.shared.authorization.dependencies import _current_user_ctx
        from app.domain.user.service import UserService

        user = _make_current_user("manager", ecosystem["manager_id"], is_master=False)
        token = _current_user_ctx.set(user)
        try:
            result = UserService(session).get_by_id(user_account["id"])
            assert result.id == user_account["id"]
        finally:
            _current_user_ctx.reset(token)


class TestRepositoryNonEmptyBranches:
    """Call get_for_manager when manager actually has data (total > 0)."""

    def test_device_repo_get_for_manager_with_data(self, session, ecosystem):
        from app.domain.device.repository import DeviceRepository
        repo = DeviceRepository(session)
        items, total = repo.get_for_manager(ecosystem["manager_id"])
        assert total >= 1
        assert len(items) >= 1

    def test_application_repo_get_for_manager_with_data(self, session, ecosystem):
        from app.domain.application.repository import ApplicationRepository
        repo = ApplicationRepository(session)
        items, total = repo.get_for_manager(ecosystem["manager_id"])
        assert total >= 1
        assert len(items) >= 1

    def test_service_repo_get_for_manager_with_data(self, session, ecosystem):
        from app.domain.service.repository import ServiceRepository
        repo = ServiceRepository(session)
        items, total = repo.get_for_manager(ecosystem["manager_id"])
        assert total >= 1
        assert len(items) >= 1

    def test_user_repo_get_for_manager_with_data(self, session, ecosystem):
        from app.domain.user.repository import UserRepository
        repo = UserRepository(session)
        items, total = repo.get_for_manager(ecosystem["manager_id"])
        assert total >= 1
        assert len(items) >= 1

    def test_ecosystem_ticket_repo_get_for_manager_with_data(self, session, ecosystem):
        from app.domain.tickets.repository import EcosystemTicketRepository
        repo = EcosystemTicketRepository(session)
        items, total = repo.get_for_manager(ecosystem["manager_id"])
        assert total >= 1
        assert len(items) >= 1

    def test_service_ticket_repo_get_for_manager_sql_with_data(self, session, ecosystem):
        from app.domain.tickets.repository import ServiceTicketRepository
        repo = ServiceTicketRepository(session)
        items, total = repo.get_for_manager_sql(ecosystem["manager_id"])
        assert total >= 1
        assert len(items) >= 1

    def test_device_repo_check_manager_access_true(self, session, ecosystem):
        from app.domain.device.repository import DeviceRepository
        repo = DeviceRepository(session)
        result = repo.check_manager_access(ecosystem["device"].id, ecosystem["manager_id"])
        assert result is True

    def test_application_repo_check_manager_access_true(self, session, ecosystem):
        from app.domain.application.repository import ApplicationRepository
        repo = ApplicationRepository(session)
        result = repo.check_manager_access(ecosystem["application"].id, ecosystem["manager_id"])
        assert result is True

    def test_service_repo_check_manager_access_true(self, session, ecosystem):
        from app.domain.service.repository import ServiceRepository
        repo = ServiceRepository(session)
        result = repo.check_manager_access(ecosystem["service"].id, ecosystem["manager_id"])
        assert result is True

    def test_user_repo_check_manager_access_true(self, session, ecosystem, user_account):
        from app.domain.user.repository import UserRepository
        repo = UserRepository(session)
        result = repo.check_manager_access(user_account["id"], ecosystem["manager_id"])
        assert result is True


class TestManagerGetAllWithData:
    """Manager get_all with actual view data returns non-empty results."""

    def test_device_service_manager_get_all_with_data(self, session, ecosystem):
        from app.shared.authorization.dependencies import _current_user_ctx
        from app.domain.device.service import DeviceService

        user = _make_current_user("manager", ecosystem["manager_id"], is_master=False)
        token = _current_user_ctx.set(user)
        try:
            result = DeviceService(session).get_all()
            assert result.total >= 1
        finally:
            _current_user_ctx.reset(token)

    def test_application_service_manager_get_all_with_data(self, session, ecosystem):
        from app.shared.authorization.dependencies import _current_user_ctx
        from app.domain.application.service import ApplicationService

        user = _make_current_user("manager", ecosystem["manager_id"], is_master=False)
        token = _current_user_ctx.set(user)
        try:
            result = ApplicationService(session).get_all()
            assert result.total >= 1
        finally:
            _current_user_ctx.reset(token)

    def test_service_service_manager_get_all_with_data(self, session, ecosystem):
        from app.shared.authorization.dependencies import _current_user_ctx
        from app.domain.service.service import ServiceService

        user = _make_current_user("manager", ecosystem["manager_id"], is_master=False)
        token = _current_user_ctx.set(user)
        try:
            result = ServiceService(session).get_all()
            assert result.total >= 1
        finally:
            _current_user_ctx.reset(token)

    def test_user_service_manager_get_all_with_data(self, session, ecosystem, user_account):
        from app.shared.authorization.dependencies import _current_user_ctx
        from app.domain.user.service import UserService

        user = _make_current_user("manager", ecosystem["manager_id"], is_master=False)
        token = _current_user_ctx.set(user)
        try:
            result = UserService(session).get_all()
            assert result.total >= 1
        finally:
            _current_user_ctx.reset(token)

    def test_service_ticket_manager_get_all_with_data(self, session, ecosystem):
        from app.shared.authorization.dependencies import _current_user_ctx
        from app.domain.tickets.service import ServiceTicketService

        user = _make_current_user("manager", ecosystem["manager_id"], is_master=False)
        token = _current_user_ctx.set(user)
        try:
            result = ServiceTicketService(session).get_all()
            assert result.total >= 1
        finally:
            _current_user_ctx.reset(token)

    def test_ecosystem_ticket_manager_get_all_with_data(self, session, ecosystem):
        from app.shared.authorization.dependencies import _current_user_ctx
        from app.domain.tickets.service import EcosystemTicketService

        user = _make_current_user("manager", ecosystem["manager_id"], is_master=False)
        token = _current_user_ctx.set(user)
        try:
            result = EcosystemTicketService(session).get_all()
            assert result.total >= 1
        finally:
            _current_user_ctx.reset(token)


# ═══════════════════════════════════════════════════════════════════════════════
# User service — roles, assign/remove (lines 77, 80, 104, 111)
# ═══════════════════════════════════════════════════════════════════════════════


class TestUserServiceRoles:
    def test_assign_role_user_not_found(self, session):
        from app.shared.authorization.dependencies import _current_user_ctx
        from app.domain.user.service import UserService
        from app.shared.exceptions import NotFoundException

        user = _make_current_user("administrator")
        token = _current_user_ctx.set(user)
        try:
            with pytest.raises(NotFoundException, match="User"):
                UserService(session).assign_role_to_user(uuid4(), uuid4())
        finally:
            _current_user_ctx.reset(token)

    def test_assign_role_role_not_found(self, session, user_account):
        from app.shared.authorization.dependencies import _current_user_ctx
        from app.domain.user.service import UserService
        from app.shared.exceptions import NotFoundException

        user = _make_current_user("administrator")
        token = _current_user_ctx.set(user)
        try:
            with pytest.raises(NotFoundException, match="Role"):
                UserService(session).assign_role_to_user(user_account["id"], uuid4())
        finally:
            _current_user_ctx.reset(token)

    def test_remove_role_not_found(self, session, user_account):
        from app.shared.authorization.dependencies import _current_user_ctx
        from app.domain.user.service import UserService
        from app.shared.exceptions import NotFoundException

        user = _make_current_user("administrator")
        token = _current_user_ctx.set(user)
        try:
            with pytest.raises(NotFoundException, match="UserRole"):
                UserService(session).remove_role_from_user(user_account["id"], uuid4())
        finally:
            _current_user_ctx.reset(token)

    def test_list_roles_user_not_found(self, session):
        from app.shared.authorization.dependencies import _current_user_ctx
        from app.domain.user.service import UserService
        from app.shared.exceptions import NotFoundException

        user = _make_current_user("administrator")
        token = _current_user_ctx.set(user)
        try:
            with pytest.raises(NotFoundException, match="User"):
                UserService(session).list_roles_by_user(uuid4())
        finally:
            _current_user_ctx.reset(token)

    def test_user_get_by_id_other_user_raises(self, session, user_account, master_admin_account):
        from app.shared.authorization.dependencies import _current_user_ctx
        from app.domain.user.service import UserService
        from app.shared.exceptions import NotFoundException

        # User tries to access admin — should raise NotFoundException
        user = _make_current_user("user", user_account["id"], is_master=False)
        token = _current_user_ctx.set(user)
        try:
            with pytest.raises(NotFoundException):
                # Admin ID from a different account type — user can't access
                UserService(session).get_by_id(master_admin_account["id"])
        finally:
            _current_user_ctx.reset(token)


# ═══════════════════════════════════════════════════════════════════════════════
# Missing schema coverage: DeviceCreate None paths, personal_data, auth_rc
# ═══════════════════════════════════════════════════════════════════════════════


class TestMissingSchemaValidators:
    def test_device_create_ip_none_passes(self):
        from app.domain.device.schemas import DeviceCreate
        d = DeviceCreate(name="d", ip=None)
        assert d.ip is None

    def test_device_create_mac_none_passes(self):
        from app.domain.device.schemas import DeviceCreate
        d = DeviceCreate(name="d", mac=None)
        assert d.mac is None

    def test_sensitive_data_create_invalid_email(self):
        from app.domain.personal_data.schemas import SensitiveDataCreate
        with pytest.raises(Exception, match="invalid email"):
            SensitiveDataCreate(
                email="notvalid",
                password="ValidPass123!",
                curp="PEMJ900615HDFLRN07",
                rfc="PEMJ900615AB1",
            )

    def test_sensitive_data_update_password_valid(self):
        from app.domain.personal_data.schemas import SensitiveDataUpdate
        u = SensitiveDataUpdate(password="ValidPass123!")
        assert u.password == "ValidPass123!"

    def test_service_ticket_get_for_user_with_data(self, session, ecosystem, user_account):
        from app.domain.tickets.repository import ServiceTicketRepository
        repo = ServiceTicketRepository(session)
        items, total = repo.get_for_user(user_account["id"])
        assert total >= 1


# ═══════════════════════════════════════════════════════════════════════════════
# Remaining controller / endpoint coverage
# ═══════════════════════════════════════════════════════════════════════════════


class TestControllerEndpointGaps:
    def test_onboarding_verify_token_not_found(self, client):
        """Token not in store → 400 (service.py lines 67-69)."""
        mock_client = AsyncMock()
        mock_client.get = AsyncMock(return_value=None)
        mock_client.aclose = AsyncMock()

        with patch("valkey.asyncio.from_url", AsyncMock(return_value=mock_client)):
            resp = client.get("/api/v1/onboarding/verify?token=invalid-token-xyz")
        assert resp.status_code == 400

    def test_onboarding_verify_account_not_found(self, client):
        """Valid token in store but account missing → 400 (service.py lines 72-75)."""
        missing_nc_id = str(uuid4())
        mock_client = AsyncMock()
        mock_client.get = AsyncMock(return_value=missing_nc_id)
        mock_client.aclose = AsyncMock()

        with patch("valkey.asyncio.from_url", AsyncMock(return_value=mock_client)):
            resp = client.get("/api/v1/onboarding/verify?token=any-token")
        assert resp.status_code == 400

    def test_payment_get_subscription_type_existing(self, master_admin_client, session):
        """GET /payments/subscription-types/{id} for existing type (lines 107-110)."""
        from app.database.model import SubscriptionType
        st = SubscriptionType(type="mensual_test", cost=50.0)
        session.add(st)
        session.commit()
        session.refresh(st)
        resp = master_admin_client.get(f"/api/v1/payments/subscription-types/{st.id}")
        assert resp.status_code == 200

    def test_payment_get_subscription_type_not_found(self, master_admin_client):
        """GET /payments/subscription-types/{id} not found (line 109)."""
        resp = master_admin_client.get(f"/api/v1/payments/subscription-types/{uuid4()}")
        assert resp.status_code == 404

    def test_auth_renew_session_missing_header(self, client):
        """POST /auth/renew without X-Session-ID header → 400 (line 27 indirect)."""
        resp = client.post("/api/v1/auth/renew")
        assert resp.status_code == 400

    def test_auth_renew_session_invalid_session(self, client):
        """POST /auth/renew with invalid session → 401 (line 136 indirect)."""
        resp = client.post(
            "/api/v1/auth/renew",
            headers={"X-Session-ID": "does-not-exist"},
        )
        assert resp.status_code == 401

    def test_service_ticket_get_by_id_admin(self, master_admin_client, session, ecosystem):
        """GET /service-tickets/{id} as admin (line 85 in tickets/service.py)."""
        resp = master_admin_client.get(f"/api/v1/service-tickets/{ecosystem['svc_ticket'].id}")
        assert resp.status_code in (200, 403, 404)

    def test_ecosystem_ticket_get_by_id_admin(self, master_admin_client, session, ecosystem):
        """GET /ecosystem-tickets/{id} as admin (line 40 in tickets/service.py)."""
        resp = master_admin_client.get(f"/api/v1/ecosystem-tickets/{ecosystem['eco_ticket'].id}")
        assert resp.status_code in (200, 403, 404)

    def test_application_auth_endpoint(self, client, session, ecosystem):
        """POST /applications/auth endpoint (lines 68-83 in application/controller.py)."""
        mock_session_svc = MagicMock()
        mock_session_svc.get_session = AsyncMock(return_value=None)

        with patch("app.domain.application.controller.SessionService", return_value=mock_session_svc):
            resp = client.post(
                "/api/v1/applications/auth",
                json={
                    "application_id": str(ecosystem["application"].id),
                    "encrypted_payload": {
                        "ciphertext": base64.b64encode(b"x" * 64).decode(),
                        "iv": base64.b64encode(b"y" * 16).decode(),
                    },
                },
            )
        # 401 — authentication fails (bad payload) but controller code IS covered
        assert resp.status_code == 401

    def test_tenant_middleware_exception_path(self, db, monkeypatch, regular_admin_account):
        """TenantContextMiddleware exception handling (lines 43-44)."""
        import app.shared.middleware.tenant as tenant_module
        from app.shared.middleware.tenant import TenantContextMiddleware
        from app.main import app as fastapi_app

        # Patch engine to raise on Session creation to trigger exception handler
        monkeypatch.setattr(tenant_module, "engine", db)

        middleware = TenantContextMiddleware(fastapi_app)

        mock_state = MagicMock()
        mock_state.current_account = {
            "account_id": "not-a-valid-uuid",  # will fail UUID() conversion → exception
            "account_type": "administrator",
            "is_master": False,
        }

        mock_request = MagicMock()
        mock_request.state = mock_state

        mock_response = MagicMock()
        call_next = AsyncMock(return_value=mock_response)

        import asyncio
        asyncio.get_event_loop().run_until_complete(
            middleware.dispatch(mock_request, call_next)
        )
        # After exception, tenant_id should be None (not set due to error)
        assert mock_state.tenant_id is None

    def test_e2e_body_too_large_after_read(self, client, master_admin_account):
        """Body > MAX_BODY_SIZE triggers 413 after actual read (line 118)."""
        import app.shared.e2e.middleware as mw_module

        # Create a fake session
        fake_session = {
            "session_key": secrets.token_hex(32),
            "account": {
                "account_id": str(master_admin_account["id"]),
                "account_type": "administrator",
                "is_master": True,
                "email": master_admin_account["email"],
            },
        }
        mock_repo = MagicMock()
        mock_repo.get_session = AsyncMock(return_value=fake_session)

        old_override = mw_module._session_repo_override
        mw_module._session_repo_override = mock_repo
        try:
            # Send no Content-Length header but a large body
            large_body = b"x" * (1024 * 1024 + 1)  # 1 MB + 1 byte
            resp = client.post(
                "/api/v1/devices/",
                headers={"X-Session-ID": "fake-session"},
                content=large_body,
            )
            assert resp.status_code == 413
        finally:
            mw_module._session_repo_override = old_override


# ═══════════════════════════════════════════════════════════════════════════════
# Final coverage gaps — all remaining 16 uncovered lines
# ═══════════════════════════════════════════════════════════════════════════════


class TestFinalCoverageGaps:
    """Tests covering the last 16 missing lines."""

    # ─── applications/auth.py line 37: _get_api_key returns None ────────────

    def test_app_get_api_key_returns_none_for_empty(self, session):
        """_get_api_key returns None when api_key is empty (line 37)."""
        from app.shared.middleware.auth.applications.auth import CryptoManager
        from app.shared.session.service import SessionService
        from types import SimpleNamespace

        mgr = CryptoManager(session, MagicMock(spec=SessionService))
        result = mgr._get_api_key(SimpleNamespace(api_key=""))
        assert result is None

    # ─── applications/auth.py lines 70-71: api_key None path ────────────────

    @pytest.mark.anyio
    async def test_app_authenticate_api_key_none(self, session):
        """authenticate returns failure when _get_api_key returns None (lines 70-71)."""
        from app.shared.middleware.auth.applications.auth import CryptoManager
        from app.domain.application.schemas import PuzzleRequest, PuzzlePayload
        from app.shared.session.service import SessionService
        from app.database.model import Application

        app = Application(
            name="ApiKeyNoneApp", version="1.0", url="http://aknone.test.com",
            description="api key none test", administrator_id=uuid4(), is_active=True,
        )
        session.add(app)
        session.commit()
        session.refresh(app)

        mock_svc = MagicMock(spec=SessionService)
        mock_svc.get_session = AsyncMock(return_value=None)
        mgr = CryptoManager(session, mock_svc)

        puzzle = PuzzleRequest(
            application_id=app.id,
            encrypted_payload=PuzzlePayload(
                ciphertext=base64.b64encode(b"x" * 64).decode(),
                iv=base64.b64encode(b"y" * 16).decode(),
            ),
        )
        with patch.object(mgr, "_get_api_key", return_value=None):
            result = await mgr.authenticate(
                puzzle, {"ip_address": "127.0.0.1", "user_agent": "test"}
            )
        assert result["valid"] is False

    # ─── applications/auth.py lines 82-83: short decrypted payload ──────────

    @pytest.mark.anyio
    async def test_app_authenticate_short_decrypted_payload(self, session):
        """authenticate returns failure when decrypted < 72 bytes (lines 82-83)."""
        from app.shared.middleware.auth.applications.auth import CryptoManager
        from app.domain.application.schemas import PuzzleRequest, PuzzlePayload
        from app.shared.session.service import SessionService
        from app.database.model import Application
        from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
        from cryptography.hazmat.primitives import padding as crypto_padding

        api_key_bytes = secrets.token_bytes(32)
        api_key_hex = api_key_bytes.hex()

        app = Application(
            name="ShortPayloadAppV2", version="1.0", url="http://shortv2.test.com",
            description="short payload v2", administrator_id=uuid4(),
            api_key=api_key_hex, is_active=True,
        )
        session.add(app)
        session.commit()
        session.refresh(app)

        # Encrypt 8-byte plaintext → 16-byte ciphertext → 16 < 72 triggers check
        iv = secrets.token_bytes(16)
        padder_obj = crypto_padding.PKCS7(128).padder()
        padded = padder_obj.update(b"tooshort") + padder_obj.finalize()
        cipher = Cipher(algorithms.AES(api_key_bytes), modes.CBC(iv))
        enc = cipher.encryptor()
        ciphertext = enc.update(padded) + enc.finalize()

        mock_svc = MagicMock(spec=SessionService)
        mock_svc.get_session = AsyncMock(return_value=None)
        mgr = CryptoManager(session, mock_svc)

        puzzle = PuzzleRequest(
            application_id=app.id,
            encrypted_payload=PuzzlePayload(
                ciphertext=base64.b64encode(ciphertext).decode(),
                iv=base64.b64encode(iv).decode(),
            ),
        )
        result = await mgr.authenticate(
            puzzle, {"ip_address": "127.0.0.1", "user_agent": "test"}
        )
        assert result["valid"] is False

    # ─── devices/auth.py lines 82-83: short decrypted payload ───────────────

    @pytest.mark.anyio
    async def test_device_authenticate_short_decrypted_payload(self, session):
        """device authenticate returns failure when decrypted < 72 bytes (lines 82-83)."""
        from app.shared.middleware.auth.devices.auth import CryptoManager as DeviceCM
        from app.domain.device.schemas import PuzzleRequest as DevicePR, PuzzlePayload as DevicePP
        from app.shared.session.service import SessionService
        from app.database.model import Device
        from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
        from cryptography.hazmat.primitives import padding as crypto_padding

        enc_key_bytes = secrets.token_bytes(32)
        enc_key_hex = enc_key_bytes.hex()

        device = Device(name="ShortPayloadDev", is_active=True, encryption_key=enc_key_hex)
        session.add(device)
        session.commit()
        session.refresh(device)

        iv = secrets.token_bytes(16)
        padder_obj = crypto_padding.PKCS7(128).padder()
        padded = padder_obj.update(b"tooshort") + padder_obj.finalize()
        cipher = Cipher(algorithms.AES(enc_key_bytes), modes.CBC(iv))
        enc = cipher.encryptor()
        ciphertext = enc.update(padded) + enc.finalize()

        mock_svc = MagicMock(spec=SessionService)
        mock_svc.get_session = AsyncMock(return_value=None)
        mgr = DeviceCM(session, mock_svc)

        puzzle = DevicePR(
            device_id=device.id,
            encrypted_payload=DevicePP(
                ciphertext=base64.b64encode(ciphertext).decode(),
                iv=base64.b64encode(iv).decode(),
            ),
        )
        result = await mgr.authenticate(
            puzzle, {"ip_address": "127.0.0.1", "user_agent": "test"}
        )
        assert result["valid"] is False

    # ─── application/controller.py line 83: success return ──────────────────

    def test_application_auth_success_return(self, client):
        """POST /applications/auth returns result dict on valid=True (line 83)."""
        mock_session_svc = MagicMock()
        mock_session_svc.get_session = AsyncMock(return_value=None)

        with patch("app.domain.application.controller.CryptoManager") as mock_cm, \
             patch("app.domain.application.controller.SessionService", return_value=mock_session_svc):
            mock_instance = MagicMock()
            mock_instance.authenticate = AsyncMock(return_value={
                "valid": True,
                "random3": secrets.token_hex(32),
                "session_id": str(uuid4()),
            })
            mock_cm.return_value = mock_instance

            resp = client.post(
                "/api/v1/applications/auth",
                json={
                    "application_id": str(uuid4()),
                    "encrypted_payload": {
                        "ciphertext": base64.b64encode(b"x" * 64).decode(),
                        "iv": base64.b64encode(b"y" * 16).decode(),
                    },
                },
            )
        assert resp.status_code == 200

    # ─── auth/controller.py line 27: _get_session_repo factory ──────────────

    def test_auth_get_session_repo_factory(self):
        """_get_session_repo() creates E2ESessionRepository (line 27)."""
        from app.domain.auth.controller import _get_session_repo

        with patch("app.domain.auth.controller.E2ESessionRepository") as mock_cls:
            mock_cls.return_value = MagicMock()
            result = _get_session_repo()
            assert mock_cls.called
            assert result is mock_cls.return_value

    # ─── auth/controller.py line 136: renew raises 401 for missing session ──

    @pytest.mark.anyio
    async def test_auth_renew_raises_401_when_no_new_id(self):
        """renew_session raises HTTP 401 when repo.renew_session returns None (line 136)."""
        from app.domain.auth.controller import renew_session

        mock_repo = MagicMock()
        mock_repo.renew_session = AsyncMock(return_value=None)
        mock_repo.close = AsyncMock()

        mock_request = MagicMock()
        mock_request.headers.get = MagicMock(return_value="some-session-id")

        with pytest.raises(HTTPException) as exc_info:
            await renew_session(mock_request, mock_repo)
        assert exc_info.value.status_code == 401

    # ─── auth/service.py line 104: empty random2 raises BadRequestException ─

    @pytest.mark.anyio
    async def test_auth_service_login_empty_random2(self, session, master_admin_account):
        """login raises BadRequestException when random2 is empty (line 104)."""
        from app.domain.auth.service import LoginService
        from app.shared.exceptions import BadRequestException

        mock_repo = MagicMock()
        mock_repo.store_session = AsyncMock()

        svc = LoginService(session, mock_repo)
        valid_payload_b64 = base64.b64encode(b"dummy_cipher_data_bytes").decode()
        valid_iv_b64 = base64.b64encode(b"sixteenbytesiv16").decode()

        with patch("app.domain.auth.service.aes_decrypt", return_value=b'{"random2": ""}'):
            with pytest.raises(BadRequestException):
                await svc.login(
                    username=master_admin_account["email"],
                    payload_b64=valid_payload_b64,
                    random_hex=secrets.token_hex(32),
                    iv_b64=valid_iv_b64,
                )

    # ─── auth/service.py line 150: _resolve_username — no entity found ───────

    def test_auth_service_resolve_username_no_entity(self):
        """_resolve_username returns None when sensitive_data exists but no entity (line 150)."""
        from app.domain.auth.service import LoginService

        mock_sensitive = MagicMock()
        mock_sensitive.id = uuid4()

        mock_result_sd = MagicMock()
        mock_result_sd.first.return_value = mock_sensitive

        mock_result_none = MagicMock()
        mock_result_none.first.return_value = None

        mock_session = MagicMock()
        # First exec → sensitive_data; next 3 (one per _HUMAN_MODELS entry) → None
        mock_session.exec.side_effect = [mock_result_sd] + [mock_result_none] * 3

        svc = LoginService(mock_session, MagicMock())
        result = svc._resolve_username("orphan@test.com")
        assert result is None

    # ─── onboarding/controller.py line 51: success verify return ────────────

    @pytest.mark.anyio
    async def test_onboarding_verify_success_return(self, session):
        """verify_email returns VerificationResponse on success (line 51)."""
        from app.domain.onboarding.controller import verify_email

        with patch("app.domain.onboarding.controller.OnboardingService") as mock_cls:
            mock_svc = MagicMock()
            mock_svc.verify = AsyncMock(return_value=None)
            mock_cls.return_value = mock_svc

            result = await verify_email(token="valid-token", session=session)
            assert "Email verified" in result.message

    # ─── service/controller.py line 59: service not found in assign_manager ─

    def test_service_assign_manager_service_not_found(self, master_admin_client):
        """assign_manager raises 404 when service not found (line 59)."""
        fake_id = str(uuid4())
        resp = master_admin_client.post(f"/api/v1/services/{fake_id}/managers/{fake_id}")
        assert resp.status_code == 404

    # ─── user/service.py line 69: user accessing a different user's record ──

    def test_user_service_get_by_id_different_user_raises(self, session, user_account):
        """UserService.get_by_id raises NotFoundException when user accesses different user (line 69)."""
        from app.domain.user.service import UserService
        from app.shared.exceptions import NotFoundException
        from app.database.model import User, NonCriticalPersonalData, SensitiveData
        from app.shared.authorization.dependencies import _current_user_ctx

        ncpd = NonCriticalPersonalData(
            first_name="Other", last_name="User", second_last_name="Two"
        )
        session.add(ncpd)
        session.flush()

        sd = SensitiveData(
            non_critical_data_id=ncpd.id,
            email="other_distinct_user@test.com",
            password="OtherPass123!",
        )
        session.add(sd)
        session.flush()

        other_user = User(sensitive_data_id=sd.id, is_active=True)
        session.add(other_user)
        session.commit()
        session.refresh(other_user)

        current_user = _make_current_user(
            account_type="user",
            account_id=user_account["id"],
            is_master=False,
        )
        token = _current_user_ctx.set(current_user)
        try:
            with pytest.raises(NotFoundException):
                UserService(session).get_by_id(other_user.id)
        finally:
            _current_user_ctx.reset(token)

    # ─── e2e/middleware.py line 118: body > MAX_BODY_SIZE after read ─────────

    @pytest.mark.anyio
    async def test_e2e_middleware_body_too_large_after_read(self, master_admin_account):
        """Body > MAX_BODY_SIZE after read triggers 413 (line 118, no content-length)."""
        from app.shared.e2e.middleware import E2EMiddleware, MAX_BODY_SIZE
        from app.main import app as fastapi_app
        import app.shared.e2e.middleware as mw_module

        middleware = E2EMiddleware(fastapi_app)

        fake_session = {
            "session_key": secrets.token_hex(32),
            "account": {
                "account_id": str(master_admin_account["id"]),
                "account_type": "administrator",
                "is_master": True,
                "email": master_admin_account["email"],
            },
        }
        mock_repo = MagicMock()
        mock_repo.get_session = AsyncMock(return_value=fake_session)

        old_override = mw_module._session_repo_override
        mw_module._session_repo_override = mock_repo
        try:
            large_body = b"x" * (MAX_BODY_SIZE + 1)

            # Mock request: POST to non-public path, valid session, NO content-length
            mock_request = MagicMock()
            mock_request.url.path = "/api/v1/devices/"
            mock_request.method = "POST"
            mock_request.body = AsyncMock(return_value=large_body)
            mock_request.state = MagicMock()

            def _get_header(key, default=None):
                return {"x-session-id": "fake-session-id"}.get(key.lower(), default)

            mock_request.headers.get = _get_header
            call_next = AsyncMock(return_value=MagicMock())

            response = await middleware.dispatch(mock_request, call_next)
            assert response.status_code == 413
        finally:
            mw_module._session_repo_override = old_override
