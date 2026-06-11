
"""Tests para AuthManager — flujo de autenticación."""
import base64
import pytest
from dataclasses import dataclass, field
from unittest.mock import AsyncMock, MagicMock
from uuid import UUID, uuid4

from app.shared.middleware.auth.auth_manager.application import ApplicationAuthManager
from app.shared.middleware.auth.auth_manager.device import DeviceAuthManager
from app.shared.middleware.auth.auth_manager.human import HumanAuthManager
from app.shared.middleware.auth.auth_manager.manager import AuthManager


# ── Fakes ───────────────────────────────────────────────────────────

FAKE_ID = uuid4()


@dataclass
class FakeEntity:
    id: UUID = field(default_factory=lambda: FAKE_ID)
    is_active: bool = True
    name: str = "Fake Entity"


class FakeRepository:
    _entity_to_return = None  # clase controla qué retorna

    def __init__(self, session):
        pass

    def get_by_id(self, entity_id):
        entity = FakeRepository._entity_to_return
        if entity and str(entity.id) == str(entity_id):
            return entity
        return None


class FakeAuthSuccess:
    def authenticate(self, entity, request_data) -> dict:
        return {"valid": True}

    def get_auth_type(self) -> str:
        return "fake_success"


class FakeAuthFail:
    def authenticate(self, entity, request_data) -> dict:
        return {"valid": False, "error": "Authentication failed"}

    def get_auth_type(self) -> str:
        return "fake_fail"


class FakeRequest:
    def __init__(self, entity_id: UUID = FAKE_ID):
        self.entity_id = entity_id


class StubAuthManager(AuthManager[FakeEntity]):
    repository_class = FakeRepository
    _auth_methods = {
        "success": FakeAuthSuccess,
        "fail": FakeAuthFail,
    }

    def _get_entity_id(self, request_data) -> UUID:
        return request_data.entity_id


class StubHumanAuthManager(HumanAuthManager[FakeEntity]):
    repository_class = FakeRepository

    def _get_entity_id(self, request_data) -> UUID:
        return request_data.entity_id


# ── Fixtures ────────────────────────────────────────────────────────

@pytest.fixture
def mock_session_service():
    service = AsyncMock()
    service.get_session.return_value = None
    service.create_entity_session.return_value = MagicMock(
        session_id="test-session-id",
        encrypted_token="test-encrypted-token")
    return service


@pytest.fixture
def active_entity():
    return FakeEntity(id=FAKE_ID, is_active=True)


@pytest.fixture
def inactive_entity():
    return FakeEntity(id=FAKE_ID, is_active=False)


@pytest.fixture
def request_info():
    return {"ip_address": "127.0.0.1", "user_agent": "test-agent"}


@pytest.fixture(autouse=True)
def reset_repository():
    """Limpiar estado del repository entre tests."""
    FakeRepository._entity_to_return = None
    yield
    FakeRepository._entity_to_return = None


# ── Tests: flujo exitoso ────────────────────────────────────────────

class TestAuthManagerSuccess:

    @pytest.mark.asyncio
    async def test_valid_auth_returns_valid(self, mock_session_service, active_entity, request_info):
        FakeRepository._entity_to_return = active_entity
        manager = StubAuthManager(None, mock_session_service, auth_type="success")
        result = await manager.authenticate(FakeRequest(), request_info)
        assert result["valid"] is True
        assert "session_id" in result
        assert "key_session" in result

    @pytest.mark.asyncio
    async def test_session_key_is_base64_32_bytes(self, mock_session_service, active_entity, request_info):
        FakeRepository._entity_to_return = active_entity
        manager = StubAuthManager(None, mock_session_service, auth_type="success")
        result = await manager.authenticate(FakeRequest(), request_info)
        key_bytes = base64.urlsafe_b64decode(result["key_session"])
        assert len(key_bytes) == 32

    @pytest.mark.asyncio
    async def test_create_session_called_with_ip_and_user_agent(self, mock_session_service, active_entity, request_info):
        FakeRepository._entity_to_return = active_entity
        manager = StubAuthManager(None, mock_session_service, auth_type="success")
        await manager.authenticate(FakeRequest(), request_info)
        mock_session_service.create_entity_session.assert_called_once()
        call_kwargs = mock_session_service.create_entity_session.call_args[1]
        assert call_kwargs["entity_id"] == str(FAKE_ID)
        assert call_kwargs["ip"] == "127.0.0.1"
        assert call_kwargs["user_agent"] == "test-agent"
        assert "key_session" in call_kwargs


# ── Tests: entidad no encontrada ────────────────────────────────────

class TestAuthManagerEntityNotFound:

    @pytest.mark.asyncio
    async def test_nonexistent_entity_fails(self, mock_session_service, request_info):
        FakeRepository._entity_to_return = None
        manager = StubAuthManager(None, mock_session_service, auth_type="success")
        result = await manager.authenticate(FakeRequest(entity_id=uuid4()), request_info)
        assert result["valid"] is False
        assert result["error"] == "Authentication failed"


# ── Tests: entidad inactiva ─────────────────────────────────────────

class TestAuthManagerEntityInactive:

    @pytest.mark.asyncio
    async def test_inactive_entity_fails(self, mock_session_service, inactive_entity, request_info):
        FakeRepository._entity_to_return = inactive_entity
        manager = StubAuthManager(None, mock_session_service, auth_type="success")
        result = await manager.authenticate(FakeRequest(), request_info)
        assert result["valid"] is False
        assert result["error"] == "Authentication failed"


# ── Tests: sesión activa ────────────────────────────────────────────

class TestAuthManagerSessionActive:

    @pytest.mark.asyncio
    async def test_active_session_fails(self, mock_session_service, active_entity, request_info):
        mock_session_service.get_session.return_value = MagicMock()
        FakeRepository._entity_to_return = active_entity
        manager = StubAuthManager(None, mock_session_service, auth_type="success")
        result = await manager.authenticate(FakeRequest(), request_info)
        assert result["valid"] is False
        assert result["error"] == "Authentication failed"


# ── Tests: autenticación falla ──────────────────────────────────────

class TestAuthManagerAuthFails:

    @pytest.mark.asyncio
    async def test_auth_method_fails(self, mock_session_service, active_entity, request_info):
        FakeRepository._entity_to_return = active_entity
        manager = StubAuthManager(None, mock_session_service, auth_type="fail")
        result = await manager.authenticate(FakeRequest(), request_info)
        assert result["valid"] is False
        assert result["error"] == "Authentication failed"


# ── Tests: tipo inválido ────────────────────────────────────────────

class TestAuthManagerInvalidType:

    def test_invalid_auth_type_raises(self, mock_session_service):
        with pytest.raises(ValueError, match="no disponible"):
            StubAuthManager(None, mock_session_service, auth_type="xyz")

    def test_canonical_auth_rc_alias_resolves(self, mock_session_service):
        manager = StubHumanAuthManager(None, mock_session_service, auth_type="auth_rc")
        assert manager._authenticator.get_auth_type() == "auth_rc"

    def test_canonical_auth_xmss_alias_resolves(self, mock_session_service):
        manager = StubHumanAuthManager(None, mock_session_service, auth_type="auth_xmss")
        assert manager._authenticator.get_auth_type() == "auth_xmss"

    def test_device_manager_registers_xmss(self, mock_session_service):
        manager = DeviceAuthManager(None, mock_session_service, auth_type="auth_xmss")
        assert manager._authenticator.get_auth_type() == "auth_xmss"

    def test_application_manager_registers_xmss(self, mock_session_service):
        manager = ApplicationAuthManager(None, mock_session_service, auth_type="auth_xmss")
        assert manager._authenticator.get_auth_type() == "auth_xmss"


# ── Tests: llave de sesión ──────────────────────────────────────────

class TestAuthManagerSessionKey:

    def test_session_key_is_32_bytes(self):
        manager = StubAuthManager.__new__(StubAuthManager)
        key = manager._generate_session_key()
        assert isinstance(key, bytes)
        assert len(key) == 32

    def test_session_keys_are_unique(self):
        manager = StubAuthManager.__new__(StubAuthManager)
        assert manager._generate_session_key() != manager._generate_session_key()
