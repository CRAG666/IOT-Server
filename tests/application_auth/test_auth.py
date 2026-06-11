"""Tests para autenticación de applications por puzzle criptográfico."""
import hashlib
import hmac
import os
import secrets
import time
import pytest
from base64 import b64encode
from unittest.mock import AsyncMock, MagicMock

from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import padding

from app.config import settings
from app.database.model import Application, Administrator


# ── Helpers: simular lo que haría la application ────────────────────

def get_server_key():
    return hashlib.sha256(
        (settings.SECRET_KEY + "|puzzle_v1").encode("utf-8")
    ).digest()


def encrypt_aes(plaintext: bytes, key: bytes) -> tuple[bytes, bytes]:
    """Cifrar AES-256-CBC con PKCS7 (simula lo que hace la application)."""
    iv = os.urandom(16)
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv))
    encryptor = cipher.encryptor()
    padder = padding.PKCS7(128).padder()
    padded = padder.update(plaintext) + padder.finalize()
    ciphertext = encryptor.update(padded) + encryptor.finalize()
    return ciphertext, iv


def build_valid_puzzle(application_id, api_key_hex: str) -> dict:
    """Construir un puzzle válido como lo haría la application."""
    api_key = bytes.fromhex(api_key_hex)
    server_key = get_server_key()
    r2 = os.urandom(32)
    timestamp = int(time.time()).to_bytes(8, byteorder="big")

    p2 = hmac.new(
        api_key + server_key,
        r2 + timestamp,
        hashlib.sha256).digest()

    plaintext = p2 + r2 + timestamp
    ciphertext, iv = encrypt_aes(plaintext, api_key)

    return {
        "application_id": str(application_id),
        "encrypted_payload": {
            "ciphertext": b64encode(ciphertext).decode(),
            "iv": b64encode(iv).decode(),
        },
    }


def build_expired_puzzle(application_id, api_key_hex: str) -> dict:
    """Construir un puzzle con timestamp expirado (hace 120 seg)."""
    api_key = bytes.fromhex(api_key_hex)
    server_key = get_server_key()
    r2 = os.urandom(32)
    timestamp = int(time.time() - 120).to_bytes(8, byteorder="big")

    p2 = hmac.new(
        api_key + server_key,
        r2 + timestamp,
        hashlib.sha256).digest()

    plaintext = p2 + r2 + timestamp
    ciphertext, iv = encrypt_aes(plaintext, api_key)

    return {
        "application_id": str(application_id),
        "encrypted_payload": {
            "ciphertext": b64encode(ciphertext).decode(),
            "iv": b64encode(iv).decode(),
        },
    }


def build_wrong_key_puzzle(application_id) -> dict:
    """Construir un puzzle cifrado con una clave incorrecta."""
    wrong_key = os.urandom(32)
    server_key = get_server_key()
    r2 = os.urandom(32)
    timestamp = int(time.time()).to_bytes(8, byteorder="big")

    p2 = hmac.new(
        wrong_key + server_key,
        r2 + timestamp,
        hashlib.sha256).digest()

    plaintext = p2 + r2 + timestamp
    ciphertext, iv = encrypt_aes(plaintext, wrong_key)

    return {
        "application_id": str(application_id),
        "encrypted_payload": {
            "ciphertext": b64encode(ciphertext).decode(),
            "iv": b64encode(iv).decode(),
        },
    }


def build_tampered_puzzle(application_id, api_key_hex: str) -> dict:
    """Construir un puzzle con P2 manipulado (HMAC no coincide)."""
    api_key = bytes.fromhex(api_key_hex)
    r2 = os.urandom(32)
    timestamp = int(time.time()).to_bytes(8, byteorder="big")

    fake_p2 = os.urandom(32)

    plaintext = fake_p2 + r2 + timestamp
    ciphertext, iv = encrypt_aes(plaintext, api_key)

    return {
        "application_id": str(application_id),
        "encrypted_payload": {
            "ciphertext": b64encode(ciphertext).decode(),
            "iv": b64encode(iv).decode(),
        },
    }


# ── Fixtures ────────────────────────────────────────────────────────

API_KEY_HEX = secrets.token_hex(32)


@pytest.fixture
def mock_session_service():
    """Mock de SessionService (no necesita Valkey)."""
    service = AsyncMock()
    service.get_session.return_value = None
    service.create_session_with_tokens.return_value = MagicMock(
        access_token="test_access_token",
        refresh_token="test_refresh_token",
        token_type="Bearer")
    return service


@pytest.fixture
def admin_for_app(db):
    """Crear un administrator para asociar a las applications."""
    from sqlmodel import Session as SqlSession
    from app.database.model import NonCriticalPersonalData, SensitiveData
    from app.shared.auth.security import get_password_hash
    from datetime import datetime

    with SqlSession(db) as session:
        non_critical = NonCriticalPersonalData(
            first_name="App",
            last_name="Admin",
            second_last_name="Test",
            phone="+523399999999",
            address="Test St",
            city="Test City",
            state="Test",
            postal_code="06500",
            birth_date=datetime(1990, 1, 1),
            is_active=True)
        session.add(non_critical)
        session.flush()

        sensitive = SensitiveData(
            non_critical_data_id=non_critical.id,
            email="app_admin@test.com",
            password="TestPass123!",
            curp="APAD111111HDFRRL09",
            rfc="APAD111111AB0")
        session.add(sensitive)
        session.flush()

        admin = Administrator(
            sensitive_data_id=sensitive.id,
            is_master=True,
            is_active=True)
        session.add(admin)
        session.commit()
        session.refresh(admin)
        return admin.id


@pytest.fixture
def app_with_key(db, admin_for_app):
    """Crear una application con api_key conocida."""
    from sqlmodel import Session as SqlSession
    with SqlSession(db) as session:
        application = Application(
            name="Test App",
            api_key=API_KEY_HEX,
            administrator_id=admin_for_app,
            version="1.0.0",
            url="https://testapp.com",
            description="Test application",
            is_active=True)
        session.add(application)
        session.commit()
        session.refresh(application)
        return {"id": application.id, "name": application.name, "key": API_KEY_HEX}


@pytest.fixture
def inactive_app(db, admin_for_app):
    """Crear una application inactiva."""
    from sqlmodel import Session as SqlSession
    with SqlSession(db) as session:
        application = Application(
            name="Inactive App",
            api_key=API_KEY_HEX,
            administrator_id=admin_for_app,
            version="1.0.0",
            url="https://inactive.com",
            description="Inactive application",
            is_active=False)
        session.add(application)
        session.commit()
        session.refresh(application)
        return {"id": application.id, "name": application.name}


@pytest.fixture
def request_info():
    """Info de la petición para crear sesión."""
    return {
        "ip_address": "127.0.0.1",
        "user_agent": "test-agent",
    }


# ── Tests ───────────────────────────────────────────────────────────

class TestAppAuthSuccess:
    """Puzzle válido → autenticación exitosa."""

    @pytest.mark.asyncio
    async def test_valid_puzzle_returns_tokens(
        self, session, mock_session_service, app_with_key, request_info
    ):
        from app.shared.middleware.auth.applications.auth import CryptoManager
        from app.domain.application.schemas import PuzzleRequest

        crypto = CryptoManager(session, mock_session_service)
        puzzle_data = build_valid_puzzle(app_with_key["id"], app_with_key["key"])
        puzzle = PuzzleRequest(**puzzle_data)

        result = await crypto.authenticate(puzzle, request_info)

        assert result["valid"] is True
        assert "access_token" in result
        assert "refresh_token" in result
        assert result["token_type"] == "Bearer"
        assert result["application_id"] == str(app_with_key["id"])

    @pytest.mark.asyncio
    async def test_valid_puzzle_calls_create_session(
        self, session, mock_session_service, app_with_key, request_info
    ):
        from app.shared.middleware.auth.applications.auth import CryptoManager
        from app.domain.application.schemas import PuzzleRequest

        crypto = CryptoManager(session, mock_session_service)
        puzzle_data = build_valid_puzzle(app_with_key["id"], app_with_key["key"])
        puzzle = PuzzleRequest(**puzzle_data)

        await crypto.authenticate(puzzle, request_info)

        mock_session_service.create_session_with_tokens.assert_called_once()


class TestAppNotFound:
    """Application no existe → Authentication failed."""

    @pytest.mark.asyncio
    async def test_nonexistent_app_fails(
        self, session, mock_session_service, request_info
    ):
        from app.shared.middleware.auth.applications.auth import CryptoManager
        from app.domain.application.schemas import PuzzleRequest

        crypto = CryptoManager(session, mock_session_service)
        puzzle_data = build_valid_puzzle(
            "00000000-0000-0000-0000-000000000000", API_KEY_HEX
        )
        puzzle = PuzzleRequest(**puzzle_data)

        result = await crypto.authenticate(puzzle, request_info)

        assert result["valid"] is False
        assert result["error"] == "Authentication failed"


class TestAppInactive:
    """Application inactiva → Authentication failed."""

    @pytest.mark.asyncio
    async def test_inactive_app_fails(
        self, session, mock_session_service, inactive_app, request_info
    ):
        from app.shared.middleware.auth.applications.auth import CryptoManager
        from app.domain.application.schemas import PuzzleRequest

        crypto = CryptoManager(session, mock_session_service)
        puzzle_data = build_valid_puzzle(inactive_app["id"], API_KEY_HEX)
        puzzle = PuzzleRequest(**puzzle_data)

        result = await crypto.authenticate(puzzle, request_info)

        assert result["valid"] is False
        assert result["error"] == "Authentication failed"


class TestAppSessionActive:
    """Application ya tiene sesión activa → Authentication failed."""

    @pytest.mark.asyncio
    async def test_active_session_fails(
        self, session, mock_session_service, app_with_key, request_info
    ):
        from app.shared.middleware.auth.applications.auth import CryptoManager
        from app.domain.application.schemas import PuzzleRequest

        mock_session_service.get_session.return_value = MagicMock()

        crypto = CryptoManager(session, mock_session_service)
        puzzle_data = build_valid_puzzle(app_with_key["id"], app_with_key["key"])
        puzzle = PuzzleRequest(**puzzle_data)

        result = await crypto.authenticate(puzzle, request_info)

        assert result["valid"] is False
        assert result["error"] == "Authentication failed"


class TestAppDecryptionFailed:
    """Payload cifrado con clave incorrecta → Authentication failed."""

    @pytest.mark.asyncio
    async def test_wrong_key_fails(
        self, session, mock_session_service, app_with_key, request_info
    ):
        from app.shared.middleware.auth.applications.auth import CryptoManager
        from app.domain.application.schemas import PuzzleRequest

        crypto = CryptoManager(session, mock_session_service)
        puzzle_data = build_wrong_key_puzzle(app_with_key["id"])
        puzzle = PuzzleRequest(**puzzle_data)

        result = await crypto.authenticate(puzzle, request_info)

        assert result["valid"] is False
        assert result["error"] == "Authentication failed"


class TestAppTimestampExpired:
    """Timestamp fuera de ventana → Authentication failed."""

    @pytest.mark.asyncio
    async def test_expired_timestamp_fails(
        self, session, mock_session_service, app_with_key, request_info
    ):
        from app.shared.middleware.auth.applications.auth import CryptoManager
        from app.domain.application.schemas import PuzzleRequest

        crypto = CryptoManager(session, mock_session_service)
        puzzle_data = build_expired_puzzle(app_with_key["id"], app_with_key["key"])
        puzzle = PuzzleRequest(**puzzle_data)

        result = await crypto.authenticate(puzzle, request_info)

        assert result["valid"] is False
        assert result["error"] == "Authentication failed"


class TestAppP2Mismatch:
    """P2 no coincide (payload manipulado) → Authentication failed."""

    @pytest.mark.asyncio
    async def test_tampered_p2_fails(
        self, session, mock_session_service, app_with_key, request_info
    ):
        from app.shared.middleware.auth.applications.auth import CryptoManager
        from app.domain.application.schemas import PuzzleRequest

        crypto = CryptoManager(session, mock_session_service)
        puzzle_data = build_tampered_puzzle(app_with_key["id"], app_with_key["key"])
        puzzle = PuzzleRequest(**puzzle_data)

        result = await crypto.authenticate(puzzle, request_info)

        assert result["valid"] is False
        assert result["error"] == "Authentication failed"


class TestAppInvalidPayload:
    """Payload con datos inválidos → Authentication failed."""

    @pytest.mark.asyncio
    async def test_garbage_ciphertext_fails(
        self, session, mock_session_service, app_with_key, request_info
    ):
        from app.shared.middleware.auth.applications.auth import CryptoManager
        from app.domain.application.schemas import PuzzleRequest

        crypto = CryptoManager(session, mock_session_service)
        puzzle_data = {
            "application_id": str(app_with_key["id"]),
            "encrypted_payload": {
                "ciphertext": b64encode(os.urandom(64)).decode(),
                "iv": b64encode(os.urandom(16)).decode(),
            },
        }
        puzzle = PuzzleRequest(**puzzle_data)

        result = await crypto.authenticate(puzzle, request_info)

        assert result["valid"] is False
        assert result["error"] == "Authentication failed"
