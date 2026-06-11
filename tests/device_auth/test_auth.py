"""Tests para autenticación de dispositivos por puzzle criptográfico."""
import hashlib
import hmac
import os
import time
import pytest
import pytest_asyncio
from base64 import b64encode
from unittest.mock import AsyncMock, MagicMock

from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import padding

from app.config import settings
from app.database.model import Device


# ── Helpers: simular lo que haría el dispositivo ────────────────────

def get_server_key():
    return hashlib.sha256(
        (settings.SECRET_KEY + "|puzzle_v1").encode("utf-8")
    ).digest()


def encrypt_aes(plaintext: bytes, key: bytes) -> tuple[bytes, bytes]:
    """Cifrar AES-256-CBC con PKCS7 (simula lo que hace el device)."""
    iv = os.urandom(16)
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv))
    encryptor = cipher.encryptor()
    padder = padding.PKCS7(128).padder()
    padded = padder.update(plaintext) + padder.finalize()
    ciphertext = encryptor.update(padded) + encryptor.finalize()
    return ciphertext, iv


def build_valid_puzzle(device_id, device_key_hex: str) -> dict:
    """Construir un puzzle válido como lo haría el dispositivo."""
    device_key = bytes.fromhex(device_key_hex)
    r2 = os.urandom(32)
    timestamp = int(time.time()).to_bytes(8, byteorder="big")

    p2 = hmac.new(
        device_key + get_server_key(),
        r2 + timestamp,
        hashlib.sha256).digest()

    plaintext = p2 + r2 + timestamp  # 32 + 32 + 8 = 72 bytes
    ciphertext, iv = encrypt_aes(plaintext, device_key)

    return {
        "device_id": str(device_id),
        "encrypted_payload": {
            "ciphertext": b64encode(ciphertext).decode(),
            "iv": b64encode(iv).decode(),
        },
    }


def build_expired_puzzle(device_id, device_key_hex: str) -> dict:
    """Construir un puzzle con timestamp expirado (hace 120 seg)."""
    device_key = bytes.fromhex(device_key_hex)
    r2 = os.urandom(32)
    timestamp = int(time.time() - 120).to_bytes(8, byteorder="big")

    p2 = hmac.new(
        device_key + get_server_key(),
        r2 + timestamp,
        hashlib.sha256).digest()

    plaintext = p2 + r2 + timestamp
    ciphertext, iv = encrypt_aes(plaintext, device_key)

    return {
        "device_id": str(device_id),
        "encrypted_payload": {
            "ciphertext": b64encode(ciphertext).decode(),
            "iv": b64encode(iv).decode(),
        },
    }


def build_wrong_key_puzzle(device_id) -> dict:
    """Construir un puzzle cifrado con una clave incorrecta."""
    wrong_key = os.urandom(32)
    r2 = os.urandom(32)
    timestamp = int(time.time()).to_bytes(8, byteorder="big")

    p2 = hmac.new(
        wrong_key + get_server_key(),
        r2 + timestamp,
        hashlib.sha256).digest()

    plaintext = p2 + r2 + timestamp
    ciphertext, iv = encrypt_aes(plaintext, wrong_key)

    return {
        "device_id": str(device_id),
        "encrypted_payload": {
            "ciphertext": b64encode(ciphertext).decode(),
            "iv": b64encode(iv).decode(),
        },
    }


def build_tampered_puzzle(device_id, device_key_hex: str) -> dict:
    """Construir un puzzle con P2 manipulado (HMAC no coincide)."""
    device_key = bytes.fromhex(device_key_hex)
    r2 = os.urandom(32)
    timestamp = int(time.time()).to_bytes(8, byteorder="big")

    fake_p2 = os.urandom(32)  # P2 falso, no calculado con HMAC

    plaintext = fake_p2 + r2 + timestamp
    ciphertext, iv = encrypt_aes(plaintext, device_key)

    return {
        "device_id": str(device_id),
        "encrypted_payload": {
            "ciphertext": b64encode(ciphertext).decode(),
            "iv": b64encode(iv).decode(),
        },
    }


# ── Fixtures ────────────────────────────────────────────────────────

DEVICE_KEY_HEX = "a" * 64  # 32 bytes en hex


@pytest.fixture
def mock_session_service():
    """Mock de SessionService (no necesita Valkey)."""
    service = AsyncMock()
    service.get_session.return_value = None  # sin sesión activa por defecto
    service.create_session_with_tokens.return_value = MagicMock(
        access_token="test_access_token",
        refresh_token="test_refresh_token",
        token_type="Bearer")
    return service


@pytest.fixture
def device_with_key(db):
    """Crear un device con encryption_key en BD."""
    from sqlmodel import Session as SqlSession
    with SqlSession(db) as session:
        device = Device(
            name="Sensor Test",
            encryption_key=DEVICE_KEY_HEX,
            is_active=True)
        session.add(device)
        session.commit()
        session.refresh(device)
        return {"id": device.id, "name": device.name, "key": DEVICE_KEY_HEX}


@pytest.fixture
def inactive_device(db):
    """Crear un device inactivo."""
    from sqlmodel import Session as SqlSession
    with SqlSession(db) as session:
        device = Device(
            name="Sensor Inactivo",
            encryption_key=DEVICE_KEY_HEX,
            is_active=False)
        session.add(device)
        session.commit()
        session.refresh(device)
        return {"id": device.id, "name": device.name}


@pytest.fixture
def device_without_key(db):
    """Crear un device sin encryption_key."""
    from sqlmodel import Session as SqlSession
    with SqlSession(db) as session:
        device = Device(
            name="Sensor Sin Key",
            encryption_key=None,
            is_active=True)
        session.add(device)
        session.commit()
        session.refresh(device)
        return {"id": device.id, "name": device.name}


@pytest.fixture
def request_info():
    """Info de la petición para crear sesión."""
    return {
        "ip_address": "127.0.0.1",
        "user_agent": "test-agent",
    }


# ── Tests ───────────────────────────────────────────────────────────

class TestDeviceAuthSuccess:
    """Puzzle válido → autenticación exitosa."""

    @pytest.mark.asyncio
    async def test_valid_puzzle_returns_tokens(
        self, session, mock_session_service, device_with_key, request_info
    ):
        from app.shared.middleware.auth.devices.auth import CryptoManager

        crypto = CryptoManager(session, mock_session_service)
        puzzle_data = build_valid_puzzle(device_with_key["id"], device_with_key["key"])

        from app.domain.device.schemas import PuzzleRequest
        puzzle = PuzzleRequest(**puzzle_data)

        result = await crypto.authenticate(puzzle, request_info)

        assert result["valid"] is True
        assert "access_token" in result
        assert "refresh_token" in result
        assert result["token_type"] == "Bearer"
        assert result["device_id"] == str(device_with_key["id"])

    @pytest.mark.asyncio
    async def test_valid_puzzle_calls_create_session(
        self, session, mock_session_service, device_with_key, request_info
    ):
        from app.shared.middleware.auth.devices.auth import CryptoManager

        crypto = CryptoManager(session, mock_session_service)
        puzzle_data = build_valid_puzzle(device_with_key["id"], device_with_key["key"])

        from app.domain.device.schemas import PuzzleRequest
        puzzle = PuzzleRequest(**puzzle_data)

        await crypto.authenticate(puzzle, request_info)

        mock_session_service.create_session_with_tokens.assert_called_once()


class TestDeviceNotFound:
    """Device no existe → Authentication failed."""

    @pytest.mark.asyncio
    async def test_nonexistent_device_fails(
        self, session, mock_session_service, request_info
    ):
        from app.shared.middleware.auth.devices.auth import CryptoManager
        from app.domain.device.schemas import PuzzleRequest

        crypto = CryptoManager(session, mock_session_service)
        puzzle_data = build_valid_puzzle(
            "00000000-0000-0000-0000-000000000000", DEVICE_KEY_HEX
        )
        puzzle = PuzzleRequest(**puzzle_data)

        result = await crypto.authenticate(puzzle, request_info)

        assert result["valid"] is False
        assert result["error"] == "Authentication failed"


class TestDeviceInactive:
    """Device inactivo → Authentication failed."""

    @pytest.mark.asyncio
    async def test_inactive_device_fails(
        self, session, mock_session_service, inactive_device, request_info
    ):
        from app.shared.middleware.auth.devices.auth import CryptoManager
        from app.domain.device.schemas import PuzzleRequest

        crypto = CryptoManager(session, mock_session_service)
        puzzle_data = build_valid_puzzle(inactive_device["id"], DEVICE_KEY_HEX)
        puzzle = PuzzleRequest(**puzzle_data)

        result = await crypto.authenticate(puzzle, request_info)

        assert result["valid"] is False
        assert result["error"] == "Authentication failed"


class TestSessionActive:
    """Device ya tiene sesión activa → Authentication failed."""

    @pytest.mark.asyncio
    async def test_active_session_fails(
        self, session, mock_session_service, device_with_key, request_info
    ):
        from app.shared.middleware.auth.devices.auth import CryptoManager
        from app.domain.device.schemas import PuzzleRequest

        # Simular sesión activa
        mock_session_service.get_session.return_value = MagicMock()

        crypto = CryptoManager(session, mock_session_service)
        puzzle_data = build_valid_puzzle(device_with_key["id"], device_with_key["key"])
        puzzle = PuzzleRequest(**puzzle_data)

        result = await crypto.authenticate(puzzle, request_info)

        assert result["valid"] is False
        assert result["error"] == "Authentication failed"


class TestNoEncryptionKey:
    """Device sin encryption_key → Authentication failed."""

    @pytest.mark.asyncio
    async def test_missing_key_fails(
        self, session, mock_session_service, device_without_key, request_info
    ):
        from app.shared.middleware.auth.devices.auth import CryptoManager
        from app.domain.device.schemas import PuzzleRequest

        crypto = CryptoManager(session, mock_session_service)
        puzzle_data = build_valid_puzzle(device_without_key["id"], DEVICE_KEY_HEX)
        puzzle = PuzzleRequest(**puzzle_data)

        result = await crypto.authenticate(puzzle, request_info)

        assert result["valid"] is False
        assert result["error"] == "Authentication failed"


class TestDecryptionFailed:
    """Payload cifrado con clave incorrecta → Authentication failed."""

    @pytest.mark.asyncio
    async def test_wrong_key_fails(
        self, session, mock_session_service, device_with_key, request_info
    ):
        from app.shared.middleware.auth.devices.auth import CryptoManager
        from app.domain.device.schemas import PuzzleRequest

        crypto = CryptoManager(session, mock_session_service)
        puzzle_data = build_wrong_key_puzzle(device_with_key["id"])
        puzzle = PuzzleRequest(**puzzle_data)

        result = await crypto.authenticate(puzzle, request_info)

        assert result["valid"] is False
        assert result["error"] == "Authentication failed"


class TestTimestampExpired:
    """Timestamp fuera de ventana → Authentication failed."""

    @pytest.mark.asyncio
    async def test_expired_timestamp_fails(
        self, session, mock_session_service, device_with_key, request_info
    ):
        from app.shared.middleware.auth.devices.auth import CryptoManager
        from app.domain.device.schemas import PuzzleRequest

        crypto = CryptoManager(session, mock_session_service)
        puzzle_data = build_expired_puzzle(
            device_with_key["id"], device_with_key["key"]
        )
        puzzle = PuzzleRequest(**puzzle_data)

        result = await crypto.authenticate(puzzle, request_info)

        assert result["valid"] is False
        assert result["error"] == "Authentication failed"


class TestP2Mismatch:
    """P2 no coincide (payload manipulado) → Authentication failed."""

    @pytest.mark.asyncio
    async def test_tampered_p2_fails(
        self, session, mock_session_service, device_with_key, request_info
    ):
        from app.shared.middleware.auth.devices.auth import CryptoManager
        from app.domain.device.schemas import PuzzleRequest

        crypto = CryptoManager(session, mock_session_service)
        puzzle_data = build_tampered_puzzle(
            device_with_key["id"], device_with_key["key"]
        )
        puzzle = PuzzleRequest(**puzzle_data)

        result = await crypto.authenticate(puzzle, request_info)

        assert result["valid"] is False
        assert result["error"] == "Authentication failed"


class TestInvalidPayloadFormat:
    """Payload con datos inválidos → Authentication failed."""

    @pytest.mark.asyncio
    async def test_garbage_ciphertext_fails(
        self, session, mock_session_service, device_with_key, request_info
    ):
        from app.shared.middleware.auth.devices.auth import CryptoManager
        from app.domain.device.schemas import PuzzleRequest

        crypto = CryptoManager(session, mock_session_service)
        puzzle_data = {
            "device_id": str(device_with_key["id"]),
            "encrypted_payload": {
                "ciphertext": b64encode(os.urandom(64)).decode(),
                "iv": b64encode(os.urandom(16)).decode(),
            },
        }
        puzzle = PuzzleRequest(**puzzle_data)

        result = await crypto.authenticate(puzzle, request_info)

        assert result["valid"] is False
        assert result["error"] == "Authentication failed"
