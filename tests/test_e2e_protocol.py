"""Unit tests for the E2E AES-256-GCM session protocol (v2).

Covers:
- SHA-256 / HKDF key derivation (SEC-004)
- AES-256-GCM encrypt/decrypt round-trips (SEC-003)
- Salted password hashing (SEC-001)
- Full login handshake (crypto layer)
- Session repository (fakeredis)
"""

import base64
import json
import secrets

import fakeredis
import pytest
from cryptography.exceptions import InvalidTag

from app.shared.crypto import (
    aes_decrypt,
    aes_encrypt,
    derive_session_key,
    derive_temp_key,
    generate_salt,
    hash_password,
    sha256_bytes,
    sha256_hex,
    verify_password,
)
from app.shared.e2e.session import E2ESessionRepository


# ─────────────────────────────────────────────────────────────────────────────
# SHA-256 helpers
# ─────────────────────────────────────────────────────────────────────────────


class TestSha256:
    def test_hex_is_64_chars(self):
        result = sha256_hex("hello")
        assert len(result) == 64
        assert result == "2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824"

    def test_bytes_is_32_bytes(self):
        result = sha256_bytes("hello")
        assert len(result) == 32

    def test_bytes_and_hex_consistent(self):
        data = "consistency_test"
        assert sha256_bytes(data).hex() == sha256_hex(data)

    def test_accepts_bytes_input(self):
        assert sha256_hex(b"hello") == sha256_hex("hello")


# ─────────────────────────────────────────────────────────────────────────────
# SEC-001: salted passwords
# ─────────────────────────────────────────────────────────────────────────────


class TestPasswordSalting:
    def test_same_password_different_salts_produce_different_hashes(self):
        s1, s2 = generate_salt(), generate_salt()
        assert hash_password("MyPass1!", s1) != hash_password("MyPass1!", s2)

    def test_verify_correct_password(self):
        salt = generate_salt()
        h = hash_password("SecurePass1!", salt)
        assert verify_password("SecurePass1!", salt, h) is True

    def test_verify_wrong_password(self):
        salt = generate_salt()
        h = hash_password("SecurePass1!", salt)
        assert verify_password("WrongPass!", salt, h) is False

    def test_salt_is_16_hex_bytes(self):
        assert len(generate_salt()) == 32  # 16 bytes → 32 hex chars


# ─────────────────────────────────────────────────────────────────────────────
# SEC-004: HKDF key derivation
# ─────────────────────────────────────────────────────────────────────────────


class TestDeriveTempKey:
    def test_output_is_32_bytes(self):
        key = derive_temp_key("abc" * 21, "random_nonce", generate_salt())
        assert len(key) == 32

    def test_deterministic(self):
        salt = generate_salt()
        k1 = derive_temp_key("password_hash", "nonce", salt)
        k2 = derive_temp_key("password_hash", "nonce", salt)
        assert k1 == k2

    def test_different_nonces_produce_different_keys(self):
        salt = generate_salt()
        k1 = derive_temp_key("password_hash", "nonce1", salt)
        k2 = derive_temp_key("password_hash", "nonce2", salt)
        assert k1 != k2

    def test_different_salts_produce_different_keys(self):
        k1 = derive_temp_key("password_hash", "nonce", generate_salt())
        k2 = derive_temp_key("password_hash", "nonce", generate_salt())
        assert k1 != k2


class TestDeriveSessionKey:
    def test_output_is_32_bytes(self):
        key = derive_session_key("random2", "random3")
        assert len(key) == 32

    def test_deterministic(self):
        k1 = derive_session_key("r2", "r3")
        k2 = derive_session_key("r2", "r3")
        assert k1 == k2

    def test_symmetric_swap_produces_different_key(self):
        k1 = derive_session_key("r2", "r3")
        k2 = derive_session_key("r3", "r2")
        assert k1 != k2


# ─────────────────────────────────────────────────────────────────────────────
# SEC-003: AES-256-GCM
# ─────────────────────────────────────────────────────────────────────────────


class TestAesGcm:
    def test_encrypt_returns_ciphertext_and_nonce(self):
        key = secrets.token_bytes(32)
        ciphertext, iv = aes_encrypt(b"Hello, World!", key)
        assert len(iv) == 12  # GCM nonce is 12 bytes
        assert ciphertext != b"Hello, World!"

    def test_round_trip(self):
        key = secrets.token_bytes(32)
        plaintext = b"secret payload data"
        ciphertext, iv = aes_encrypt(plaintext, key)
        recovered = aes_decrypt(ciphertext, key, iv)
        assert recovered == plaintext

    def test_different_nonces_produce_different_ciphertext(self):
        key = secrets.token_bytes(32)
        plaintext = b"same data"
        ct1, _ = aes_encrypt(plaintext, key)
        ct2, _ = aes_encrypt(plaintext, key)
        assert ct1 != ct2

    def test_explicit_nonce(self):
        key = secrets.token_bytes(32)
        iv = secrets.token_bytes(12)  # GCM nonce: 12 bytes
        plaintext = b"deterministic test"
        ct1, iv1 = aes_encrypt(plaintext, key, iv=iv)
        ct2, iv2 = aes_encrypt(plaintext, key, iv=iv)
        assert ct1 == ct2
        assert iv1 == iv == iv2

    def test_json_payload_round_trip(self):
        key = secrets.token_bytes(32)
        payload = {"random2": secrets.token_hex(32), "nested": {"a": 1}}
        plaintext = json.dumps(payload).encode()
        ciphertext, iv = aes_encrypt(plaintext, key)
        recovered = aes_decrypt(ciphertext, key, iv)
        assert json.loads(recovered.decode()) == payload

    def test_tampered_ciphertext_raises_invalid_tag(self):
        """AES-GCM must detect any bit-flip in the ciphertext (SEC-003)."""
        key = secrets.token_bytes(32)
        ciphertext, iv = aes_encrypt(b"sensitive data", key)
        tampered = bytearray(ciphertext)
        tampered[0] ^= 0xFF
        with pytest.raises(InvalidTag):
            aes_decrypt(bytes(tampered), key, iv)

    def test_tampered_nonce_raises_invalid_tag(self):
        key = secrets.token_bytes(32)
        ciphertext, iv = aes_encrypt(b"data", key)
        bad_iv = bytearray(iv)
        bad_iv[0] ^= 0x01
        with pytest.raises(InvalidTag):
            aes_decrypt(ciphertext, key, bytes(bad_iv))


# ─────────────────────────────────────────────────────────────────────────────
# E2E session repository (fakeredis)
# ─────────────────────────────────────────────────────────────────────────────


@pytest.fixture
async def repo():
    client = fakeredis.FakeAsyncValkey(decode_responses=True)
    r = E2ESessionRepository("redis://localhost:6379/0")
    r.client = client
    yield r
    await client.flushall()
    await client.aclose()


class TestE2ESessionRepository:
    async def test_create_and_get_session(self, repo: E2ESessionRepository):
        session_key = secrets.token_bytes(32).hex()
        account = {"account_id": "uuid-1", "account_type": "administrator"}
        session_id = await repo.create_session(
            session_key_hex=session_key, account=account
        )
        assert session_id

        record = await repo.get_session(session_id)
        assert record is not None
        assert record["session_key"] == session_key
        assert record["account"]["account_id"] == "uuid-1"

    async def test_get_missing_session_returns_none(self, repo: E2ESessionRepository):
        result = await repo.get_session("nonexistent-id")
        assert result is None

    async def test_delete_session(self, repo: E2ESessionRepository):
        session_id = await repo.create_session(
            session_key_hex=secrets.token_bytes(32).hex(),
            account={"account_id": "x"},
        )
        await repo.delete_session(session_id)
        assert await repo.get_session(session_id) is None

    async def test_renew_session_returns_new_id(self, repo: E2ESessionRepository):
        session_id = await repo.create_session(
            session_key_hex=secrets.token_bytes(32).hex(),
            account={"account_id": "y"},
        )
        new_id = await repo.renew_session(session_id)
        assert new_id is not None
        assert new_id != session_id
        assert await repo.get_session(session_id) is None
        assert await repo.get_session(new_id) is not None

    async def test_renew_missing_session_returns_none(self, repo: E2ESessionRepository):
        result = await repo.renew_session("ghost-session-id")
        assert result is None


# ─────────────────────────────────────────────────────────────────────────────
# Full handshake simulation (v2 — AES-GCM + HKDF + salt)
# ─────────────────────────────────────────────────────────────────────────────


class TestFullHandshake:
    """Simulate the complete client-server login exchange with v2 protocol."""

    def test_handshake_round_trip(self):
        password = "MySecret123!"
        password_sha256 = sha256_hex(password)
        salt = generate_salt()

        random_hex = secrets.token_hex(16)
        random2 = secrets.token_hex(32)

        temp_key = derive_temp_key(password_sha256, random_hex, salt)
        client_payload = json.dumps({"random2": random2}).encode()
        ciphertext, iv = aes_encrypt(client_payload, temp_key)

        server_temp_key = derive_temp_key(password_sha256, random_hex, salt)
        decrypted = aes_decrypt(ciphertext, server_temp_key, iv)
        server_inner = json.loads(decrypted.decode())
        assert server_inner["random2"] == random2

        random3 = secrets.token_hex(32)
        session_key_server = derive_session_key(random2, random3)

        response_plain = json.dumps({"random3": random3, "session-id": "fake-uuid"}).encode()
        resp_ct, resp_iv = aes_encrypt(response_plain, server_temp_key)

        resp_decrypted = aes_decrypt(resp_ct, temp_key, resp_iv)
        server_response = json.loads(resp_decrypted.decode())
        assert server_response["random3"] == random3

        session_key_client = derive_session_key(random2, server_response["random3"])
        assert session_key_client == session_key_server

    def test_wrong_password_prevents_decryption(self):
        """Wrong password produces ciphertext that fails GCM auth tag check."""
        real_sha256 = sha256_hex("correct_password")
        wrong_sha256 = sha256_hex("wrong_password")
        salt = generate_salt()
        random_hex = secrets.token_hex(16)
        random2 = secrets.token_hex(32)

        client_key = derive_temp_key(real_sha256, random_hex, salt)
        payload = json.dumps({"random2": random2}).encode()
        ciphertext, iv = aes_encrypt(payload, client_key)

        server_key = derive_temp_key(wrong_sha256, random_hex, salt)
        with pytest.raises(InvalidTag):
            aes_decrypt(ciphertext, server_key, iv)

    def test_wrong_salt_prevents_decryption(self):
        """Different salt means different temp_key → GCM tag failure."""
        password_sha256 = sha256_hex("my_password")
        random_hex = secrets.token_hex(16)
        real_salt = generate_salt()
        wrong_salt = generate_salt()

        client_key = derive_temp_key(password_sha256, random_hex, real_salt)
        ciphertext, iv = aes_encrypt(b"payload", client_key)

        server_key = derive_temp_key(password_sha256, random_hex, wrong_salt)
        with pytest.raises(InvalidTag):
            aes_decrypt(ciphertext, server_key, iv)
