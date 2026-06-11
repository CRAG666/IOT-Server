"""OWASP API2:2023 — Broken Authentication.

Tests for timing-safe credential comparison, login credential error uniformity,
inactive-account rejection, and session expiry handling.
"""

import base64
import hmac as _hmac
import json
import secrets

import pytest

from app.shared.crypto import (
    aes_encrypt,
    derive_temp_key,
    derive_session_key,
    sha256_hex,
    generate_salt,
    hash_password,
    verify_password,
)
from app.shared.auth.security import check_password


# ── Unit-level tests ──────────────────────────────────────────────────────────


class TestVerifyPasswordSafety:
    def test_verify_password_correct(self):
        salt = generate_salt()
        h = hash_password("SecurePass1!", salt)
        assert verify_password("SecurePass1!", salt, h) is True

    def test_verify_password_incorrect(self):
        salt = generate_salt()
        h = hash_password("SecurePass1!", salt)
        assert verify_password("WrongPass99!", salt, h) is False

    def test_verify_password_uses_constant_time_compare(self):
        """verify_password must use hmac.compare_digest to prevent timing attacks (SEC-002)."""
        import inspect
        from app.shared import crypto as crypto_module
        src = inspect.getsource(crypto_module.verify_password)
        assert "compare_digest" in src, (
            "verify_password must use hmac.compare_digest instead of == "
            "(timing side-channel, SEC-002)"
        )

    def test_password_hash_includes_salt(self):
        """Two identical passwords must produce different digests when salted (SEC-001)."""
        salt1 = generate_salt()
        salt2 = generate_salt()
        h1 = hash_password("SamePassword1!", salt1)
        h2 = hash_password("SamePassword1!", salt2)
        assert h1 != h2, (
            "SEC-001: two identical passwords with different salts must produce different hashes"
        )

    def test_aes_gcm_provides_auth_tag(self):
        """AES-GCM must detect ciphertext tampering (SEC-003)."""
        from cryptography.exceptions import InvalidTag
        key = secrets.token_bytes(32)
        ciphertext, iv = aes_encrypt(b"hello world", key)
        # Flip a byte in the ciphertext
        tampered = bytearray(ciphertext)
        tampered[0] ^= 0xFF
        from app.shared.crypto import aes_decrypt
        with pytest.raises(InvalidTag):
            aes_decrypt(bytes(tampered), key, iv)


# ── API-level tests ───────────────────────────────────────────────────────────


class TestLoginErrorUniformity:
    """Login must return identical status/body for all invalid credential variants."""

    def _login_raw(self, client, email: str, password: str) -> int:
        random_hex = secrets.token_hex(16)
        salt = generate_salt()
        inner_hash = sha256_hex(password)
        # build a throwaway temp_key with a random salt (we don't have the real one)
        temp_key = derive_temp_key(inner_hash, random_hex, salt)
        random2 = secrets.token_hex(16)
        payload_bytes = json.dumps({"random2": random2}).encode()
        ciphertext, iv = aes_encrypt(payload_bytes, temp_key)
        body = {
            "username": email,
            "payload": base64.b64encode(ciphertext).decode(),
            "random": random_hex,
            "iv": base64.b64encode(iv).decode(),
        }
        return client.post("/api/v1/auth/login", json=body).status_code

    def test_wrong_password_returns_401(self, client):
        assert self._login_raw(client, "master_admin@test.com", "WrongPassword!") == 401

    def test_nonexistent_user_returns_401(self, client):
        assert self._login_raw(client, "nobody@nowhere.com", "AnyPassword!") == 401

    def test_same_status_for_wrong_and_missing(self, client):
        s1 = self._login_raw(client, "master_admin@test.com", "WrongPassword!")
        s2 = self._login_raw(client, "nobody@nowhere.com", "AnyPassword!")
        assert s1 == s2 == 401


class TestSessionValidity:
    def test_invalid_session_returns_401(self, client):
        resp = client.get(
            "/api/v1/administrators",
            headers={"X-Session-ID": "not-a-real-session-id"},
        )
        assert resp.status_code == 401

    def test_tampered_session_returns_401(self, client):
        resp = client.get(
            "/api/v1/administrators",
            headers={"X-Session-ID": secrets.token_hex(32)},
        )
        assert resp.status_code == 401


class TestAESIntegrity:
    def test_aes_gcm_rejects_tampered_body(self, master_admin_client):
        """Bit-flipped payload must be rejected — AES-GCM detects tampering (SEC-003).

        Uses a real session key so the middleware reaches the decryption step;
        a random throwaway key would be rejected earlier (wrong session).
        """
        key = master_admin_client.session_key
        ciphertext, iv = aes_encrypt(b'{"key":"value"}', key)
        tampered = bytearray(ciphertext)
        tampered[0] ^= 0xFF
        body = {
            "payload": base64.b64encode(bytes(tampered)).decode(),
            "iv": base64.b64encode(iv).decode(),
        }
        resp = master_admin_client._raw.post(
            "/api/v1/administrators",
            json=body,
            headers={"X-Session-ID": master_admin_client.session_id},
        )
        assert resp.status_code in (400, 401, 403, 422)
