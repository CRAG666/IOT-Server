"""Tests for the E2E login endpoint (POST /api/v1/auth/login) — protocol v2."""

import base64
import json
import secrets

import fakeredis
import pytest
from fastapi.testclient import TestClient

from app.main import app
from app.domain.auth.controller import _get_session_repo
from app.shared.crypto import aes_encrypt, derive_temp_key, sha256_hex, generate_salt
from app.shared.e2e.session import E2ESessionRepository


@pytest.fixture
def fake_session_repo():
    """Provide a fakeredis-backed E2ESessionRepository for login tests."""
    fake_client = fakeredis.FakeAsyncValkey(decode_responses=True)
    repo = E2ESessionRepository("redis://localhost:6379/0")
    repo.client = fake_client
    repo._external_client = True  # prevent close() from nullifying .client between requests

    def override():
        return repo

    app.dependency_overrides[_get_session_repo] = override
    yield repo
    app.dependency_overrides.pop(_get_session_repo, None)


def _do_login(client: TestClient, email: str, salted_hash: str, salt: str) -> "Response":
    """Helper: call /auth/login with the v2 protocol."""
    random_hex = secrets.token_hex(16)
    random2 = secrets.token_hex(32)
    temp_key = derive_temp_key(salted_hash, random_hex, salt)
    inner_plain = json.dumps({"random2": random2}).encode()
    ciphertext, iv = aes_encrypt(inner_plain, temp_key)
    return client.post(
        "/api/v1/auth/login",
        json={
            "username": email,
            "payload": base64.b64encode(ciphertext).decode(),
            "random": random_hex,
            "iv": base64.b64encode(iv).decode(),
        },
    )


def _get_salt(client: TestClient, email: str) -> str:
    """Fetch the per-user salt via /auth/challenge."""
    resp = client.get(f"/api/v1/auth/challenge?email={email}")
    assert resp.status_code == 200
    return resp.json()["salt"]


class TestLoginEndpoint:
    """Full E2E login handshake tests (v2: AES-GCM + HKDF + salted passwords)."""

    def test_login_success_returns_payload_and_iv(
        self, client: TestClient, master_admin_account: dict, fake_session_repo
    ):
        """A valid login returns an encrypted payload and iv."""
        password = master_admin_account["password"]
        email = master_admin_account["email"]

        salt = _get_salt(client, email)
        salted_hash = sha256_hex(salt + sha256_hex(password))

        response = _do_login(client, email, salted_hash, salt)

        assert response.status_code == 200
        data = response.json()
        assert "payload" in data
        assert "iv" in data

    def test_login_wrong_password_returns_401(
        self, client: TestClient, master_admin_account: dict, fake_session_repo
    ):
        """Wrong password derives a wrong temp_key → AES-GCM tag failure → 401."""
        email = master_admin_account["email"]
        salt = _get_salt(client, email)
        # Use wrong password to compute salted_hash
        wrong_salted = sha256_hex(salt + sha256_hex("WrongPassword!"))
        response = _do_login(client, email, wrong_salted, salt)
        assert response.status_code == 401

    def test_login_unknown_username_returns_401(
        self, client: TestClient, fake_session_repo
    ):
        """Non-existent user returns 401 (challenge returns a fake salt)."""
        ch = client.get("/api/v1/auth/challenge?email=nobody@nowhere.com")
        assert ch.status_code == 200
        fake_salt = ch.json()["salt"]
        fake_hash = sha256_hex(fake_salt + sha256_hex("anything"))
        response = _do_login(client, "nobody@nowhere.com", fake_hash, fake_salt)
        assert response.status_code == 401

    def test_login_inactive_user_returns_401(
        self, client: TestClient, inactive_user_account: dict, fake_session_repo
    ):
        """Inactive account is rejected even with correct password."""
        password = inactive_user_account["password"]
        email = inactive_user_account["email"]
        salt = _get_salt(client, email)
        salted_hash = sha256_hex(salt + sha256_hex(password))
        response = _do_login(client, email, salted_hash, salt)
        assert response.status_code == 401
