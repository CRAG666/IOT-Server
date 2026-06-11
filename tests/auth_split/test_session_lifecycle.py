"""Tests for auth session lifecycle — logout, renew, and edge cases."""

from __future__ import annotations

import base64
import json
import secrets

import fakeredis
import pytest
from fastapi.testclient import TestClient

from app.main import app
from app.domain.auth.controller import _get_session_repo
from app.shared.crypto import aes_decrypt, derive_session_key
from app.shared.e2e.session import E2ESessionRepository


@pytest.fixture
def fake_session_repo():
    fake_client = fakeredis.FakeAsyncValkey(decode_responses=True)
    repo = E2ESessionRepository("redis://localhost:6379/0")
    repo.client = fake_client
    repo._external_client = True

    def override():
        return repo

    app.dependency_overrides[_get_session_repo] = override
    yield repo
    app.dependency_overrides.pop(_get_session_repo, None)


class TestLogout:
    def test_logout_requires_session_header(self, client, fake_session_repo):
        resp = client.post("/api/v1/auth/logout")
        assert resp.status_code == 400

    def test_logout_valid_session_succeeds(self, master_admin_client):
        resp = master_admin_client._raw.post(
            "/api/v1/auth/logout",
            headers={"X-Session-ID": master_admin_client.session_id},
        )
        assert resp.status_code == 200


class TestRenewSession:
    def test_renew_requires_session_header(self, client, fake_session_repo):
        resp = client.post("/api/v1/auth/renew")
        assert resp.status_code == 400

    def test_renew_invalid_session_returns_401(self, client, fake_session_repo):
        resp = client.post(
            "/api/v1/auth/renew",
            headers={"X-Session-ID": "no-such-session"},
        )
        assert resp.status_code == 401

    def test_renew_valid_session_returns_new_session_id(self, master_admin_client):
        old_session_id = master_admin_client.session_id

        resp = master_admin_client._raw.post(
            "/api/v1/auth/renew",
            headers={"X-Session-ID": old_session_id},
        )
        assert resp.status_code == 200
        # Response is E2E-encrypted — decrypt with session key
        data = resp.json()
        ct = base64.b64decode(data["payload"])
        iv = base64.b64decode(data["iv"])
        decrypted = aes_decrypt(ct, master_admin_client.session_key, iv)
        inner = json.loads(decrypted)
        assert "new_session_id" in inner
        assert inner["new_session_id"] != old_session_id
