"""Tests de rate limiting para los endpoints de /tickets/service y /tickets/ecosystem.

Límite configurado: 3 peticiones por segundo por IP, por router independiente.
"""
import time
import pytest
import fakeredis

from app.main import app
from app.shared.rate_limit import get_rate_limit_repository



class _FakeRateLimitRepo:
    """Valkey-compatible rate limit repository backed by fakeredis."""

    def __init__(self):
        self._client = fakeredis.FakeAsyncValkey()

    async def increment_rate_limit(self, key: str, window_seconds: int = 900) -> int:
        rate_key = f"rate_limit:{key}"
        count = await self._client.incr(rate_key)
        if count == 1:
            await self._client.expire(rate_key, int(window_seconds))
        return count

    async def get_rate_limit_ttl(self, key: str) -> int:
        rate_key = f"rate_limit:{key}"
        ttl = await self._client.ttl(rate_key)
        return max(int(ttl), 0)

    async def close(self) -> None:
        await self._client.aclose()


@pytest.fixture
def fake_rate_repo():
    """Provide a fresh fakeredis-backed rate limit repo and wire it into the app."""
    repo = _FakeRateLimitRepo()
    app.dependency_overrides[get_rate_limit_repository] = lambda: repo
    yield repo
    app.dependency_overrides.pop(get_rate_limit_repository, None)


# ─────────────────────────────────────────────────────────────────────────────
# ServiceTicket rate limit
# ─────────────────────────────────────────────────────────────────────────────

class TestServiceTicketRateLimit:

    def test_first_three_requests_are_allowed(self, master_admin_client, fake_rate_repo):
        """Las 3 primeras peticiones deben pasar."""
        for _ in range(3):
            resp = master_admin_client.get(
                "/api/v1/tickets/service")
            assert resp.status_code == 200

    def test_fourth_request_returns_429(self, master_admin_client, fake_rate_repo):
        """La 4ª petición en el mismo segundo debe devolver 429."""
        for _ in range(3):
            master_admin_client.get(
                "/api/v1/tickets/service")

        resp = master_admin_client.get(
            "/api/v1/tickets/service")
        assert resp.status_code == 429

    def test_429_has_retry_after_header(self, master_admin_client, fake_rate_repo):
        """La respuesta 429 debe incluir Retry-After: 1."""
        for _ in range(3):
            master_admin_client.get("/api/v1/tickets/service")

        resp = master_admin_client.get("/api/v1/tickets/service")
        assert resp.status_code == 429
        assert "Retry-After" in resp.headers
        assert resp.headers["Retry-After"] == "1"

    def test_rate_limit_resets_after_window_expires(self, master_admin_client, fake_rate_repo):
        """Después de 1 segundo la cuota se reinicia."""
        for _ in range(3):
            master_admin_client.get("/api/v1/tickets/service")

        assert master_admin_client.get(
            "/api/v1/tickets/service"
        ).status_code == 429

        time.sleep(1.1)

        resp = master_admin_client.get("/api/v1/tickets/service")
        assert resp.status_code == 200

    def test_service_limit_does_not_affect_ecosystem_endpoint(self, master_admin_client, fake_rate_repo):
        """Agotar el límite de /tickets/service no debe bloquear /tickets/ecosystem."""
        for _ in range(3):
            master_admin_client.get("/api/v1/tickets/service")

        assert master_admin_client.get(
            "/api/v1/tickets/service"
        ).status_code == 429

        resp = master_admin_client.get("/api/v1/tickets/ecosystem")
        assert resp.status_code == 200

    def test_unauthenticated_requests_consume_quota(self, client, fake_rate_repo):
        """Las peticiones sin token también consumen cuota."""
        for _ in range(3):
            resp = client.get("/api/v1/tickets/service")
            assert resp.status_code == 401

        resp = client.get("/api/v1/tickets/service")
        assert resp.status_code == 429


# ─────────────────────────────────────────────────────────────────────────────
# EcosystemTicket rate limit
# ─────────────────────────────────────────────────────────────────────────────

class TestEcosystemTicketRateLimit:

    def test_first_three_requests_are_allowed(self, master_admin_client, fake_rate_repo):
        """Las 3 primeras peticiones deben pasar."""
        for _ in range(3):
            resp = master_admin_client.get(
                "/api/v1/tickets/ecosystem")
            assert resp.status_code == 200

    def test_fourth_request_returns_429(self, master_admin_client, fake_rate_repo):
        """La 4ª petición en el mismo segundo debe devolver 429."""
        for _ in range(3):
            master_admin_client.get(
                "/api/v1/tickets/ecosystem")

        resp = master_admin_client.get(
            "/api/v1/tickets/ecosystem")
        assert resp.status_code == 429

    def test_429_has_retry_after_header(self, master_admin_client, fake_rate_repo):
        """La respuesta 429 debe incluir Retry-After: 1."""
        for _ in range(3):
            master_admin_client.get("/api/v1/tickets/ecosystem")

        resp = master_admin_client.get("/api/v1/tickets/ecosystem")
        assert resp.status_code == 429
        assert "Retry-After" in resp.headers
        assert resp.headers["Retry-After"] == "1"

    def test_rate_limit_resets_after_window_expires(self, master_admin_client, fake_rate_repo):
        """Después de 1 segundo la cuota se reinicia."""
        for _ in range(3):
            master_admin_client.get("/api/v1/tickets/ecosystem")

        assert master_admin_client.get(
            "/api/v1/tickets/ecosystem"
        ).status_code == 429

        time.sleep(1.1)

        resp = master_admin_client.get("/api/v1/tickets/ecosystem")
        assert resp.status_code == 200

    def test_ecosystem_limit_does_not_affect_service_endpoint(self, master_admin_client, fake_rate_repo):
        """Agotar el límite de /tickets/ecosystem no debe bloquear /tickets/service."""
        for _ in range(3):
            master_admin_client.get("/api/v1/tickets/ecosystem")

        assert master_admin_client.get(
            "/api/v1/tickets/ecosystem"
        ).status_code == 429

        resp = master_admin_client.get("/api/v1/tickets/service")
        assert resp.status_code == 200

    def test_unauthenticated_requests_consume_quota(self, client, fake_rate_repo):
        """Las peticiones sin token también consumen cuota."""
        for _ in range(3):
            resp = client.get("/api/v1/tickets/ecosystem")
            assert resp.status_code == 401

        resp = client.get("/api/v1/tickets/ecosystem")
        assert resp.status_code == 429
