"""Tests for ops endpoints: /health, /ready, request-ID middleware."""
import pytest
from fastapi.testclient import TestClient


class TestHealthEndpoint:
    def test_health_returns_200(self, client: TestClient):
        response = client.get("/health")
        assert response.status_code == 200

    def test_health_body(self, client: TestClient):
        response = client.get("/health")
        assert response.json() == {"status": "ok"}

    def test_health_no_auth_required(self, client: TestClient):
        response = client.get("/health")
        assert response.status_code == 200

    def test_request_id_uuid_is_propagated(self, client: TestClient):
        """A well-formed UUID X-Request-ID is echoed as-is (SEC-011)."""
        import uuid
        rid = str(uuid.uuid4())
        response = client.get("/health", headers={"X-Request-ID": rid})
        assert response.headers.get("X-Request-ID") == rid

    def test_non_uuid_request_id_is_replaced_with_server_uuid(self, client: TestClient):
        """Non-UUID X-Request-ID values are replaced to prevent log injection (SEC-011)."""
        import uuid
        response = client.get("/health", headers={"X-Request-ID": "test-id-123"})
        echoed = response.headers.get("X-Request-ID", "")
        # Must be a valid UUID, not the injected string
        assert echoed != "test-id-123"
        uuid.UUID(echoed)  # raises ValueError if not a UUID

    def test_request_id_generated_when_absent(self, client: TestClient):
        response = client.get("/health")
        assert "X-Request-ID" in response.headers
        assert len(response.headers["X-Request-ID"]) > 0


class TestReadyEndpoint:
    def test_ready_returns_200(self, client: TestClient):
        response = client.get("/ready")
        assert response.status_code == 200

    def test_ready_body(self, client: TestClient):
        response = client.get("/ready")
        assert response.json() == {"status": "ready"}

    def test_ready_no_auth_required(self, client: TestClient):
        response = client.get("/ready")
        assert response.status_code == 200
