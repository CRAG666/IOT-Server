"""OWASP API9:2023 — Improper Inventory Management.

OpenAPI documentation endpoints should not be publicly accessible in production,
as they provide a complete attack surface map to unauthenticated clients.
"""

import pytest


class TestOpenAPIDocsExposure:
    """API schema documentation must not be accessible in production mode (DEBUG=False).

    SEC-013: /docs, /redoc, and /openapi.json must return 404 when DEBUG=False.
    The hide_docs_in_production middleware enforces this at request time.
    """

    def test_openapi_json_not_accessible_in_production(self, prod_client):
        """In production mode, /openapi.json must return 404."""
        resp = prod_client.get("/openapi.json")
        assert resp.status_code in (401, 403, 404), (
            "SEC-013: /openapi.json is publicly accessible in production; "
            "the hide_docs_in_production middleware should return 404"
        )

    def test_swagger_docs_not_accessible_in_production(self, prod_client):
        """In production mode, /docs must return 404."""
        resp = prod_client.get("/docs")
        assert resp.status_code in (401, 403, 404), (
            "SEC-013: /docs (Swagger UI) is publicly accessible in production"
        )

    def test_redoc_not_accessible_in_production(self, prod_client):
        """In production mode, /redoc must return 404."""
        resp = prod_client.get("/redoc")
        assert resp.status_code in (401, 403, 404), (
            "SEC-013: /redoc is publicly accessible in production"
        )

    def test_openapi_schema_exposes_all_endpoints(self, client):
        """Confirm the schema reveals internal route paths (informational)."""
        resp = client.get("/openapi.json")
        if resp.status_code != 200:
            pytest.skip("openapi.json not accessible — already protected")

        schema = resp.json()
        paths = list(schema.get("paths", {}).keys())
        protected_paths = [p for p in paths if "auth" in p or "administrator" in p]
        # We just document what's exposed; the xfail above is the actionable item.
        assert len(protected_paths) > 0, (
            "Expected to find protected paths in the schema — schema may be empty"
        )


class TestHealthEndpoints:
    """Health/readiness endpoints must not leak internal state."""

    def test_health_endpoint_is_accessible(self, client):
        resp = client.get("/health")
        assert resp.status_code == 200

    def test_health_response_does_not_leak_internals(self, client):
        resp = client.get("/health")
        assert resp.status_code == 200
        body = resp.json()
        # Must not reveal DB connection strings, stack traces, env vars, etc.
        body_str = str(body).lower()
        for sensitive in ("password", "secret", "token", "traceback", "exception"):
            assert sensitive not in body_str, (
                f"Health endpoint leaks '{sensitive}' in response body"
            )

    def test_ready_endpoint_is_accessible(self, client):
        resp = client.get("/ready")
        assert resp.status_code == 200
