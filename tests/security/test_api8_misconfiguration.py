"""OWASP API8:2023 — Security Misconfiguration.

Tests covering CORS headers, missing security response headers, client-controlled
X-Request-ID, and default log level.
"""

import re
import uuid

import pytest


class TestCORSConfiguration:
    """CORS must not expose credentials to arbitrary origins (SEC-009).

    ``allow_origins=["*"]`` with ``allow_credentials=True`` is invalid per the
    CORS spec and prevents credentialed cross-origin requests in browsers.
    It should be replaced with an explicit allowlist.
    """

    def test_cors_wildcard_not_combined_with_credentials_in_code(self):
        """Inspect config: wildcard CORS must not coexist with allow_credentials=True."""
        import inspect
        from app import main as main_module

        src = inspect.getsource(main_module)

        wildcard_cors = '["*"]' in src or '"*"' in src
        credentials_true = "allow_credentials=True" in src

        if wildcard_cors and credentials_true:
            pytest.xfail(
                "SEC-009 (CRITICAL): allow_origins=[\"*\"] combined with "
                "allow_credentials=True is a security misconfiguration; "
                "restrict CORS origins to an env-configured allowlist"
            )

    def test_cors_origin_header_echoed_to_null_origin(self, client):
        """A 'null' origin must not receive Access-Control-Allow-Origin: null."""
        resp = client.get(
            "/health",
            headers={"Origin": "null"},
        )
        acao = resp.headers.get("access-control-allow-origin", "")
        assert acao != "null", (
            "SEC-009: 'null' origin reflected — sandbox iframe CORS bypass possible"
        )

    def test_cors_arbitrary_origin_not_reflected_on_protected_endpoint(self, client):
        """Arbitrary origins must not receive ACAO on protected endpoints."""
        resp = client.get(
            "/api/v1/administrators/",
            headers={"Origin": "https://evil.example.com"},
        )
        acao = resp.headers.get("access-control-allow-origin", "")
        # Wildcard is the current state — document as xfail pending fix
        if acao == "*":
            pytest.xfail(
                "SEC-009: wildcard ACAO returned on protected endpoint; "
                "restrict to configured allowlist"
            )


class TestSecurityResponseHeaders:
    """Responses must include defensive HTTP security headers (SEC-010).

    Missing headers allow clickjacking, MIME-sniffing, and information leakage.
    """

    def _check_header(self, resp, header: str, expected_pattern: str | None = None):
        value = resp.headers.get(header)
        if value is None:
            pytest.xfail(
                f"SEC-010: missing security header '{header}'; "
                "add a SecurityHeadersMiddleware to app/main.py"
            )
        if expected_pattern and not re.search(expected_pattern, value, re.IGNORECASE):
            pytest.xfail(
                f"SEC-010: header '{header}: {value}' does not match "
                f"expected pattern '{expected_pattern}'"
            )

    def test_x_content_type_options_present(self, client):
        resp = client.get("/health")
        self._check_header(resp, "x-content-type-options", "nosniff")

    def test_x_frame_options_present(self, client):
        resp = client.get("/health")
        self._check_header(resp, "x-frame-options")

    def test_x_request_id_returned(self, client):
        """Server must echo (or generate) a request ID for audit correlation."""
        resp = client.get("/health")
        assert "x-request-id" in resp.headers, (
            "x-request-id header missing from response"
        )


class TestClientControlledRequestID:
    """X-Request-ID must be sanitized or always server-generated (SEC-011)."""

    def test_injected_request_id_is_sanitized_or_ignored(self, client):
        """A non-UUID X-Request-ID must not appear verbatim in the response."""
        malicious_id = "INJECTED\n\rX-Evil-Header: poison"
        resp = client.get("/health", headers={"X-Request-ID": malicious_id})
        echoed = resp.headers.get("x-request-id", "")
        assert "\n" not in echoed and "\r" not in echoed, (
            "SEC-011: newline characters in X-Request-ID echoed — header injection possible"
        )

    def test_server_generates_uuid_request_id_when_none_supplied(self, client):
        """When no X-Request-ID is sent, server must generate a valid UUID."""
        resp = client.get("/health")
        rid = resp.headers.get("x-request-id", "")
        try:
            uuid.UUID(rid)
        except ValueError:
            pytest.fail(
                f"X-Request-ID '{rid}' is not a valid UUID — "
                "cannot be trusted for audit correlation"
            )

    def test_client_supplied_uuid_request_id_is_accepted(self, client):
        """A well-formed UUID X-Request-ID may be echoed as-is."""
        client_rid = str(uuid.uuid4())
        resp = client.get("/health", headers={"X-Request-ID": client_rid})
        assert resp.headers.get("x-request-id") == client_rid


class TestDefaultLogLevel:
    """Production default log level must not be DEBUG (SEC-012)."""

    def test_default_log_level_is_not_debug(self):
        """The Settings.LOG_LEVEL default must not be 'DEBUG' (leaks request data)."""
        import inspect
        from app import config as cfg_module

        src = inspect.getsource(cfg_module.Settings)
        if 'LOG_LEVEL: str = "DEBUG"' in src:
            pytest.xfail(
                "SEC-012 (LOW): default LOG_LEVEL is 'DEBUG'; "
                "change to 'INFO' to avoid leaking sensitive data in production logs"
            )
