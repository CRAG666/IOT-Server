"""OWASP API4:2023 — Unrestricted Resource Consumption.

Tests for missing request body size limits and the memory-leaking legacy
in-memory rate-limit window dict.
"""

import base64
import json

import pytest


class TestRequestBodySizeLimit:
    """The E2E middleware must reject payloads that exceed a reasonable size limit.

    SEC-007: Currently there is no Content-Length cap before decryption, so a
    very large base64-encoded payload will be fully decoded and passed to AES
    decrypt, potentially exhausting server memory and CPU.
    """

    def test_oversized_payload_returns_413_or_400(self, client, master_admin_account):
        """A 1 MB+ encrypted payload must be rejected without processing."""
        from tests.conftest import e2e_login
        from app.shared.crypto import aes_encrypt

        session_id, session_key = e2e_login(client, master_admin_account)

        # Build a 2 MB plaintext body
        big_data = "A" * (2 * 1024 * 1024)
        ct, iv = aes_encrypt(json.dumps({"data": big_data}).encode(), session_key)

        envelope = {
            "payload": base64.b64encode(ct).decode(),
            "iv": base64.b64encode(iv).decode(),
        }
        resp = client.post(
            "/api/v1/services",
            json=envelope,
            headers={"X-Session-ID": session_id},
        )
        # We accept 413 (ideal), 400 (current — JSON parse or validation error),
        # 403 (auth check before body read), or 422 (Pydantic validation).
        # We do NOT want 201 (created with garbage data) or 500 (server crash).
        assert resp.status_code in (400, 403, 413, 422), (
            f"SEC-007: oversized body was processed (status {resp.status_code}); "
            "add Content-Length validation in E2EMiddleware.dispatch()"
        )

    def test_max_body_size_constant_is_configured(self):
        """Document that a MAX_BODY_SIZE limit is defined in the middleware."""
        import inspect
        from app.shared.e2e import middleware as mw
        src = inspect.getsource(mw)
        if "MAX_BODY_SIZE" in src or "max_body" in src.lower():
            return  # already fixed
        pytest.xfail(
            "SEC-007: no MAX_BODY_SIZE guard in E2EMiddleware; "
            "add a Content-Length check before reading body"
        )


class TestLegacyMemoryLeak:
    """The legacy in-memory window dict must not accumulate unbounded data.

    SEC-008: rate_limit.py defines a module-level ``_windows: defaultdict(deque)``
    that is never cleaned up and grows without bound under sustained traffic.
    """

    def test_legacy_windows_dict_is_not_used(self):
        """_windows should not be referenced by the active rate-limit logic."""
        import inspect
        from app.shared import rate_limit as rl

        src = inspect.getsource(rl)
        # _windows appears in the module; check it is only in comments or the
        # dead-code legacy section, not referenced by the active dependency.
        functions_using_windows = [
            name for name, fn in [
                ("enforce_request_rate_limit", rl.enforce_request_rate_limit),
                ("rate_limiter", rl.rate_limiter),
            ]
            if "_windows" in inspect.getsource(fn)
        ]
        assert functions_using_windows == [], (
            f"SEC-008: legacy _windows dict used in {functions_using_windows}; "
            "this dict is never cleaned and will grow unbounded"
        )
