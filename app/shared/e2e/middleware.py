"""E2E AES-256-CBC middleware.

Every protected endpoint must arrive with an *X-Session-ID* header.  The
middleware:

1. Looks up the session key from Valkey (or the test override repo).
2. Sets ``request.state.current_account`` so Casbin dependencies can read it.
3. For POST / PUT / PATCH requests: decrypts the ``{"payload": "…", "iv":
   "…"}`` JSON body (base64-encoded AES-256-CBC ciphertext) and replaces the
   request body with the plaintext before handing off to the route handler.
4. Collects the route handler's response, encrypts it with the same session
   key, and returns ``{"payload": "…", "iv": "…"}``.

Test injection
--------------
Set ``_session_repo_override`` to an ``E2ESessionRepository`` backed by
``fakeredis`` before running tests.  The middleware will use it instead of the
real Valkey connection so the full E2E crypto stack runs without a live server.
"""

from __future__ import annotations

import base64
import json
import logging

from fastapi import status
from starlette.middleware.base import BaseHTTPMiddleware
from starlette.requests import Request
from starlette.responses import JSONResponse, Response

from app.config import settings
from app.shared.crypto import aes_decrypt, aes_encrypt
from app.shared.e2e.session import E2ESessionRepository

logger = logging.getLogger(__name__)

# Injected by test fixtures; always None in production.
_session_repo_override: E2ESessionRepository | None = None

# SEC-007: maximum raw request body size accepted before decryption.
# A 1 MB limit prevents memory exhaustion from oversized AES payloads.
MAX_BODY_SIZE: int = 1 * 1024 * 1024  # 1 MB

PUBLIC_PATHS: frozenset[str] = frozenset(
    {
        "/docs",
        "/openapi.json",
        "/redoc",
        "/health",
        "/ready",
        "/metrics",
        "/api/v1/auth/login",
        "/api/v1/auth/challenge",
        "/api/v1/onboarding/register",
        "/api/v1/onboarding/verify",
    }
)


class E2EMiddleware(BaseHTTPMiddleware):
    """Request/response E2E encryption middleware."""

    def __init__(self, app, valkey_url: str | None = None):
        super().__init__(app)
        url = valkey_url or settings.VALKEY_URL
        self.session_repo = E2ESessionRepository(url)

    def _repo(self) -> E2ESessionRepository:
        return _session_repo_override if _session_repo_override is not None else self.session_repo

    async def dispatch(self, request: Request, call_next) -> Response:
        path = request.url.path

        if (
            path in PUBLIC_PATHS
            or path.startswith("/docs")
            or path.startswith("/redoc")
        ):
            return await call_next(request)

        # ── Session lookup ───────────────────────────────────────────────────
        session_id = request.headers.get("X-Session-ID")
        if not session_id:
            # No session header — pass through with no current_account.
            # Endpoints that require auth will reject via their own dependency.
            request.state.current_account = None
            return await call_next(request)

        try:
            session = await self._repo().get_session(session_id)
        except Exception:
            logger.exception("Valkey unavailable during session lookup")
            return JSONResponse(
                status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
                content={"detail": "Session service unavailable"},
            )

        if not session:
            return JSONResponse(
                status_code=status.HTTP_401_UNAUTHORIZED,
                content={"detail": "Invalid or expired session"},
            )

        session_key: bytes = bytes.fromhex(session["session_key"])
        request.state.current_account = session["account"]

        # ── Decrypt request body (mutating methods only) ─────────────────────
        if request.method in {"POST", "PUT", "PATCH"}:
            content_length = request.headers.get("content-length")
            if content_length and int(content_length) > MAX_BODY_SIZE:
                return JSONResponse(
                    status_code=status.HTTP_413_CONTENT_TOO_LARGE,
                    content={"detail": "Request body too large"},
                )
            body = await request.body()
            if len(body) > MAX_BODY_SIZE:
                return JSONResponse(
                    status_code=status.HTTP_413_CONTENT_TOO_LARGE,
                    content={"detail": "Request body too large"},
                )
            if body:
                decrypted = self._decrypt_body(body, session_key)
                if decrypted is None:
                    return JSONResponse(
                        status_code=status.HTTP_400_BAD_REQUEST,
                        content={"detail": "Invalid encrypted payload"},
                    )
                request._body = decrypted  # type: ignore[attr-defined]

        # ── Route handler ────────────────────────────────────────────────────
        response = await call_next(request)

        # ── Encrypt response ─────────────────────────────────────────────────
        raw_body = b""
        async for chunk in response.body_iterator:
            raw_body += chunk

        ciphertext, iv = aes_encrypt(raw_body, session_key)
        encrypted = {
            "payload": base64.b64encode(ciphertext).decode("ascii"),
            "iv": base64.b64encode(iv).decode("ascii"),
        }
        headers = dict(response.headers)
        headers.pop("content-length", None)
        return JSONResponse(
            content=encrypted,
            status_code=response.status_code,
            headers={k: v for k, v in headers.items() if k.lower() != "content-length"},
        )

    @staticmethod
    def _decrypt_body(body: bytes, session_key: bytes) -> bytes | None:
        try:
            envelope = json.loads(body)
            payload_b64: str = envelope["payload"]
            iv_b64: str = envelope["iv"]
            ciphertext = base64.b64decode(payload_b64)
            iv = base64.b64decode(iv_b64)
            return aes_decrypt(ciphertext, session_key, iv)
        except Exception:
            return None
