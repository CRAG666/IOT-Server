"""Authentication endpoints for the E2E AES-256-GCM session protocol (v2)."""

from __future__ import annotations

from typing import Annotated

from fastapi import APIRouter, Depends, HTTPException, Request, status

from app.config import settings
from app.database import SessionDep
from app.domain.auth.schemas import LoginRequest, LoginResponse, MessageResponse
from app.domain.auth.service import LoginService
from app.shared.auth.service import CurrentAccountDep, ChangePasswordRequest
from app.shared.e2e.session import E2ESessionRepository
from app.shared.exceptions import BadRequestException
from app.shared.rate_limit import enforce_request_rate_limit


auth_router = APIRouter(
    prefix="/auth",
    tags=["Auth"],
    dependencies=[Depends(enforce_request_rate_limit)],
)


def _get_session_repo() -> E2ESessionRepository:
    return E2ESessionRepository(settings.VALKEY_URL)


SessionRepoDep = Annotated[E2ESessionRepository, Depends(_get_session_repo)]


# ─────────────────────────────────────────────────────────────────────────────
# Challenge (SEC-001: client needs salt before computing temp_key)
# ─────────────────────────────────────────────────────────────────────────────


@auth_router.get(
    "/challenge",
    response_model=dict,
    include_in_schema=True,
)
async def challenge(email: str, db: SessionDep, repo: SessionRepoDep) -> dict:
    """Return the per-user password salt and a server nonce.

    The client must call this before ``/login`` to obtain the salt needed to
    compute sha256(salt + sha256(plain_password)) for the handshake.
    The response is always HTTP 200 regardless of whether the email exists to
    prevent user enumeration.
    """
    try:
        service = LoginService(db, repo)
        return await service.get_challenge(email)
    finally:
        await repo.close()


# ─────────────────────────────────────────────────────────────────────────────
# Login
# ─────────────────────────────────────────────────────────────────────────────


@auth_router.post("/login", response_model=LoginResponse)
async def login(
    request_body: LoginRequest,
    db: SessionDep,
    repo: SessionRepoDep,
) -> LoginResponse:
    """E2E login handshake.

    The client supplies an AES-256-CBC encrypted payload (keyed from a
    temporary key derived from the stored password hash and a client nonce).
    The server returns the session key material encrypted with the same
    temporary key.
    """
    try:
        service = LoginService(db, repo)
        result = await service.login(
            username=request_body.username,
            payload_b64=request_body.payload,
            random_hex=request_body.random,
            iv_b64=request_body.iv,
        )
        return LoginResponse(**result)
    except BadRequestException as exc:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail=str(exc),
        ) from exc
    finally:
        await repo.close()


# ─────────────────────────────────────────────────────────────────────────────
# Logout
# ─────────────────────────────────────────────────────────────────────────────


@auth_router.post("/logout", response_model=MessageResponse)
async def logout(request: Request, repo: SessionRepoDep) -> MessageResponse:
    """Terminate the current E2E session."""
    session_id = request.headers.get("X-Session-ID")
    if not session_id:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Missing X-Session-ID header",
        )
    try:
        await repo.delete_session(session_id)
        return MessageResponse(message="Logged out successfully")
    finally:
        await repo.close()


# ─────────────────────────────────────────────────────────────────────────────
# Session renewal
# ─────────────────────────────────────────────────────────────────────────────


@auth_router.post("/renew", response_model=dict)
async def renew_session(request: Request, repo: SessionRepoDep) -> dict:
    """Issue a new session ID with a fresh TTL; invalidate the old one.

    The response is automatically encrypted by the E2E middleware because this
    endpoint sits behind it.  The plaintext JSON is ``{"new_session_id": "…"}``.
    """
    session_id = request.headers.get("X-Session-ID")
    if not session_id:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Missing X-Session-ID header",
        )
    try:
        new_id = await repo.renew_session(session_id)
        if not new_id:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Session not found or already expired",
            )
        return {"new_session_id": new_id}
    finally:
        await repo.close()


# ─────────────────────────────────────────────────────────────────────────────
# Change password
# ─────────────────────────────────────────────────────────────────────────────


@auth_router.patch("/change-password", response_model=MessageResponse)
def change_password(
    payload: ChangePasswordRequest,
    current: CurrentAccountDep,
    db: SessionDep,
) -> MessageResponse:
    """Change the authenticated user's password."""
    from app.shared.auth.service import SharedAuthService

    service = SharedAuthService(db)
    return service.change_password(current, payload)
