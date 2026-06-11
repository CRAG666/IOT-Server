"""Schemas for the E2E login / renew / logout endpoints."""

from pydantic import BaseModel


class LoginRequest(BaseModel):
    """Client → server login payload.

    The client:
    1. Computes ``temp_key = sha256(sha256(password) + random)``.
    2. Generates ``random2`` (a fresh nonce).
    3. Encrypts ``{"random2": "<random2>"}`` using AES-256-CBC with *temp_key*
       and a random *iv*.
    4. Sends this request.
    """

    username: str
    payload: str  # base64 AES-256-CBC ciphertext of {"random2": "…"}
    random: str   # hex nonce used to derive the temp key
    iv: str       # base64 IV used to encrypt the payload


class LoginResponse(BaseModel):
    """Server → client login response.

    The server encrypts ``{"random3": "…", "session-id": "…"}`` with the same
    *temp_key* (new IV) and returns this.  The client computes
    ``session_key = sha256(random2 + random3)`` and stores *session_id*.
    """

    payload: str  # base64 AES-256-CBC ciphertext
    iv: str       # base64 IV


class RenewResponse(BaseModel):
    """Response from the session-renewal endpoint (body is still encrypted)."""

    new_session_id: str


class MessageResponse(BaseModel):
    message: str
