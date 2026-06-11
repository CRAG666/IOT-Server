"""E2E login service — AES-256-GCM handshake (SEC-003/004/001)."""

from __future__ import annotations

import base64
import json
import secrets
from typing import Any

from sqlmodel import Session, select

from app.database.model import (
    Administrator,
    Manager,
    SensitiveData,
    User,
)
from app.shared.crypto import (
    aes_decrypt,
    aes_encrypt,
    derive_session_key,
    derive_temp_key,
    sha256_hex,
    verify_password,
)
from app.shared.e2e.session import E2ESessionRepository
from app.shared.exceptions import BadRequestException


_HUMAN_MODELS: dict[str, type] = {
    "administrator": Administrator,
    "manager": Manager,
    "user": User,
}


class LoginService:
    def __init__(self, db: Session, session_repo: E2ESessionRepository):
        self.db = db
        self.session_repo = session_repo

    async def get_challenge(self, email: str) -> dict[str, str]:
        """Return the per-user salt and a fresh server nonce.

        SEC-001: The client uses the salt to compute sha256(salt + sha256(password))
        before sending it.  Returning the salt before authentication is safe because
        the salt has no value without the actual password.
        """
        sensitive = self.db.exec(select(SensitiveData).where(SensitiveData.email == email)).first()
        # Return the same shape even if the user does not exist (prevents enumeration)
        salt = sensitive.password_salt if sensitive else secrets.token_hex(16)
        random_hex = secrets.token_hex(32)
        return {"salt": salt, "random": random_hex}

    async def login(
        self,
        username: str,
        payload_b64: str,
        random_hex: str,
        iv_b64: str,
    ) -> dict[str, str]:
        """Run the E2E login handshake and return ``{"payload": …, "iv": …}``.

        Protocol (v2 — AES-GCM + HKDF + salted passwords)
        ---------------------------------------------------
        1. Resolve *username* (email) → account + sensitive_data.
        2. Client sends sha256(plain_password); server applies salt:
           effective_hash = sha256(salt + client_sha256).
        3. temp_key = HKDF(ikm=effective_hash+random_hex, salt=user_salt,
                           info="iotmx-temp-key-v2").
        4. Decrypt client AES-GCM payload → extract random2.
        5. random3 = server random; session_key = HKDF(random2+random3,
                     info="iotmx-session-key-v2").
        6. Store session in Valkey; encrypt {random3, session_id} with temp_key.
        """
        resolved = self._resolve_username(username)
        if resolved is None:
            raise BadRequestException("Invalid credentials")

        entity, sensitive_data, account_type, is_master = resolved

        # The client sends sha256(plain_password) — apply the stored salt
        # to reconstruct the effective key material.
        # The client sends sha256(salt + sha256(password)) as the effective hash.
        # The server's stored password_hash is hash_password(password, salt) which equals
        # sha256(salt + sha256(password)) — same value, so we pass it directly as IKM.
        temp_key = derive_temp_key(
            password_sha256_hex=sensitive_data.password_hash,
            random_hex=random_hex,
            salt=sensitive_data.password_salt,
        )

        # Decrypt client payload (AES-GCM) → {"random2": "…"}
        try:
            ciphertext = base64.b64decode(payload_b64)
            iv = base64.b64decode(iv_b64)
            plaintext = aes_decrypt(ciphertext, temp_key, iv)
            inner: dict[str, str] = json.loads(plaintext.decode("utf-8"))
            random2: str = inner["random2"]
        except Exception as exc:
            raise BadRequestException("Invalid credentials") from exc

        if not random2:
            raise BadRequestException("Invalid credentials")

        random3 = secrets.token_hex(32)
        session_key_bytes = derive_session_key(random2, random3)

        account_context: dict[str, Any] = {
            "account_id": str(entity.id),
            "sensitive_data_id": str(sensitive_data.id),
            "account_type": account_type,
            "email": sensitive_data.email,
            "is_master": is_master,
            "auth_method": "e2e",
        }

        session_id = await self.session_repo.create_session(
            session_key_hex=session_key_bytes.hex(),
            account=account_context,
        )

        response_plain = json.dumps({"random3": random3, "session-id": session_id}).encode()
        enc_ciphertext, enc_iv = aes_encrypt(response_plain, temp_key)

        return {
            "payload": base64.b64encode(enc_ciphertext).decode("ascii"),
            "iv": base64.b64encode(enc_iv).decode("ascii"),
        }

    def _resolve_username(
        self,
        username: str,
    ) -> tuple[Any, SensitiveData, str, bool] | None:
        stmt = select(SensitiveData).where(SensitiveData.email == username)
        sensitive_data = self.db.exec(stmt).first()
        if not sensitive_data:
            return None

        for account_type, model in _HUMAN_MODELS.items():
            stmt2 = select(model).where(model.sensitive_data_id == sensitive_data.id)  # type: ignore[attr-defined]
            entity = self.db.exec(stmt2).first()
            if entity is not None:
                is_master = getattr(entity, "is_master", False)
                is_active = getattr(entity, "is_active", True)
                if not is_active:
                    return None
                return entity, sensitive_data, account_type, is_master

        return None
