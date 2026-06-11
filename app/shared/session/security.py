import base64
import hashlib
import hmac
import json
import secrets
from datetime import datetime, timedelta, timezone
from typing import Any

from jose import jwe
from jose.exceptions import JWEError


class SessionHMAC:
    """HMAC operations for entity session request verification."""

    @staticmethod
    def compute_hmac(session_id: str, payload: str, key_session: str) -> str:
        """Compute HMAC-SHA256 tag for request integrity verification."""
        try:
            key_bytes = base64.urlsafe_b64decode(key_session)
        except Exception as e:
            raise ValueError(f"Invalid key_session for HMAC: {e}") from e

        message = f"{session_id}:{payload}".encode("utf-8")
        signature = hmac.new(key_bytes, message, hashlib.sha256).digest()

        return base64.urlsafe_b64encode(signature).decode().rstrip("=")

    @staticmethod
    def verify_hmac(
        session_id: str,
        payload: str,
        tag: str,
        key_session: str,
    ) -> bool:
        """Verify HMAC tag using constant-time comparison."""
        expected_tag = SessionHMAC.compute_hmac(session_id, payload, key_session)
        return secrets.compare_digest(tag, expected_tag)


class JWEHandler:
    """JWE encryption/decryption for legacy user session tokens."""
    def __init__(self, encryption_key: str):
        try:
            key_bytes = base64.b64decode(encryption_key)
        except Exception as e:
            raise ValueError(f"ENCRYPTION_KEY must be valid base64: {e}")

        if len(key_bytes) != 32:
            raise ValueError(
                f"ENCRYPTION_KEY must be exactly 32 bytes when decoded, got {len(key_bytes)} bytes"
            )

        self.encryption_key = key_bytes

    def encrypt(self, claims: dict[str, Any], ttl_minutes: int = 30) -> str:
        now = datetime.now(timezone.utc)
        exp_timestamp = int((now + timedelta(minutes=ttl_minutes)).timestamp())
        iat_timestamp = int(now.timestamp())

        claims_with_timestamps = {
            **claims,
            "exp": exp_timestamp,
            "iat": iat_timestamp,
        }

        payload_json = json.dumps(claims_with_timestamps)

        encrypted = jwe.encrypt(
            plaintext=payload_json.encode(),
            key=self.encryption_key,
            algorithm="dir",
            encryption="A256GCM",
        )

        if isinstance(encrypted, bytes):
            return encrypted.decode()
        return encrypted  # pragma: no cover

    def decrypt(self, token: str) -> dict[str, Any]:
        decrypted = jwe.decrypt(token.encode(), self.encryption_key)

        try:
            claims = json.loads(decrypted.decode())
        except json.JSONDecodeError as e:
            raise JWEError(f"Invalid JSON payload in token: {e}")

        if not self.verify_expiration(claims):
            raise JWEError("Token has expired")

        return claims

    def verify_expiration(self, claims: dict[str, Any]) -> bool:
        exp = claims.get("exp")
        if not exp or not isinstance(exp, (int, float)):
            return False

        now_timestamp = int(datetime.now(timezone.utc).timestamp())
        return exp > now_timestamp
