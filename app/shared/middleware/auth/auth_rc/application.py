"""Adaptador de puzzle criptográfico para aplicaciones."""

import hashlib

from app.database.model import Application
from app.shared.middleware.auth.auth_rc.puzzle import PuzzleVerifier
from app.shared.middleware.auth.interface import IAuthMethod


class ApplicationAuth(IAuthMethod[Application]):
    """
    Extrae api_key de Application y delega al PuzzleVerifier.
    """

    def __init__(self):
        self.verifier = PuzzleVerifier()

    def authenticate(self, application: Application, puzzle) -> dict:
        if not application.api_key:
            return {"valid": False, "error": "Authentication failed"}

        try:
            key = self._normalize_key(application.api_key)
        except ValueError:  # pragma: no cover
            return {"valid": False, "error": "Invalid application api key"}

        return self.verifier.verify(key, puzzle, str(application.id))

    def get_auth_type(self) -> str:
        return "auth_rc"

    def _normalize_key(self, value: str) -> bytes:
        value = value.strip()

        try:
            raw = bytes.fromhex(value)
            if len(raw) == 32:
                return raw
        except ValueError:
            pass

        return hashlib.sha256(value.encode("utf-8")).digest()