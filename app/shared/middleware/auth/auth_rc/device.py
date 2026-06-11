"""Adaptador de puzzle criptográfico para dispositivos."""

import hashlib

from app.database.model import Device
from app.shared.middleware.auth.auth_rc.puzzle import PuzzleVerifier
from app.shared.middleware.auth.interface import IAuthMethod


class DeviceAuth(IAuthMethod[Device]):
    """
    Extrae encryption_key del Device y delega al PuzzleVerifier.
    """

    def __init__(self):
        self.verifier = PuzzleVerifier()

    def authenticate(self, device: Device, puzzle) -> dict:
        if not device.encryption_key:
            return {"valid": False, "error": "Authentication failed"}

        try:
            key = self._normalize_key(device.encryption_key)
        except ValueError:  # pragma: no cover
            return {"valid": False, "error": "Invalid device encryption key"}

        return self.verifier.verify(key, puzzle, str(device.id))

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