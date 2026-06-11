from app.database.model import Device
from app.shared.middleware.auth.auth_xmss.challenge import XMSSChallengeFactory
from app.shared.middleware.auth.interface import IAuthMethod


class DeviceXMSSAuth(IAuthMethod[Device]):  # pragma: no cover
    def __init__(self):
        self.verifier = XMSSChallengeFactory()

    def authenticate(self, device: Device, request_data) -> dict:
        payload = request_data.get("payload")
        public_root = request_data.get("public_root")

        if not public_root:
            return {"valid": False, "error": "XMSS root is not configured"}

        if hasattr(device, "is_active") and not device.is_active:
            return {"valid": False, "error": "Device is inactive"}

        is_valid = self.verifier.verify_payload(
            payload=payload,
            public_root=public_root,
        )

        if not is_valid:
            return {"valid": False, "error": "Invalid XMSS signature"}

        return {"valid": True}

    def get_auth_type(self) -> str:
        return "auth_xmss"