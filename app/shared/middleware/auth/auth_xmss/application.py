from app.database.model import Application
from app.shared.middleware.auth.auth_xmss.challenge import XMSSChallengeFactory
from app.shared.middleware.auth.interface import IAuthMethod


class ApplicationXMSSAuth(IAuthMethod[Application]):  # pragma: no cover
    def __init__(self):
        self.verifier = XMSSChallengeFactory()

    def authenticate(self, application: Application, request_data) -> dict:
        payload = request_data.get("payload")
        public_root = request_data.get("public_root")

        if not public_root:
            return {"valid": False, "error": "XMSS root is not configured"}

        if hasattr(application, "is_active") and not application.is_active:
            return {"valid": False, "error": "Application is inactive"}

        is_valid = self.verifier.verify_payload(
            payload=payload,
            public_root=public_root,
        )

        if not is_valid:
            return {"valid": False, "error": "Invalid XMSS signature"}

        return {"valid": True}

    def get_auth_type(self) -> str:
        return "auth_xmss"