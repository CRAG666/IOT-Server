from __future__ import annotations

from app.database.model import Administrator, Manager, SensitiveData, User
from app.shared.auth.security import verify_password
from app.shared.middleware.auth.interface import IAuthMethod


class HumanPasswordAuth(IAuthMethod):
    """
    Autenticación humana con switch por entidad.

    Atiende:
    - user
    - manager
    - administrator

    La entidad ya viene resuelta desde el repository.
    """

    def authenticate(self, entity, request_data) -> dict:
        account_type = request_data.get("account_type")
        sensitive_data: SensitiveData = request_data.get("sensitive_data")
        password: str = request_data.get("password")

        if account_type == "administrator":
            return self._authenticate_administrator(entity, sensitive_data, password)

        if account_type == "manager":
            return self._authenticate_manager(entity, sensitive_data, password)

        if account_type == "user":
            return self._authenticate_user(entity, sensitive_data, password)

        return {"valid": False, "error": "Invalid human entity type"}

    def get_auth_type(self) -> str:
        return "human_password"

    def _authenticate_administrator(
        self,
        entity: Administrator,
        sensitive_data: SensitiveData,
        password: str,
    ) -> dict:
        if not isinstance(entity, Administrator):
            return {"valid": False, "error": "Invalid administrator account"}

        return self._verify_common(entity, sensitive_data, password)

    def _authenticate_manager(
        self,
        entity: Manager,
        sensitive_data: SensitiveData,
        password: str,
    ) -> dict:
        if not isinstance(entity, Manager):
            return {"valid": False, "error": "Invalid manager account"}

        return self._verify_common(entity, sensitive_data, password)

    def _authenticate_user(
        self,
        entity: User,
        sensitive_data: SensitiveData,
        password: str,
    ) -> dict:
        if not isinstance(entity, User):
            return {"valid": False, "error": "Invalid user account"}

        return self._verify_common(entity, sensitive_data, password)

    def _verify_common(
        self,
        entity,
        sensitive_data: SensitiveData,
        password: str,
    ) -> dict:
        if sensitive_data is None:
            return {"valid": False, "error": "Invalid credentials"}

        if not verify_password(password, sensitive_data.password_salt, sensitive_data.password_hash):
            return {"valid": False, "error": "Invalid credentials"}

        if hasattr(entity, "is_active") and not entity.is_active:
            return {"valid": False, "error": "Account is inactive"}

        return {"valid": True}