from dataclasses import dataclass
from typing import Annotated, Literal
from uuid import UUID

from fastapi import Depends, HTTPException, Request, status
from fastapi.security import HTTPBearer
from sqlmodel import Session, select

from app.database import SessionDep
from app.database.model import SensitiveData
from app.domain.auth.schemas import (
    ChangePasswordRequest,
    LoginRequest,
    MessageResponse,
    TokenResponse,
)
from app.domain.auth.security import (
    create_access_token,
    get_password_hash,
    verify_password,
)
from app.shared.exceptions import BadRequestException


AccountType = Literal["administrator", "manager", "user"]

# Solo para Swagger / OpenAPI
bearer_scheme = HTTPBearer()


@dataclass
class CurrentAccount:
    account_id: UUID
    sensitive_data_id: UUID
    account_type: AccountType
    email: str
    is_master: bool = False


class AuthService:
    def __init__(self, session: Session):
        self.session = session

    def _resolve_account(self, sensitive_data: SensitiveData):
        if sensitive_data.administrator is not None:
            account = sensitive_data.administrator
            return account, "administrator", bool(account.is_master)

        if sensitive_data.manager is not None:
            account = sensitive_data.manager
            return account, "manager", False

        if sensitive_data.user is not None:
            account = sensitive_data.user
            return account, "user", False

        return None, None, False

    def login(self, payload: LoginRequest) -> TokenResponse:
        stmt = select(SensitiveData).where(SensitiveData.email == payload.email)
        sensitive_data = self.session.exec(stmt).first()

        if sensitive_data is None:
            raise BadRequestException("Credenciales inválidas")

        if not verify_password(payload.password, sensitive_data.password_hash):
            raise BadRequestException("Credenciales inválidas")

        account, account_type, is_master = self._resolve_account(sensitive_data)
        if account is None or account_type is None:
            raise BadRequestException("La cuenta no tiene un perfil asociado")

        if not account.is_active:
            raise BadRequestException("La cuenta está inactiva")

        token = create_access_token(
            {
                "sub": str(account.id),
                "email": sensitive_data.email,
                "type": account_type,
                "is_master": is_master,
            }
        )

        return TokenResponse(
            access_token=token,
            account_type=account_type,
            is_master=is_master,
        )

    def change_password(
        self,
        current: CurrentAccount,
        payload: ChangePasswordRequest,
    ) -> MessageResponse:
        sensitive_data = self.session.get(SensitiveData, current.sensitive_data_id)
        if sensitive_data is None:
            raise BadRequestException("No se encontró la cuenta asociada")

        if not verify_password(payload.current_password, sensitive_data.password_hash):
            raise BadRequestException("La contraseña actual no es correcta")

        sensitive_data.password_hash = get_password_hash(payload.new_password)
        self.session.add(sensitive_data)
        self.session.commit()
        self.session.refresh(sensitive_data)

        return MessageResponse(message="Contraseña actualizada correctamente")


def get_auth_service(session: SessionDep) -> AuthService:
    return AuthService(session)


AuthServiceDep = Annotated[AuthService, Depends(get_auth_service)]


def get_current_account_from_request(request: Request) -> CurrentAccount:
    current = getattr(request.state, "current_account", None)

    if not isinstance(current, dict):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="No autenticado",
        )

    try:
        return CurrentAccount(
            account_id=UUID(current["account_id"]),
            sensitive_data_id=UUID(current["sensitive_data_id"]),
            account_type=current["account_type"],
            email=current["email"],
            is_master=bool(current["is_master"]),
        )
    except (KeyError, ValueError, TypeError) as exc:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Contexto de autenticación inválido",
        ) from exc


CurrentAccountDep = Annotated[
    CurrentAccount,
    Depends(get_current_account_from_request),
]


def require_authenticated(
    _: Annotated[object, Depends(bearer_scheme)],
    current: CurrentAccountDep,
) -> CurrentAccount:
    return current


def require_admin(
    _: Annotated[object, Depends(bearer_scheme)],
    current: CurrentAccountDep,
) -> CurrentAccount:
    if current.account_type != "administrator":
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Se requieren privilegios de administrador",
        )
    return current


def require_master_admin(
    _: Annotated[object, Depends(bearer_scheme)],
    current: CurrentAccountDep,
) -> CurrentAccount:
    if current.account_type != "administrator" or not current.is_master:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Se requieren privilegios de administrador master",
        )
    return current


def require_admin_or_manager(
    _: Annotated[object, Depends(bearer_scheme)],
    current: CurrentAccountDep,
) -> CurrentAccount:
    if current.account_type not in {"administrator", "manager"}:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Se requieren privilegios de administrador o gerente",
        )
    return current