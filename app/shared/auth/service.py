"""Authentication service — minimal shim for the E2E session protocol.

All JWT / token generation has been removed.  This module only provides:
- ``CurrentAccount`` dataclass (identity of an authenticated caller)
- ``get_current_account_from_request`` FastAPI dependency
- ``SharedAuthService.change_password``
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Annotated, Literal
from uuid import UUID

from fastapi import Depends, HTTPException, Request, status
from pydantic import BaseModel
from sqlmodel import Session

from app.database import SessionDep
from app.database.model import SensitiveData
from app.shared.auth.security import check_password
from app.shared.exceptions import BadRequestException


AccountType = Literal["administrator", "manager", "user", "device", "application"]


@dataclass
class CurrentAccount:
    account_id: UUID
    sensitive_data_id: UUID | None
    account_type: AccountType
    email: str | None
    is_master: bool = False
    auth_method: str | None = None


class ChangePasswordRequest(BaseModel):
    current_password: str
    new_password: str


class MessageResponse(BaseModel):
    message: str


class SharedAuthService:
    def __init__(self, session: Session):
        self.session = session

    def change_password(
        self,
        current: CurrentAccount,
        payload: ChangePasswordRequest,
    ) -> MessageResponse:
        if current.sensitive_data_id is None:
            raise BadRequestException("This entity does not use password authentication")

        sensitive_data = self.session.get(SensitiveData, current.sensitive_data_id)
        if sensitive_data is None:
            raise BadRequestException("Associated account was not found")

        if not check_password(payload.current_password, sensitive_data.password_salt, sensitive_data.password_hash):
            raise BadRequestException("Current password is incorrect")

        if check_password(payload.new_password, sensitive_data.password_salt, sensitive_data.password_hash):
            raise BadRequestException("New password must be different from current password")

        sensitive_data.password = payload.new_password
        self.session.add(sensitive_data)
        self.session.commit()

        return MessageResponse(message="Password updated successfully")


def get_current_account_from_request(request: Request) -> CurrentAccount:
    """FastAPI dependency: extract ``CurrentAccount`` from request state.

    The E2E middleware (or the DEBUG ``X-Test-Account`` bypass) populates
    ``request.state.current_account`` before route handlers run.
    """
    current = getattr(request.state, "current_account", None)

    if not isinstance(current, dict):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Not authenticated",
        )

    try:
        sensitive_data_id = current.get("sensitive_data_id")
        return CurrentAccount(
            account_id=UUID(current["account_id"]),
            sensitive_data_id=UUID(sensitive_data_id) if sensitive_data_id else None,
            account_type=current["account_type"],
            email=current.get("email"),
            is_master=bool(current.get("is_master", False)),
            auth_method=current.get("auth_method"),
        )
    except (KeyError, ValueError, TypeError) as exc:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid authentication context",
        ) from exc


CurrentAccountDep = Annotated[CurrentAccount, Depends(get_current_account_from_request)]


def get_shared_auth_service(session: SessionDep) -> SharedAuthService:
    return SharedAuthService(session)


SharedAuthServiceDep = Annotated[SharedAuthService, Depends(get_shared_auth_service)]
