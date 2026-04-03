from fastapi import APIRouter

from app.domain.auth.schemas import (
    ChangePasswordRequest,
    LoginRequest,
    MessageResponse,
    TokenResponse,
)
from app.domain.auth.service import AuthServiceDep, CurrentAccountDep

auth_router = APIRouter(prefix="/auth", tags=["Auth"])


@auth_router.post("/login", response_model=TokenResponse)
def login(payload: LoginRequest, service: AuthServiceDep):
    return service.login(payload)


@auth_router.patch("/change-password", response_model=MessageResponse)
def change_password(
    payload: ChangePasswordRequest,
    service: AuthServiceDep,
    current: CurrentAccountDep,
):
    return service.change_password(current, payload)