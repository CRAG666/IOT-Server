from uuid import UUID
import logging

from fastapi import status
from sqlmodel import Session
from starlette.middleware.base import BaseHTTPMiddleware
from starlette.requests import Request
from starlette.responses import JSONResponse

from app.database import engine
from app.database.model import Administrator, Manager, User
from app.domain.auth.security import decode_access_token


PUBLIC_PATHS = {
    "/docs",
    "/openapi.json",
    "/redoc",
    "/api/v1/auth/login",
}

logger = logging.getLogger(__name__)


class Human(BaseHTTPMiddleware):
    async def dispatch(self, request: Request, call_next):
        path = request.url.path

        if path in PUBLIC_PATHS or path.startswith("/docs") or path.startswith("/redoc"):
            return await call_next(request)

        request.state.current_account = None

        auth_header = request.headers.get("Authorization")
        if not auth_header:
            return await call_next(request)

        if not auth_header.startswith("Bearer "):
            return JSONResponse(
                status_code=status.HTTP_401_UNAUTHORIZED,
                content={"detail": "Formato de token inválido"},
            )

        token = auth_header.replace("Bearer ", "", 1).strip()

        try:
            payload = decode_access_token(token)

            raw_account_id = payload.get("sub")
            account_type = payload.get("type")
            email = payload.get("email")
            is_master = bool(payload.get("is_master", False))

            if not raw_account_id:
                return JSONResponse(
                    status_code=status.HTTP_401_UNAUTHORIZED,
                    content={"detail": "Token sin identificador de cuenta"},
                )

            if account_type not in {"administrator", "manager", "user"}:
                return JSONResponse(
                    status_code=status.HTTP_401_UNAUTHORIZED,
                    content={"detail": "Tipo de cuenta inválido en el token"},
                )

            model_map = {
                "administrator": Administrator,
                "manager": Manager,
                "user": User,
            }

            account_id = UUID(str(raw_account_id))

            with Session(engine) as session:
                account = session.get(model_map[account_type], account_id)

                if account is None:
                    return JSONResponse(
                        status_code=status.HTTP_401_UNAUTHORIZED,
                        content={"detail": "La cuenta del token no existe"},
                    )

                # Ojo: si is_active en tu modelo es property derivada y falla, quita este bloque
                if hasattr(account, "is_active") and not account.is_active:
                    return JSONResponse(
                        status_code=status.HTTP_401_UNAUTHORIZED,
                        content={"detail": "La cuenta está inactiva"},
                    )

                request.state.current_account = {
                    "account_id": str(account.id),
                    "sensitive_data_id": str(account.sensitive_data_id),
                    "account_type": account_type,
                    "email": email,
                    "is_master": is_master,
                }

        except Exception:
            logger.exception("Error no controlado en middleware de autenticacion")
            return JSONResponse(
                status_code=status.HTTP_401_UNAUTHORIZED,
                content={"detail": "Token inválido o expirado"},
            )

        return await call_next(request)