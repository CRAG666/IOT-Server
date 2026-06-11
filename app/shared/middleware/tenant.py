"""TenantContext middleware.

Runs after E2EMiddleware.  If the authenticated account is an Administrator it
looks up their tenant_id from the SQL DB and attaches it to request.state so
route handlers and services can filter data by tenant without re-querying.

Master admins have no tenant_id (they are system-wide) and their
request.state.tenant_id is set to None.
"""

from __future__ import annotations

import logging
from uuid import UUID

from sqlmodel import Session, select
from starlette.middleware.base import BaseHTTPMiddleware
from starlette.requests import Request
from starlette.responses import Response

from app.database import engine

logger = logging.getLogger(__name__)


class TenantContextMiddleware(BaseHTTPMiddleware):
    async def dispatch(self, request: Request, call_next) -> Response:
        tenant_id: UUID | None = None

        account = getattr(request.state, "current_account", None)
        if account and account.get("account_type") == "administrator":
            from app.database.model import Administrator

            account_id = account.get("account_id")
            if account_id and not account.get("is_master"):
                try:
                    with Session(engine) as session:
                        admin = session.exec(
                            select(Administrator).where(Administrator.id == UUID(account_id))
                        ).first()
                        if admin:
                            tenant_id = admin.tenant_id
                except Exception:
                    logger.exception("TenantContextMiddleware: failed to resolve tenant_id")

        request.state.tenant_id = tenant_id
        return await call_next(request)
