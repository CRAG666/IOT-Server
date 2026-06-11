"""FastAPI dependency: read tenant_id from request state."""

from typing import Annotated
from uuid import UUID

from fastapi import Depends, Request


def get_tenant_id(request: Request) -> UUID | None:
    """Return the tenant_id attached by TenantContextMiddleware, or None for master admins."""
    return getattr(request.state, "tenant_id", None)


TenantIdDep = Annotated[UUID | None, Depends(get_tenant_id)]
