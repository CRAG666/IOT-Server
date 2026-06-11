"""FastAPI dependency helpers for authorization.

Type-level policy checks are delegated to
:mod:`app.shared.authorization.enforcer`. Instance-level row filtering is
handled by SQL views at the repository layer.
"""

from contextvars import ContextVar
from typing import TypeVar

from fastapi import Depends, HTTPException, status

from app.shared.authorization.enforcer import is_allowed
from app.shared.authorization.models import CurrentUser
from app.shared.auth.service import CurrentAccountDep


_current_user_ctx: ContextVar[CurrentUser | None] = ContextVar(
    "current_user", default=None
)

T = TypeVar("T")


def get_current_user_from_context() -> CurrentUser | None:
    """Return the ``CurrentUser`` stored in the current request context.

    Returns:
        The authenticated user, or ``None`` if called outside a request.
    """
    return _current_user_ctx.get()


def require_permission(action: str, resource_type: type[T]):
    """FastAPI dependency: enforce a Casbin permission, then expose the user.

    Args:
        action: ``"read"``, ``"write"``, or ``"delete"``.
        resource_type: the model class being accessed; its ``__name__`` is
            used as the Casbin resource string.

    Returns:
        A ``Depends``-wrapped callable that resolves to the ``CurrentUser``
        on success or raises HTTP 403.
    """
    def check(current: CurrentAccountDep) -> CurrentUser:
        user = CurrentUser.from_state_dict(current.__dict__)
        if not is_allowed(user.account_type, user.is_master, action, resource_type.__name__):
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail=f"Insufficient permissions: {action} on {resource_type.__name__}",
            )
        _current_user_ctx.set(user)
        return user

    return Depends(check)


def require_read(resource_type: type[T]):
    """Dependency: require ``read`` permission on *resource_type*."""
    return require_permission("read", resource_type)


def require_write(resource_type: type[T]):
    """Dependency: require ``write`` permission on *resource_type*."""
    return require_permission("write", resource_type)


def require_delete(resource_type: type[T]):
    """Dependency: require ``delete`` permission on *resource_type*."""
    return require_permission("delete", resource_type)


def require_administer(resource_type: type[T]):
    """Dependency: require ``administer`` permission on *resource_type*.

    ``administer`` is currently granted only to master admins (via ``*`` wildcard).
    """
    return require_permission("administer", resource_type)
