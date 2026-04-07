from typing import TypeVar, Annotated
from fastapi import Depends, HTTPException, status

from app.shared.authorization.oso_config import get_oso
from app.shared.authorization.models import CurrentUser
from app.domain.auth.service import CurrentAccountDep


T = TypeVar("T")


def require_oso_permission(action: str, resource_type: type[T]):
    def check_permission(current: CurrentAccountDep) -> CurrentUser:
        user = CurrentUser.from_state_dict(current.__dict__)
        oso = get_oso()
        allowed = oso.is_allowed(user, action, resource_type)
        
        if not allowed:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail=f"Insufficient permissions: {action} on {resource_type.__name__}",
            )
        
        return user
    
    return Depends(check_permission)


def require_read(resource_type: type[T]):
    return require_oso_permission("read", resource_type)


def require_write(resource_type: type[T]):
    return require_oso_permission("write", resource_type)


def require_delete(resource_type: type[T]):
    return require_oso_permission("delete", resource_type)


def require_administer(resource_type: type[T]):
    return require_oso_permission("administer", resource_type)

