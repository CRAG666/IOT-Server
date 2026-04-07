from app.shared.authorization.dependencies import (
    require_oso_permission,
    require_read,
    require_write,
    require_delete,
    require_administer,
)
from app.shared.authorization.models import CurrentUser
from app.shared.authorization.oso_config import get_oso

__all__ = [
    "require_oso_permission",
    "require_read",
    "require_write",
    "require_delete",
    "require_administer",
    "CurrentUser",
    "get_oso",
]
