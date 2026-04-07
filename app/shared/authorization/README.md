# Authorization

RBAC implementation using OSO policy engine.

## Structure

```
app/shared/authorization/
├── __init__.py           # Public API
├── models.py             # CurrentUser dataclass
├── policies.polar        # Authorization rules
├── oso_config.py         # OSO initialization
└── dependencies.py       # FastAPI dependencies
```

## Usage

```python
from app.shared.authorization import require_read, require_write, require_delete
from app.database.model import Device

class DeviceController(FullCrudApiController):
    list_dependencies = [require_read(Device)]
    create_dependencies = [require_write(Device)]
    delete_dependencies = [require_delete(Device)]
```

## Available Dependencies

- `require_read(ResourceType)` - Read permission
- `require_write(ResourceType)` - Write permission
- `require_delete(ResourceType)` - Delete permission
- `require_administer(ResourceType)` - Administration permission

## Policies

Policies are defined in `policies.polar` using Polar language. The authorization rules implement a role-based access control system with four roles:

- **Master Administrator**: Full system access
- **Administrator**: Manage resources except administrators
- **Manager**: Create and modify resources, cannot delete
- **User**: Read-only access, can create tickets

## Integration

Authorization is enforced at the Controller layer via FastAPI dependencies. Service and Repository layers remain unchanged.
