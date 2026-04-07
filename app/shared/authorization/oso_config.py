from pathlib import Path
from oso import Oso

from app.shared.authorization.models import CurrentUser
from app.database.model import (
    Device,
    User,
    Administrator,
    Manager,
    Service,
    Application,
    ServiceTicket,
    EcosystemTicket,
)


_oso_instance: Oso | None = None


def init_oso() -> Oso:
    oso = Oso()
    
    oso.register_class(CurrentUser)
    oso.register_class(Device)
    oso.register_class(User)
    oso.register_class(Administrator)
    oso.register_class(Manager)
    oso.register_class(Service)
    oso.register_class(Application)
    oso.register_class(ServiceTicket)
    oso.register_class(EcosystemTicket)
    oso.register_class(ServiceTicket, name="Ticket")
    
    policy_dir = Path(__file__).parent
    policy_file = policy_dir / "policies.polar"
    
    if not policy_file.exists():
        raise FileNotFoundError(f"Policy file not found: {policy_file}")
    
    oso.load_files([str(policy_file)])
    
    return oso


def get_oso() -> Oso:
    global _oso_instance
    
    if _oso_instance is None:
        _oso_instance = init_oso()
    
    return _oso_instance


def reload_policies() -> None:
    """
    Reload policies from disk.
    
    This is useful during development or when policies are updated
    dynamically. In production, policies are typically loaded once
    at startup.
    
    Warning:
        This will affect all subsequent authorization checks.
    """
    global _oso_instance
    _oso_instance = init_oso()
