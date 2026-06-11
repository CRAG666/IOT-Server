"""Casbin-based authorization enforcer for the IoTmx platform.

Type-level RBAC decisions live here. Instance-level row filtering is
delegated to the SQL views in ``app/database/views.py``.

Policy rules are persisted in the ``casbin_rule`` database table via
``casbin-sqlalchemy-adapter``.  On first boot the table is seeded from
``policy.csv``; from that point on the master admin may modify rules through
the ``/api/v1/policies`` endpoints without touching the file.
"""

from pathlib import Path

import casbin

_POLICY_DIR = Path(__file__).parent
_enforcer: casbin.Enforcer | None = None


def _seed_if_empty(enforcer: casbin.Enforcer) -> None:
    """Populate the DB-backed policy from policy.csv if the table is empty."""
    if enforcer.get_policy():
        return
    policy_path = _POLICY_DIR / "policy.csv"
    with open(policy_path) as fh:
        for raw in fh:
            line = raw.strip()
            if not line or line.startswith("#"):
                continue
            parts = [p.strip() for p in line.split(",")]
            if len(parts) >= 4 and parts[0] == "p":
                enforcer.add_policy(parts[1], parts[2], parts[3])


def _build_enforcer() -> casbin.Enforcer:
    from casbin_sqlalchemy_adapter import Adapter
    from app.config import settings

    adapter = Adapter(settings.DATABASE_URL)
    e = casbin.Enforcer(str(_POLICY_DIR / "model.conf"), adapter)
    _seed_if_empty(e)
    return e


def get_enforcer() -> casbin.Enforcer:
    """Return the shared Casbin Enforcer (lazy singleton, DB-backed)."""
    global _enforcer
    if _enforcer is None:
        _enforcer = _build_enforcer()
    return _enforcer


def reset_enforcer() -> None:
    """Discard the cached enforcer so the next call rebuilds it.

    Used in tests to get a clean enforcer against a fresh database.
    """
    global _enforcer
    _enforcer = None


def _role_for(account_type: str, is_master: bool) -> str:
    """Map account credentials to a Casbin role string."""
    if account_type == "administrator" and is_master:
        return "master_admin"
    return account_type


def is_allowed(account_type: str, is_master: bool, action: str, resource: str) -> bool:
    """Check whether an account may perform *action* on *resource*.

    This is the single entry-point for type-level authorization.
    Instance-level filtering (e.g. a manager may only see their own users)
    is enforced separately at the repository/SQL-view layer.

    Args:
        account_type: entity kind from the session (``administrator``, ``manager``, ``user``).
        is_master: ``True`` for the master administrator.
        action: ``"read"``, ``"write"``, ``"delete"``, or ``"administer"``.
        resource: the SQLModel class name being accessed (e.g. ``"User"``).

    Returns:
        ``True`` if the policy permits the combination, ``False`` otherwise.
    """
    role = _role_for(account_type, is_master)
    return get_enforcer().enforce(role, resource, action)
