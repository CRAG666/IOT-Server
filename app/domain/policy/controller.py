"""REST controller for dynamic Casbin policy management.

All endpoints require the ``administer`` permission, which is currently
granted only to the master administrator via the ``master_admin, *, *``
wildcard rule.

Routes
------
GET    /api/v1/policies              List all policy rules
POST   /api/v1/policies              Add a policy rule
GET    /api/v1/policies/{role}       Get all rules for a role
DELETE /api/v1/policies/{role}/{resource}/{action}  Remove a rule
"""

from fastapi import APIRouter, status

from app.domain.policy.schemas import PolicyRuleIn, PolicyRuleOut, RolePermissionsOut
from app.domain.policy.service import PolicyServiceDep
from app.shared.authorization.dependencies import require_administer


class _Policy:
    """Sentinel class used as the Casbin resource for policy management."""


_administer_dep = require_administer(_Policy)

policy_router = APIRouter(prefix="/policies", tags=["Policies"])


@policy_router.get(
    "",
    response_model=list[PolicyRuleOut],
    dependencies=[_administer_dep],
)
def list_policies(service: PolicyServiceDep) -> list[PolicyRuleOut]:
    """List every active Casbin policy rule."""
    return service.list_all()


@policy_router.post(
    "",
    response_model=PolicyRuleOut,
    status_code=status.HTTP_201_CREATED,
    dependencies=[_administer_dep],
)
def add_policy(payload: PolicyRuleIn, service: PolicyServiceDep) -> PolicyRuleOut:
    """Add a new policy rule (idempotent — no error if it already exists)."""
    return service.add_rule(payload.role, payload.resource, payload.action)


@policy_router.get(
    "/{role}",
    response_model=RolePermissionsOut,
    dependencies=[_administer_dep],
)
def get_role_policies(role: str, service: PolicyServiceDep) -> RolePermissionsOut:
    """Get all policy rules for a given role."""
    return service.get_for_role(role)


@policy_router.delete(
    "/{role}/{resource}/{action}",
    status_code=status.HTTP_204_NO_CONTENT,
    dependencies=[_administer_dep],
)
def remove_policy(role: str, resource: str, action: str, service: PolicyServiceDep) -> None:
    """Remove a specific policy rule."""
    service.remove_rule(role, resource, action)
