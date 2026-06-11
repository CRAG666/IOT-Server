"""Service layer for dynamic Casbin policy management.

All mutations go through the DB-backed enforcer, so changes persist immediately
without restarting the server.  The master_admin wildcard rule is immutable and
cannot be removed through this API.
"""

from typing import Annotated

from fastapi import Depends

from app.domain.policy.schemas import PolicyRuleOut, RolePermissionsOut
from app.shared.authorization.enforcer import get_enforcer
from app.shared.exceptions import BadRequestException, NotFoundException

_IMMUTABLE_RULES: set[tuple[str, str, str]] = {("master_admin", "*", "*")}


class PolicyService:
    """Wraps the Casbin enforcer with business-rule guards."""

    def list_all(self) -> list[PolicyRuleOut]:
        """Return every policy rule currently in the enforcer."""
        return [
            PolicyRuleOut(role=p[0], resource=p[1], action=p[2])
            for p in get_enforcer().get_policy()
        ]

    def get_for_role(self, role: str) -> RolePermissionsOut:
        """Return all rules for a specific role."""
        rules = [
            PolicyRuleOut(role=role, resource=p[1], action=p[2])
            for p in get_enforcer().get_filtered_policy(0, role)
        ]
        if not rules:
            raise NotFoundException("role", role)
        return RolePermissionsOut(role=role, permissions=rules)

    def add_rule(self, role: str, resource: str, action: str) -> PolicyRuleOut:
        """Add a policy rule; returns the rule (idempotent if it already exists)."""
        enforcer = get_enforcer()
        if not enforcer.has_policy(role, resource, action):
            enforcer.add_policy(role, resource, action)
        return PolicyRuleOut(role=role, resource=resource, action=action)

    def remove_rule(self, role: str, resource: str, action: str) -> None:
        """Remove a policy rule.

        Raises:
            BadRequestException: when attempting to delete an immutable rule.
            NotFoundException: when the rule does not exist.
        """
        if (role, resource, action) in _IMMUTABLE_RULES:
            raise BadRequestException(
                "The master_admin wildcard rule cannot be removed."
            )
        enforcer = get_enforcer()
        if not enforcer.has_policy(role, resource, action):
            raise NotFoundException("policy rule", f"{role} / {resource} / {action}")
        enforcer.remove_policy(role, resource, action)


def get_policy_service() -> PolicyService:
    return PolicyService()


PolicyServiceDep = Annotated[PolicyService, Depends(get_policy_service)]
