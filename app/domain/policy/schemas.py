"""Pydantic schemas for the policy management API."""

from typing import Literal

from pydantic import BaseModel, field_validator

_VALID_ACTIONS = {"read", "write", "delete", "administer"}


class PolicyRuleIn(BaseModel):
    """Payload for adding a policy rule."""

    role: str
    resource: str
    action: Literal["read", "write", "delete", "administer"]

    @field_validator("role", "resource")
    @classmethod
    def no_wildcards(cls, v: str) -> str:
        if "*" in v:
            raise ValueError("wildcards are not allowed in role or resource")
        return v


class PolicyRuleOut(BaseModel):
    """A single resolved policy rule."""

    role: str
    resource: str
    action: str


class RolePermissionsOut(BaseModel):
    """All permission rules for one role."""

    role: str
    permissions: list[PolicyRuleOut]
