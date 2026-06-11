"""Tests for BaseApiController model_class auto-wiring and Casbin column order.

These tests exist to pin two invariants introduced in the permission refactor:

1. ``model_class`` on a controller auto-wires standard CRUD→action dependencies;
   explicit ``*_dependencies`` declarations override the auto-wired values.
2. The Casbin enforcer uses the standard ``(sub, obj, act)`` column order — a
   regression here would silently break all authorization checks.
"""

import pytest
from pydantic import BaseModel

from app.shared.authorization.dependencies import require_administer
from app.shared.authorization.enforcer import get_enforcer
from app.shared.base_domain.controller import FullCrudApiController, ReadOnlyApiController


# ── Minimal stubs for controller instantiation ─────────────────────────────
# _register_routes is overridden to a no-op — we are testing the __init__
# wiring logic only, not the FastAPI route definitions.

class _Model:
    pass


class _Schema(BaseModel):
    pass


class _RO(ReadOnlyApiController):
    """Read-only stub: skips route registration."""
    prefix = "/x"
    service_dep = object
    response_schema = _Schema

    def _register_routes(self): pass


class _CRUD(FullCrudApiController):
    """Full-CRUD stub: skips route registration."""
    prefix = "/x"
    service_dep = object
    response_schema = _Schema
    create_schema = _Schema
    update_schema = _Schema

    def _register_routes(self): pass


# ── model_class auto-wiring ─────────────────────────────────────────────────

class TestModelClassAutoWiring:
    """BaseApiController wires CRUD deps from model_class when not overridden."""

    def test_no_model_class_leaves_list_dep_none(self):
        class _Ctrl(_RO):
            model_class = None

        ctrl = _Ctrl()
        assert ctrl.list_dependencies is None
        assert ctrl.retrieve_dependencies is None

    def test_model_class_wires_read_for_list_and_retrieve(self):
        class _Ctrl(_RO):
            model_class = _Model

        ctrl = _Ctrl()
        assert ctrl.list_dependencies is not None
        assert len(ctrl.list_dependencies) == 1
        assert ctrl.retrieve_dependencies is not None
        assert len(ctrl.retrieve_dependencies) == 1

    def test_model_class_wires_write_for_create_and_update(self):
        class _Ctrl(_CRUD):
            model_class = _Model

        ctrl = _Ctrl()
        assert ctrl.create_dependencies is not None
        assert ctrl.update_dependencies is not None

    def test_model_class_wires_delete(self):
        class _Ctrl(_CRUD):
            model_class = _Model

        ctrl = _Ctrl()
        assert ctrl.delete_dependencies is not None

    def test_explicit_dep_overrides_model_class_for_that_operation(self):
        custom = [require_administer(_Model)]

        class _Ctrl(_CRUD):
            model_class = _Model
            create_dependencies = custom

        ctrl = _Ctrl()
        assert ctrl.create_dependencies is custom
        # update not overridden — auto-wired to require_write
        assert ctrl.update_dependencies is not custom
        assert ctrl.update_dependencies is not None

    def test_partial_override_leaves_read_deps_auto_wired(self):
        custom = [require_administer(_Model)]

        class _Ctrl(_CRUD):
            model_class = _Model
            create_dependencies = custom
            update_dependencies = custom
            delete_dependencies = custom

        ctrl = _Ctrl()
        # Mutations use the explicit administer dep
        assert ctrl.create_dependencies is custom
        assert ctrl.update_dependencies is custom
        assert ctrl.delete_dependencies is custom
        # Read operations are auto-wired from model_class
        assert ctrl.list_dependencies is not None
        assert ctrl.list_dependencies is not custom
        assert ctrl.retrieve_dependencies is not None
        assert ctrl.retrieve_dependencies is not custom


# ── Casbin column order ─────────────────────────────────────────────────────

class TestCasbinColumnOrder:
    """Enforcer uses standard (sub, obj, act) — not the legacy (sub, act, obj)."""

    def test_standard_order_allows_known_permission(self):
        # policy.csv: p, administrator, User, read  → (sub, obj, act)
        # enforce(sub, obj, act) must return True
        assert get_enforcer().enforce("administrator", "User", "read")

    def test_standard_order_denies_forbidden_action(self):
        # administrator cannot write to Administrator (only read)
        assert not get_enforcer().enforce("administrator", "Administrator", "write")

    def test_reversed_order_is_not_a_valid_policy(self):
        # If someone calls enforce(sub, act, obj) — the legacy wrong order —
        # the lookup should fail because "read" is not a resource in the policy
        # and "User" is not an action.
        assert not get_enforcer().enforce("administrator", "read", "User")

    def test_manager_resource_action_order(self):
        assert get_enforcer().enforce("manager", "Device", "read")
        assert get_enforcer().enforce("manager", "Device", "write")
        assert not get_enforcer().enforce("manager", "Device", "delete")

    def test_user_resource_action_order(self):
        assert get_enforcer().enforce("user", "Service", "read")
        assert not get_enforcer().enforce("user", "Service", "write")

    def test_master_admin_wildcard_with_correct_order(self):
        assert get_enforcer().enforce("master_admin", "Administrator", "write")
        assert get_enforcer().enforce("master_admin", "Administrator", "delete")
        assert get_enforcer().enforce("master_admin", "Role", "administer")

    def test_support_agent_column_order(self):
        assert get_enforcer().enforce("support_agent", "ServiceTicket", "read")
        assert get_enforcer().enforce("support_agent", "ServiceTicket", "write")
        assert not get_enforcer().enforce("support_agent", "ServiceTicket", "delete")

    def test_support_admin_column_order(self):
        assert get_enforcer().enforce("support_admin", "EcosystemTicket", "write")
        assert get_enforcer().enforce("support_admin", "EcosystemTicket", "delete")
        assert not get_enforcer().enforce("support_admin", "Administrator", "read")
