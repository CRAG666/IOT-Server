"""Detailed role-permission matrix tests — Casbin implementation.

These replace the former oso-based assertions.  Every assert from the
original file is preserved; the fixture is updated to use the typed
``is_allowed`` helper instead of an Oso instance.
"""

import pytest
from uuid import uuid4

from app.shared.authorization.enforcer import is_allowed
from app.shared.authorization.models import CurrentUser


# ── Fixtures ─────────────────────────────────────────────────────────────────

@pytest.fixture
def master_admin() -> CurrentUser:
    return CurrentUser(
        account_id=uuid4(),
        account_type="administrator",
        email="master@iot.com",
        is_master=True,
        sensitive_data_id=uuid4())


@pytest.fixture
def regular_admin() -> CurrentUser:
    return CurrentUser(
        account_id=uuid4(),
        account_type="administrator",
        email="admin@iot.com",
        is_master=False,
        sensitive_data_id=uuid4())


@pytest.fixture
def manager_user() -> CurrentUser:
    return CurrentUser(
        account_id=uuid4(),
        account_type="manager",
        email="manager@iot.com",
        is_master=False,
        sensitive_data_id=uuid4())


@pytest.fixture
def regular_user() -> CurrentUser:
    return CurrentUser(
        account_id=uuid4(),
        account_type="user",
        email="user@iot.com",
        is_master=False,
        sensitive_data_id=uuid4())


def allowed(user: CurrentUser, action: str, resource: str) -> bool:
    return is_allowed(user.account_type, user.is_master, action, resource)


# ── Master admin ──────────────────────────────────────────────────────────────

class TestMasterAdministratorPermissions:
    def test_can_manage_administrators(self, master_admin):
        assert allowed(master_admin, "read", "Administrator")
        assert allowed(master_admin, "write", "Administrator")
        assert allowed(master_admin, "delete", "Administrator")

    def test_can_manage_managers(self, master_admin):
        assert allowed(master_admin, "read", "Manager")
        assert allowed(master_admin, "write", "Manager")
        assert allowed(master_admin, "delete", "Manager")

    def test_can_manage_users(self, master_admin):
        assert allowed(master_admin, "read", "User")
        assert allowed(master_admin, "write", "User")
        assert allowed(master_admin, "delete", "User")

    def test_can_manage_devices(self, master_admin):
        assert allowed(master_admin, "read", "Device")
        assert allowed(master_admin, "write", "Device")
        assert allowed(master_admin, "delete", "Device")

    def test_can_manage_applications(self, master_admin):
        assert allowed(master_admin, "read", "Application")
        assert allowed(master_admin, "write", "Application")
        assert allowed(master_admin, "delete", "Application")

    def test_can_manage_services(self, master_admin):
        assert allowed(master_admin, "read", "Service")
        assert allowed(master_admin, "write", "Service")
        assert allowed(master_admin, "delete", "Service")

    def test_can_manage_tickets(self, master_admin):
        assert allowed(master_admin, "read", "ServiceTicket")
        assert allowed(master_admin, "write", "ServiceTicket")


# ── Regular admin ─────────────────────────────────────────────────────────────

class TestRegularAdministratorPermissions:
    def test_cannot_manage_administrators(self, regular_admin):
        assert allowed(regular_admin, "read", "Administrator") is True
        assert allowed(regular_admin, "write", "Administrator") is False
        assert allowed(regular_admin, "delete", "Administrator") is False

    def test_can_create_managers(self, regular_admin):
        assert allowed(regular_admin, "read", "Manager")
        assert allowed(regular_admin, "write", "Manager")
        assert allowed(regular_admin, "delete", "Manager")

    def test_can_create_users(self, regular_admin):
        assert allowed(regular_admin, "read", "User")
        assert allowed(regular_admin, "write", "User")
        assert allowed(regular_admin, "delete", "User")

    def test_can_manage_devices(self, regular_admin):
        assert allowed(regular_admin, "read", "Device")
        assert allowed(regular_admin, "write", "Device")
        assert allowed(regular_admin, "delete", "Device")

    def test_can_manage_applications(self, regular_admin):
        assert allowed(regular_admin, "read", "Application")
        assert allowed(regular_admin, "write", "Application")
        assert allowed(regular_admin, "delete", "Application")

    def test_can_manage_services(self, regular_admin):
        assert allowed(regular_admin, "read", "Service")
        assert allowed(regular_admin, "write", "Service")

    def test_can_review_tickets(self, regular_admin):
        assert allowed(regular_admin, "read", "ServiceTicket")
        assert allowed(regular_admin, "write", "ServiceTicket")


# ── Manager ───────────────────────────────────────────────────────────────────

class TestManagerPermissions:
    def test_can_create_users(self, manager_user):
        assert allowed(manager_user, "read", "User")
        assert allowed(manager_user, "write", "User")

    def test_can_create_and_modify_devices(self, manager_user):
        assert allowed(manager_user, "read", "Device")
        assert allowed(manager_user, "write", "Device")

    def test_can_consult_applications(self, manager_user):
        assert allowed(manager_user, "read", "Application")

    def test_can_consult_services(self, manager_user):
        assert allowed(manager_user, "read", "Service")

    def test_can_manage_tickets(self, manager_user):
        assert allowed(manager_user, "read", "ServiceTicket")
        assert allowed(manager_user, "write", "ServiceTicket")


# ── Regular user ──────────────────────────────────────────────────────────────

class TestUserPermissions:
    def test_cannot_create_anything(self, regular_user):
        assert allowed(regular_user, "write", "Administrator") is False
        assert allowed(regular_user, "write", "Manager") is False
        assert allowed(regular_user, "write", "Device") is False
        assert allowed(regular_user, "write", "Application") is False
        assert allowed(regular_user, "write", "Service") is False

    def test_can_consult_devices(self, regular_user):
        assert allowed(regular_user, "read", "Device")

    def test_cannot_delete_anything(self, regular_user):
        assert allowed(regular_user, "delete", "Device") is False
        assert allowed(regular_user, "delete", "User") is False
        assert allowed(regular_user, "delete", "ServiceTicket") is False
