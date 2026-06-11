"""Tests for the Casbin RBAC policy.

These replace the former ``test_oso_policies.py`` and verify that every
allow/deny combination from the original Polar policy is preserved.
"""

import pytest
from uuid import uuid4

from app.shared.authorization.enforcer import is_allowed
from app.shared.authorization.models import CurrentUser


# ── Fixtures ────────────────────────────────────────────────────────────────

@pytest.fixture
def master_admin() -> CurrentUser:
    return CurrentUser(
        account_id=uuid4(),
        account_type="administrator",
        email="master@example.com",
        is_master=True,
        sensitive_data_id=uuid4())


@pytest.fixture
def regular_admin() -> CurrentUser:
    return CurrentUser(
        account_id=uuid4(),
        account_type="administrator",
        email="admin@example.com",
        is_master=False,
        sensitive_data_id=uuid4())


@pytest.fixture
def manager() -> CurrentUser:
    return CurrentUser(
        account_id=uuid4(),
        account_type="manager",
        email="manager@example.com",
        is_master=False,
        sensitive_data_id=uuid4())


@pytest.fixture
def regular_user() -> CurrentUser:
    return CurrentUser(
        account_id=uuid4(),
        account_type="user",
        email="user@example.com",
        is_master=False,
        sensitive_data_id=uuid4())


def check(user: CurrentUser, action: str, resource: str) -> bool:
    return is_allowed(user.account_type, user.is_master, action, resource)


# ── Master admin ─────────────────────────────────────────────────────────────

class TestMasterAdminPermissions:
    def test_can_read_devices(self, master_admin):
        assert check(master_admin, "read", "Device")

    def test_can_write_devices(self, master_admin):
        assert check(master_admin, "write", "Device")

    def test_can_delete_devices(self, master_admin):
        assert check(master_admin, "delete", "Device")

    def test_can_administer(self, master_admin):
        assert check(master_admin, "administer", "Device")

    def test_can_manage_administrators(self, master_admin):
        assert check(master_admin, "read", "Administrator")
        assert check(master_admin, "write", "Administrator")
        assert check(master_admin, "delete", "Administrator")

    def test_can_manage_managers(self, master_admin):
        assert check(master_admin, "read", "Manager")
        assert check(master_admin, "write", "Manager")
        assert check(master_admin, "delete", "Manager")

    def test_can_manage_users(self, master_admin):
        assert check(master_admin, "read", "User")
        assert check(master_admin, "write", "User")
        assert check(master_admin, "delete", "User")

    def test_can_manage_applications(self, master_admin):
        assert check(master_admin, "read", "Application")
        assert check(master_admin, "write", "Application")
        assert check(master_admin, "delete", "Application")

    def test_can_manage_services(self, master_admin):
        assert check(master_admin, "read", "Service")
        assert check(master_admin, "write", "Service")
        assert check(master_admin, "delete", "Service")

    def test_can_manage_tickets(self, master_admin):
        assert check(master_admin, "read", "ServiceTicket")
        assert check(master_admin, "write", "ServiceTicket")
        assert check(master_admin, "read", "EcosystemTicket")
        assert check(master_admin, "write", "EcosystemTicket")

    def test_can_manage_roles(self, master_admin):
        assert check(master_admin, "read", "Role")
        assert check(master_admin, "write", "Role")
        assert check(master_admin, "delete", "Role")


# ── Regular admin (non-master) ───────────────────────────────────────────────

class TestRegularAdminPermissions:
    def test_can_read_devices(self, regular_admin):
        assert check(regular_admin, "read", "Device")

    def test_can_write_devices(self, regular_admin):
        assert check(regular_admin, "write", "Device")

    def test_can_delete_devices(self, regular_admin):
        assert check(regular_admin, "delete", "Device")

    def test_can_read_administrators(self, regular_admin):
        assert check(regular_admin, "read", "Administrator")

    def test_cannot_write_administrators(self, regular_admin):
        assert not check(regular_admin, "write", "Administrator")

    def test_cannot_delete_administrators(self, regular_admin):
        assert not check(regular_admin, "delete", "Administrator")

    def test_can_read_roles(self, regular_admin):
        assert check(regular_admin, "read", "Role")

    def test_cannot_write_roles(self, regular_admin):
        assert not check(regular_admin, "write", "Role")

    def test_cannot_delete_roles(self, regular_admin):
        assert not check(regular_admin, "delete", "Role")

    def test_can_manage_managers(self, regular_admin):
        assert check(regular_admin, "read", "Manager")
        assert check(regular_admin, "write", "Manager")
        assert check(regular_admin, "delete", "Manager")

    def test_can_manage_users(self, regular_admin):
        assert check(regular_admin, "read", "User")
        assert check(regular_admin, "write", "User")
        assert check(regular_admin, "delete", "User")

    def test_can_manage_applications(self, regular_admin):
        assert check(regular_admin, "read", "Application")
        assert check(regular_admin, "write", "Application")
        assert check(regular_admin, "delete", "Application")

    def test_can_manage_services(self, regular_admin):
        assert check(regular_admin, "read", "Service")
        assert check(regular_admin, "write", "Service")
        assert check(regular_admin, "delete", "Service")

    def test_can_review_tickets(self, regular_admin):
        assert check(regular_admin, "read", "ServiceTicket")
        assert check(regular_admin, "write", "ServiceTicket")
        assert check(regular_admin, "read", "EcosystemTicket")
        assert check(regular_admin, "write", "EcosystemTicket")


# ── Manager ──────────────────────────────────────────────────────────────────

class TestManagerPermissions:
    def test_can_read_devices(self, manager):
        assert check(manager, "read", "Device")

    def test_can_write_devices(self, manager):
        assert check(manager, "write", "Device")

    def test_cannot_delete_devices(self, manager):
        assert not check(manager, "delete", "Device")

    def test_cannot_delete_users(self, manager):
        assert not check(manager, "delete", "User")

    def test_cannot_access_roles(self, manager):
        assert not check(manager, "read", "Role")
        assert not check(manager, "write", "Role")

    def test_cannot_access_administrators(self, manager):
        assert not check(manager, "read", "Administrator")

    def test_can_read_users(self, manager):
        assert check(manager, "read", "User")

    def test_can_write_users(self, manager):
        assert check(manager, "write", "User")

    def test_can_consult_applications(self, manager):
        assert check(manager, "read", "Application")

    def test_can_write_applications(self, manager):
        assert check(manager, "write", "Application")

    def test_cannot_delete_applications(self, manager):
        assert not check(manager, "delete", "Application")

    def test_can_consult_services(self, manager):
        assert check(manager, "read", "Service")

    def test_can_manage_ecosystem_tickets(self, manager):
        assert check(manager, "read", "EcosystemTicket")
        assert check(manager, "write", "EcosystemTicket")

    def test_cannot_delete_ecosystem_tickets(self, manager):
        assert not check(manager, "delete", "EcosystemTicket")

    def test_can_manage_service_tickets(self, manager):
        assert check(manager, "read", "ServiceTicket")
        assert check(manager, "write", "ServiceTicket")

    def test_cannot_delete_managers(self, manager):
        assert not check(manager, "delete", "Manager")


# ── Regular user ─────────────────────────────────────────────────────────────

class TestRegularUserPermissions:
    def test_can_read_devices(self, regular_user):
        assert check(regular_user, "read", "Device")

    def test_cannot_write_devices(self, regular_user):
        assert not check(regular_user, "write", "Device")

    def test_cannot_delete_devices(self, regular_user):
        assert not check(regular_user, "delete", "Device")

    def test_can_read_own_profile(self, regular_user):
        assert check(regular_user, "read", "User")

    def test_can_write_own_profile(self, regular_user):
        assert check(regular_user, "write", "User")

    def test_cannot_delete_self(self, regular_user):
        assert not check(regular_user, "delete", "User")

    def test_can_read_applications(self, regular_user):
        assert check(regular_user, "read", "Application")

    def test_cannot_write_applications(self, regular_user):
        assert not check(regular_user, "write", "Application")

    def test_can_read_services(self, regular_user):
        assert check(regular_user, "read", "Service")

    def test_cannot_write_services(self, regular_user):
        assert not check(regular_user, "write", "Service")

    def test_can_create_ecosystem_tickets(self, regular_user):
        assert check(regular_user, "write", "EcosystemTicket")

    def test_can_read_service_tickets(self, regular_user):
        assert check(regular_user, "read", "ServiceTicket")

    def test_cannot_write_service_tickets(self, regular_user):
        assert not check(regular_user, "write", "ServiceTicket")

    def test_cannot_access_roles(self, regular_user):
        assert not check(regular_user, "read", "Role")
        assert not check(regular_user, "write", "Role")

    def test_cannot_access_managers(self, regular_user):
        assert not check(regular_user, "read", "Manager")

    def test_cannot_access_administrators(self, regular_user):
        assert not check(regular_user, "read", "Administrator")

    def test_cannot_write_anything_elevated(self, regular_user):
        for resource in ("Administrator", "Manager", "Device", "Application", "Service"):
            assert not check(regular_user, "write", resource)

    def test_cannot_delete_anything(self, regular_user):
        for resource in ("Device", "User", "ServiceTicket"):
            assert not check(regular_user, "delete", resource)


# ── CurrentUser model ────────────────────────────────────────────────────────

class TestCurrentUserModel:
    def test_from_state_dict_with_uuid_strings(self):
        account_id = uuid4()
        sensitive_data_id = uuid4()
        state_dict = {
            "account_id": str(account_id),
            "account_type": "administrator",
            "email": "test@example.com",
            "is_master": True,
            "sensitive_data_id": str(sensitive_data_id),
        }
        user = CurrentUser.from_state_dict(state_dict)
        assert user.account_id == account_id
        assert user.account_type == "administrator"
        assert user.email == "test@example.com"
        assert user.is_master is True
        assert user.sensitive_data_id == sensitive_data_id

    def test_from_state_dict_with_uuid_objects(self):
        account_id = uuid4()
        sensitive_data_id = uuid4()
        state_dict = {
            "account_id": account_id,
            "account_type": "user",
            "email": "u@example.com",
            "is_master": False,
            "sensitive_data_id": sensitive_data_id,
        }
        user = CurrentUser.from_state_dict(state_dict)
        assert user.account_id == account_id
        assert user.is_master is False
