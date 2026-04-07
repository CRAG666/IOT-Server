import pytest
from uuid import uuid4

from app.shared.authorization.oso_config import init_oso
from app.shared.authorization.models import CurrentUser
from app.database.model import (
    Device,
    User,
    Administrator,
    Manager,
    Service,
    Application,
    ServiceTicket,
)


@pytest.fixture
def oso():
    return init_oso()


@pytest.fixture
def master_admin():
    return CurrentUser(
        account_id=uuid4(),
        account_type="administrator",
        email="master@iot.com",
        is_master=True,
        sensitive_data_id=uuid4(),
    )


@pytest.fixture
def regular_admin():
    return CurrentUser(
        account_id=uuid4(),
        account_type="administrator",
        email="admin@iot.com",
        is_master=False,
        sensitive_data_id=uuid4(),
    )


@pytest.fixture
def manager_user():
    return CurrentUser(
        account_id=uuid4(),
        account_type="manager",
        email="manager@iot.com",
        is_master=False,
        sensitive_data_id=uuid4(),
    )


@pytest.fixture
def regular_user():
    return CurrentUser(
        account_id=uuid4(),
        account_type="user",
        email="user@iot.com",
        is_master=False,
        sensitive_data_id=uuid4(),
    )


class TestMasterAdministratorPermissions:
    
    def test_can_manage_administrators(self, oso, master_admin):
        assert oso.is_allowed(master_admin, "read", Administrator)
        assert oso.is_allowed(master_admin, "write", Administrator)
        assert oso.is_allowed(master_admin, "delete", Administrator)
    
    def test_can_manage_managers(self, oso, master_admin):
        assert oso.is_allowed(master_admin, "read", Manager)
        assert oso.is_allowed(master_admin, "write", Manager)
        assert oso.is_allowed(master_admin, "delete", Manager)
    
    def test_can_manage_users(self, oso, master_admin):
        assert oso.is_allowed(master_admin, "read", User)
        assert oso.is_allowed(master_admin, "write", User)
        assert oso.is_allowed(master_admin, "delete", User)
    
    def test_can_manage_devices(self, oso, master_admin):
        assert oso.is_allowed(master_admin, "read", Device)
        assert oso.is_allowed(master_admin, "write", Device)
        assert oso.is_allowed(master_admin, "delete", Device)
    
    def test_can_manage_applications(self, oso, master_admin):
        assert oso.is_allowed(master_admin, "read", Application)
        assert oso.is_allowed(master_admin, "write", Application)
        assert oso.is_allowed(master_admin, "delete", Application)
    
    def test_can_manage_services(self, oso, master_admin):
        assert oso.is_allowed(master_admin, "read", Service)
        assert oso.is_allowed(master_admin, "write", Service)
        assert oso.is_allowed(master_admin, "delete", Service)
    
    def test_can_manage_tickets(self, oso, master_admin):
        assert oso.is_allowed(master_admin, "read", ServiceTicket)
        assert oso.is_allowed(master_admin, "write", ServiceTicket)


class TestRegularAdministratorPermissions:
    
    def test_cannot_manage_administrators(self, oso, regular_admin):
        assert oso.is_allowed(regular_admin, "read", Administrator) is True  # Can read
        assert oso.is_allowed(regular_admin, "write", Administrator) is False  # Cannot write
        assert oso.is_allowed(regular_admin, "delete", Administrator) is False  # Cannot delete
    
    def test_can_create_managers(self, oso, regular_admin):
        assert oso.is_allowed(regular_admin, "read", Manager)
        assert oso.is_allowed(regular_admin, "write", Manager)
        assert oso.is_allowed(regular_admin, "delete", Manager)
    
    def test_can_create_users(self, oso, regular_admin):
        assert oso.is_allowed(regular_admin, "read", User)
        assert oso.is_allowed(regular_admin, "write", User)
        assert oso.is_allowed(regular_admin, "delete", User)
    
    def test_can_manage_devices(self, oso, regular_admin):
        assert oso.is_allowed(regular_admin, "read", Device)
        assert oso.is_allowed(regular_admin, "write", Device)
        assert oso.is_allowed(regular_admin, "delete", Device)
    
    def test_can_manage_applications(self, oso, regular_admin):
        assert oso.is_allowed(regular_admin, "read", Application)
        assert oso.is_allowed(regular_admin, "write", Application)
        assert oso.is_allowed(regular_admin, "delete", Application)
    
    def test_can_manage_services(self, oso, regular_admin):
        assert oso.is_allowed(regular_admin, "read", Service)
        assert oso.is_allowed(regular_admin, "write", Service)
    
    def test_can_review_tickets(self, oso, regular_admin):
        assert oso.is_allowed(regular_admin, "read", ServiceTicket)
        assert oso.is_allowed(regular_admin, "write", ServiceTicket)


class TestManagerPermissions:
    
    def test_can_create_managers(self, oso, manager_user):
        assert oso.is_allowed(manager_user, "read", Manager)
        assert oso.is_allowed(manager_user, "write", Manager)
    
    def test_can_create_users(self, oso, manager_user):
        assert oso.is_allowed(manager_user, "read", User)
        assert oso.is_allowed(manager_user, "write", User)
    
    def test_can_create_and_modify_devices(self, oso, manager_user):
        assert oso.is_allowed(manager_user, "read", Device)
        assert oso.is_allowed(manager_user, "write", Device)
    
    def test_cannot_delete_devices(self, oso, manager_user):
        assert oso.is_allowed(manager_user, "delete", Device) is False
    
    def test_can_consult_applications(self, oso, manager_user):
        assert oso.is_allowed(manager_user, "read", Application)
    
    def test_cannot_modify_applications(self, oso, manager_user):
        assert oso.is_allowed(manager_user, "write", Application) is False
        assert oso.is_allowed(manager_user, "delete", Application) is False
    
    def test_can_consult_services(self, oso, manager_user):
        assert oso.is_allowed(manager_user, "read", Service)
    
    def test_cannot_modify_services(self, oso, manager_user):
        assert oso.is_allowed(manager_user, "write", Service) is False
    
    def test_can_manage_tickets(self, oso, manager_user):
        assert oso.is_allowed(manager_user, "read", ServiceTicket)
        assert oso.is_allowed(manager_user, "write", ServiceTicket)


class TestUserPermissions:
    
    def test_cannot_create_anything(self, oso, regular_user):
        assert oso.is_allowed(regular_user, "write", Administrator) is False
        assert oso.is_allowed(regular_user, "write", Manager) is False
        assert oso.is_allowed(regular_user, "write", Device) is False
        assert oso.is_allowed(regular_user, "write", Application) is False
        assert oso.is_allowed(regular_user, "write", Service) is False
    
    def test_can_consult_devices(self, oso, regular_user):
        assert oso.is_allowed(regular_user, "read", Device)
    
    def test_cannot_consult_users(self, oso, regular_user):
        assert oso.is_allowed(regular_user, "read", User) is False
    
    def test_cannot_consult_services(self, oso, regular_user):
        assert oso.is_allowed(regular_user, "read", Service) is False
    
    def test_cannot_consult_applications(self, oso, regular_user):
        assert oso.is_allowed(regular_user, "read", Application) is False
    
    def test_can_create_tickets(self, oso, regular_user):
        assert oso.is_allowed(regular_user, "read", ServiceTicket)
        assert oso.is_allowed(regular_user, "write", ServiceTicket)
    
    def test_cannot_delete_anything(self, oso, regular_user):
        assert oso.is_allowed(regular_user, "delete", Device) is False
        assert oso.is_allowed(regular_user, "delete", User) is False
        assert oso.is_allowed(regular_user, "delete", ServiceTicket) is False


class TestPasswordChangePermissions:
    
    def test_users_can_change_own_password(self, oso, regular_user):
        # Create a mock user object with matching ID
        user_obj = type('User', (), {'id': regular_user.account_id})()
        assert oso.is_allowed(regular_user, "write", user_obj)
    
    def test_managers_can_change_own_password(self, oso, manager_user):
        user_obj = type('User', (), {'id': manager_user.account_id})()
        assert oso.is_allowed(manager_user, "write", user_obj)
    
    def test_admins_can_change_own_password(self, oso, regular_admin):
        user_obj = type('User', (), {'id': regular_admin.account_id})()
        assert oso.is_allowed(regular_admin, "write", user_obj)
