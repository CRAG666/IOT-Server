import pytest
from uuid import uuid4

from app.shared.authorization.oso_config import init_oso
from app.shared.authorization.models import CurrentUser
from app.database.model import Device, User


@pytest.fixture
def oso():
    return init_oso()


@pytest.fixture
def master_admin():
    return CurrentUser(
        account_id=uuid4(),
        account_type="administrator",
        email="master@example.com",
        is_master=True,
        sensitive_data_id=uuid4(),
    )


@pytest.fixture
def regular_admin():
    return CurrentUser(
        account_id=uuid4(),
        account_type="administrator",
        email="admin@example.com",
        is_master=False,
        sensitive_data_id=uuid4(),
    )


@pytest.fixture
def manager():
    return CurrentUser(
        account_id=uuid4(),
        account_type="manager",
        email="manager@example.com",
        is_master=False,
        sensitive_data_id=uuid4(),
    )


@pytest.fixture
def regular_user():
    return CurrentUser(
        account_id=uuid4(),
        account_type="user",
        email="user@example.com",
        is_master=False,
        sensitive_data_id=uuid4(),
    )


class TestMasterAdminPermissions:
    def test_master_admin_can_read(self, oso, master_admin):
        assert oso.is_allowed(master_admin, "read", Device)
    
    def test_master_admin_can_write(self, oso, master_admin):
        assert oso.is_allowed(master_admin, "write", Device)
    
    def test_master_admin_can_delete(self, oso, master_admin):
        assert oso.is_allowed(master_admin, "delete", Device)
    
    def test_master_admin_can_administer(self, oso, master_admin):
        assert oso.is_allowed(master_admin, "administer", Device)


class TestRegularAdminPermissions:
    def test_regular_admin_can_read(self, oso, regular_admin):
        assert oso.is_allowed(regular_admin, "read", Device)
    
    def test_regular_admin_can_write(self, oso, regular_admin):
        assert oso.is_allowed(regular_admin, "write", Device)
    
    def test_regular_admin_can_delete(self, oso, regular_admin):
        assert oso.is_allowed(regular_admin, "delete", Device)


class TestManagerPermissions:
    
    def test_manager_can_read(self, oso, manager):
        assert oso.is_allowed(manager, "read", Device)
    
    def test_manager_can_write(self, oso, manager):
        assert oso.is_allowed(manager, "write", Device)
    
    def test_manager_cannot_delete(self, oso, manager):
        assert not oso.is_allowed(manager, "delete", Device)


class TestRegularUserPermissions:
    def test_user_can_read(self, oso, regular_user):
        assert oso.is_allowed(regular_user, "read", Device)
    
    def test_user_cannot_write(self, oso, regular_user):
        assert not oso.is_allowed(regular_user, "write", Device)
    
    def test_user_cannot_delete(self, oso, regular_user):
        assert not oso.is_allowed(regular_user, "delete", Device)


class TestCurrentUserModel:
    def test_from_state_dict(self):
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
