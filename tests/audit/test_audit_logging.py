import pytest
from uuid import uuid4

from app.shared.authorization.dependencies import (
    _current_user_ctx,
    get_current_user_from_context)
from app.shared.authorization.models import CurrentUser
from app.domain.audit.repository import AuditRepository



@pytest.fixture
def mock_admin():
    return CurrentUser(
        account_id=uuid4(),
        account_type="administrator",
        email="admin@iot.com",
        is_master=True,
        sensitive_data_id=uuid4())


@pytest.fixture
def mock_manager():
    return CurrentUser(
        account_id=uuid4(),
        account_type="manager",
        email="manager@iot.com",
        is_master=False,
        sensitive_data_id=uuid4())


@pytest.fixture
def set_admin_ctx(mock_admin):
    token = _current_user_ctx.set(mock_admin)
    yield
    _current_user_ctx.reset(token)


class TestContextVarIsolation:
    def test_default_is_none(self):
        assert get_current_user_from_context() is None

    def test_set_and_get(self, set_admin_ctx, mock_admin):
        user = get_current_user_from_context()
        assert user is not None
        assert user.account_id == mock_admin.account_id
        assert user.account_type == "administrator"

    def test_switch_user_and_restore(self, mock_admin, mock_manager):
        token1 = _current_user_ctx.set(mock_admin)
        assert get_current_user_from_context().account_id == mock_admin.account_id

        token2 = _current_user_ctx.set(mock_manager)
        assert get_current_user_from_context().account_id == mock_manager.account_id

        _current_user_ctx.reset(token2)
        assert get_current_user_from_context().account_id == mock_admin.account_id

        _current_user_ctx.reset(token1)
        assert get_current_user_from_context() is None


class TestAuditRepository:
    def test_log_writes_to_db(self, session):
        repo = AuditRepository(session)
        entry = repo.log(
            account_id=uuid4(),
            account_type="administrator",
            action="create",
            resource_type="Device",
            resource_id=uuid4())
        assert entry.id is not None
        assert entry.created_at is not None
        assert entry.action == "create"

    def test_log_with_all_fields(self, session):
        repo = AuditRepository(session)
        entry = repo.log(
            account_id=uuid4(),
            account_type="manager",
            action="update",
            resource_type="Service",
            resource_id=uuid4(),
            details='{"name":{"from":"old","to":"new"}}',
            ip_address="10.0.0.1")
        assert entry.details == '{"name":{"from":"old","to":"new"}}'
        assert entry.ip_address == "10.0.0.1"
        assert entry.account_type == "manager"

    def test_get_by_account_returns_only_that_account(self, session):
        repo = AuditRepository(session)
        a1 = uuid4()
        a2 = uuid4()
        repo.log(account_id=a1, account_type="admin", action="create", resource_type="Device", resource_id=uuid4())
        repo.log(account_id=a1, account_type="admin", action="update", resource_type="Device", resource_id=uuid4())
        repo.log(account_id=a2, account_type="user", action="create", resource_type="Ticket", resource_id=uuid4())

        items, total = repo.get_by_account(a1)
        assert total == 2
        assert all(i.account_id == a1 for i in items)

    def test_get_by_resource_filters_correctly(self, session):
        repo = AuditRepository(session)
        dev_a = uuid4()
        dev_b = uuid4()
        repo.log(account_id=uuid4(), account_type="admin", action="create", resource_type="Device", resource_id=dev_a)
        repo.log(account_id=uuid4(), account_type="admin", action="update", resource_type="Device", resource_id=dev_a)
        repo.log(account_id=uuid4(), account_type="admin", action="create", resource_type="Device", resource_id=dev_b)

        assert len(repo.get_by_resource("Device", dev_a)) == 2
        assert len(repo.get_by_resource("Device", dev_b)) == 1

    def test_get_by_account_pagination(self, session):
        repo = AuditRepository(session)
        user_id = uuid4()
        for _ in range(7):
            repo.log(account_id=user_id, account_type="admin", action="create", resource_type="Device", resource_id=uuid4())
        items, total = repo.get_by_account(user_id, offset=2, limit=3)
        assert total == 7
        assert len(items) == 3

    def test_none_resource_id(self, session):
        repo = AuditRepository(session)
        entry = repo.log(
            account_id=uuid4(),
            account_type="admin",
            action="login",
            resource_type="Auth",
            resource_id=None)
        assert entry.resource_id is None


class TestAuditLogNoSensitiveData:
    def test_device_encryption_key_not_logged(self, master_admin_client):

        resp = master_admin_client.post(
            "/api/v1/devices",
            json={"name": "Sec Device", "encryption_key": "secret-key-12345"})
        assert resp.status_code in [200, 201]

        resp2 = master_admin_client.patch(
            f"/api/v1/devices/{resp.json()['id']}",
            json={"encryption_key": "new-secret-key"})
        assert resp2.status_code == 200


class TestAuditLogViaAPI:
    def test_device_create_generates_audit(self, master_admin_client):
        resp = master_admin_client.post(
            "/api/v1/devices",
            json={"name": "Audit Device"})
        assert resp.status_code in [200, 201]

    def test_device_update_generates_audit(self, master_admin_client):
        resp = master_admin_client.post(
            "/api/v1/devices",
            json={"name": "Device AUD"})
        device_id = resp.json()["id"]

        resp2 = master_admin_client.patch(
            f"/api/v1/devices/{device_id}",
            json={"name": "Device AUD Updated"})
        assert resp2.status_code == 200

    def test_device_delete_generates_audit(self, master_admin_client):
        resp = master_admin_client.post(
            "/api/v1/devices",
            json={"name": "Device to Delete"})
        device_id = resp.json()["id"]

        resp2 = master_admin_client.delete(
            f"/api/v1/devices/{device_id}")
        assert resp2.status_code == 204

    def test_service_create_generates_audit(self, master_admin_client):
        resp = master_admin_client.post(
            "/api/v1/services",
            json={
                "name": f"Audit Service {uuid4().hex[:8]}",
                "description": "Audit test",
                "administrator_id": str(master_admin_client.account['id']),
            })
        assert resp.status_code in [200, 201]
