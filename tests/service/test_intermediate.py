"""Tests para tablas intermedias de Service — managers, applications, devices."""
import pytest

APP_BASE = {
    "version": "1.0.0",
    "url": "https://test.com",
    "description": "Test app",
}


# ── Fixtures ────────────────────────────────────────────────────────


@pytest.fixture
def service_data(master_admin_client):
    response = master_admin_client.post(
        "/api/v1/services",
        json={
            "name": "Servicio de Prueba",
            "description": "Para tests de tablas intermedias",
            "administrator_id": str(master_admin_client.account['id']),
        })
    assert response.status_code == 201
    return response.json()


@pytest.fixture
def application_data(master_admin_client):
    response = master_admin_client.post(
        "/api/v1/applications",
        json={
            "name": "App de Prueba",
            "administrator_id": str(master_admin_client.account['id']),
            **APP_BASE,
        })
    assert response.status_code == 201
    return response.json()


@pytest.fixture
def device_data(master_admin_client):
    response = master_admin_client.post(
        "/api/v1/devices",
        json={
            "name": "Sensor de Prueba",
            "brand": "TestBrand",
            "model": "T-100",
        })
    assert response.status_code == 201
    return response.json()


# ── Tests: ManagerService ───────────────────────────────────────────


class TestAssignManager:
    """POST /services/{service_id}/managers/{manager_id}"""

    def test_assign_manager_success(self, master_admin_client, service_data, manager_client):
        response = master_admin_client.post(
            f"/api/v1/services/{service_data['id']}/managers/{manager_client.account['id']}")
        assert response.status_code == 201
        data = response.json()
        assert data["service_id"] == service_data["id"]
        assert data["manager_id"] == str(manager_client.account['id'])

    def test_assign_manager_not_found(self, master_admin_client, service_data):
        fake_id = "00000000-0000-0000-0000-000000000000"
        response = master_admin_client.post(
            f"/api/v1/services/{service_data['id']}/managers/{fake_id}")
        assert response.status_code == 404

    def test_assign_manager_duplicate(self, master_admin_client, service_data, manager_client):
        master_admin_client.post(
            f"/api/v1/services/{service_data['id']}/managers/{manager_client.account['id']}")
        response = master_admin_client.post(
            f"/api/v1/services/{service_data['id']}/managers/{manager_client.account['id']}")
        assert response.status_code == 409


class TestUnassignManager:
    """DELETE /services/{service_id}/managers/{manager_id}"""

    def test_unassign_manager_success(self, master_admin_client, service_data, manager_client):
        master_admin_client.post(
            f"/api/v1/services/{service_data['id']}/managers/{manager_client.account['id']}")
        response = master_admin_client.delete(
            f"/api/v1/services/{service_data['id']}/managers/{manager_client.account['id']}")
        assert response.status_code == 204

    def test_unassign_manager_not_assigned(self, master_admin_client, service_data, manager_client):
        response = master_admin_client.delete(
            f"/api/v1/services/{service_data['id']}/managers/{manager_client.account['id']}")
        assert response.status_code == 404


class TestListManagers:
    """GET /services/{service_id}/managers"""

    def test_list_managers_empty(self, master_admin_client, service_data):
        response = master_admin_client.get(f"/api/v1/services/{service_data['id']}/managers")
        assert response.status_code == 200
        assert response.json() == []

    def test_list_managers_with_data(self, master_admin_client, service_data, manager_client):
        master_admin_client.post(
            f"/api/v1/services/{service_data['id']}/managers/{manager_client.account['id']}")
        response = master_admin_client.get(f"/api/v1/services/{service_data['id']}/managers")
        assert response.status_code == 200
        data = response.json()
        assert len(data) == 1
        assert data[0]["manager_id"] == str(manager_client.account['id'])

    def test_list_managers_service_not_found(self, master_admin_client):
        fake_id = "00000000-0000-0000-0000-000000000000"
        response = master_admin_client.get(f"/api/v1/services/{fake_id}/managers")
        assert response.status_code == 404


# ── Tests: ApplicationService ───────────────────────────────────────


class TestAssignApplication:
    """POST /services/{service_id}/applications/{application_id}"""

    def test_assign_application_success(self, master_admin_client, service_data, application_data):
        response = master_admin_client.post(
            f"/api/v1/services/{service_data['id']}/applications/{application_data['id']}")
        assert response.status_code == 201
        data = response.json()
        assert data["service_id"] == service_data["id"]
        assert data["application_id"] == application_data["id"]

    def test_assign_application_service_not_found(self, master_admin_client, application_data):
        fake_id = "00000000-0000-0000-0000-000000000000"
        response = master_admin_client.post(
            f"/api/v1/services/{fake_id}/applications/{application_data['id']}")
        assert response.status_code == 404

    def test_assign_application_not_found(self, master_admin_client, service_data):
        fake_id = "00000000-0000-0000-0000-000000000000"
        response = master_admin_client.post(
            f"/api/v1/services/{service_data['id']}/applications/{fake_id}")
        assert response.status_code == 404

    def test_assign_application_duplicate(self, master_admin_client, service_data, application_data):
        master_admin_client.post(
            f"/api/v1/services/{service_data['id']}/applications/{application_data['id']}")
        response = master_admin_client.post(
            f"/api/v1/services/{service_data['id']}/applications/{application_data['id']}")
        assert response.status_code == 409


class TestUnassignApplication:
    """DELETE /services/{service_id}/applications/{application_id}"""

    def test_unassign_application_success(self, master_admin_client, service_data, application_data):
        master_admin_client.post(
            f"/api/v1/services/{service_data['id']}/applications/{application_data['id']}")
        response = master_admin_client.delete(
            f"/api/v1/services/{service_data['id']}/applications/{application_data['id']}")
        assert response.status_code == 204

    def test_unassign_application_not_assigned(self, master_admin_client, service_data, application_data):
        response = master_admin_client.delete(
            f"/api/v1/services/{service_data['id']}/applications/{application_data['id']}")
        assert response.status_code == 404


class TestListApplications:
    """GET /services/{service_id}/applications"""

    def test_list_applications_empty(self, master_admin_client, service_data):
        response = master_admin_client.get(f"/api/v1/services/{service_data['id']}/applications")
        assert response.status_code == 200
        assert response.json() == []

    def test_list_applications_with_data(self, master_admin_client, service_data, application_data):
        master_admin_client.post(
            f"/api/v1/services/{service_data['id']}/applications/{application_data['id']}")
        response = master_admin_client.get(f"/api/v1/services/{service_data['id']}/applications")
        assert response.status_code == 200
        data = response.json()
        assert len(data) == 1
        assert data[0]["application_id"] == application_data["id"]

    def test_list_applications_service_not_found(self, master_admin_client):
        fake_id = "00000000-0000-0000-0000-000000000000"
        response = master_admin_client.get(f"/api/v1/services/{fake_id}/applications")
        assert response.status_code == 404


# ── Tests: DeviceService ────────────────────────────────────────────


class TestAssignDevice:
    """POST /services/{service_id}/devices/{device_id}"""

    def test_assign_device_success(self, master_admin_client, service_data, device_data):
        response = master_admin_client.post(
            f"/api/v1/services/{service_data['id']}/devices/{device_data['id']}")
        assert response.status_code == 201
        data = response.json()
        assert data["service_id"] == service_data["id"]
        assert data["device_id"] == device_data["id"]

    def test_assign_device_service_not_found(self, master_admin_client, device_data):
        fake_id = "00000000-0000-0000-0000-000000000000"
        response = master_admin_client.post(
            f"/api/v1/services/{fake_id}/devices/{device_data['id']}")
        assert response.status_code == 404

    def test_assign_device_not_found(self, master_admin_client, service_data):
        fake_id = "00000000-0000-0000-0000-000000000000"
        response = master_admin_client.post(
            f"/api/v1/services/{service_data['id']}/devices/{fake_id}")
        assert response.status_code == 404

    def test_assign_device_duplicate(self, master_admin_client, service_data, device_data):
        master_admin_client.post(
            f"/api/v1/services/{service_data['id']}/devices/{device_data['id']}")
        response = master_admin_client.post(
            f"/api/v1/services/{service_data['id']}/devices/{device_data['id']}")
        assert response.status_code == 409


class TestUnassignDevice:
    """DELETE /services/{service_id}/devices/{device_id}"""

    def test_unassign_device_success(self, master_admin_client, service_data, device_data):
        master_admin_client.post(
            f"/api/v1/services/{service_data['id']}/devices/{device_data['id']}")
        response = master_admin_client.delete(
            f"/api/v1/services/{service_data['id']}/devices/{device_data['id']}")
        assert response.status_code == 204

    def test_unassign_device_not_assigned(self, master_admin_client, service_data, device_data):
        response = master_admin_client.delete(
            f"/api/v1/services/{service_data['id']}/devices/{device_data['id']}")
        assert response.status_code == 404


class TestListDevices:
    """GET /services/{service_id}/devices"""

    def test_list_devices_empty(self, master_admin_client, service_data):
        response = master_admin_client.get(f"/api/v1/services/{service_data['id']}/devices")
        assert response.status_code == 200
        assert response.json() == []

    def test_list_devices_with_data(self, master_admin_client, service_data, device_data):
        master_admin_client.post(
            f"/api/v1/services/{service_data['id']}/devices/{device_data['id']}")
        response = master_admin_client.get(f"/api/v1/services/{service_data['id']}/devices")
        assert response.status_code == 200
        data = response.json()
        assert len(data) == 1
        assert data[0]["device_id"] == device_data["id"]

    def test_list_devices_service_not_found(self, master_admin_client):
        fake_id = "00000000-0000-0000-0000-000000000000"
        response = master_admin_client.get(f"/api/v1/services/{fake_id}/devices")
        assert response.status_code == 404
