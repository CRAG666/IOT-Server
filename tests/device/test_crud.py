import pytest
from fastapi.testclient import TestClient
from uuid import uuid4

from tests.e2e_client import E2ETestClient


class TestDeviceList:
    """Test GET /devices endpoint."""

    def test_list_devices_as_master_admin(
        self, master_admin_client: E2ETestClient
    ):
        """Test listing devices as master admin."""
        response = master_admin_client.get("/api/v1/devices")
        assert response.status_code == 200
        data = response.json()
        assert "total" in data
        assert "data" in data
        assert isinstance(data["data"], list)

    def test_list_devices_as_regular_admin(
        self, regular_admin_client: E2ETestClient
    ):
        """Test listing devices as regular admin."""
        response = regular_admin_client.get("/api/v1/devices")
        assert response.status_code == 200
        data = response.json()
        assert "total" in data
        assert "data" in data

    def test_list_devices_as_manager(
        self, manager_client: E2ETestClient
    ):
        """Test listing devices as manager."""
        response = manager_client.get("/api/v1/devices")
        assert response.status_code == 200
        data = response.json()
        assert "total" in data
        assert "data" in data

    def test_list_devices_as_user(
        self, user_client: E2ETestClient
    ):
        """Test listing devices as regular user."""
        response = user_client.get("/api/v1/devices")
        assert response.status_code == 200
        data = response.json()
        assert "total" in data
        assert "data" in data

    def test_list_devices_without_token(self, client: TestClient):
        """Test listing devices without authentication."""
        response = client.get("/api/v1/devices")
        assert response.status_code == 401

    def test_list_devices_pagination(
        self, master_admin_client: E2ETestClient
    ):
        """Test listing devices with pagination parameters."""
        response = master_admin_client.get("/api/v1/devices?offset=0&limit=10")
        assert response.status_code == 200
        data = response.json()
        assert data["limit"] == 10
        assert data["offset"] == 0


class TestDeviceRetrieve:
    """Test GET /devices/{id} endpoint."""

    def test_retrieve_device_as_master_admin(
        self, master_admin_client: E2ETestClient
    ):
        """Test retrieving a device as master admin."""

        # First create a device
        device_data = {
            "name": "Test Device",
            "brand": "TestBrand",
            "model": "TestModel",
            "serial_number": "SN123456789",
            "ip": "192.168.1.100",
            "mac": "00:11:22:33:44:55"
        }
        create_response = master_admin_client.post(
            "/api/v1/devices",
            json=device_data)
        assert create_response.status_code == 201
        device_id = create_response.json()["id"]

        # Then retrieve it
        response = master_admin_client.get(f"/api/v1/devices/{device_id}")
        assert response.status_code == 200
        data = response.json()
        assert data["name"] == "Test Device"
        assert data["is_active"] is True

    def test_retrieve_device_not_found(
        self, master_admin_client: E2ETestClient
    ):
        """Test retrieving a non-existent device."""
        response = master_admin_client.get(f"/api/v1/devices/{uuid4()}")
        assert response.status_code == 404

    def test_retrieve_device_invalid_uuid(
        self, master_admin_client: E2ETestClient
    ):
        """Test retrieving device with invalid UUID."""
        response = master_admin_client.get("/api/v1/devices/not-a-uuid")
        assert response.status_code == 422

    def test_retrieve_device_as_user(
        self, user_client: E2ETestClient, master_admin_client: E2ETestClient
    ):
        """Test retrieving device as regular user."""
        # Create device as admin
        device_data = {
            "name": "User Device",
            "brand": "TestBrand",
            "model": "TestModel",
            "serial_number": "SN987654321",
            "ip": "192.168.1.101",
            "mac": "00:11:22:33:44:66"
        }
        create_response = master_admin_client.post(
            "/api/v1/devices",
            json=device_data)
        device_id = create_response.json()["id"]

        # Retrieve as user
        response = user_client.get(f"/api/v1/devices/{device_id}")
        assert response.status_code == 200


class TestDeviceCreate:
    """Test POST /devices endpoint."""

    def test_create_device_as_master_admin(
        self, master_admin_client: E2ETestClient
    ):
        """Test creating a new device as master admin."""
        device_data = {
            "name": "New Device",
            "brand": "BrandX",
            "model": "ModelY",
            "serial_number": "SN111222333",
            "ip": "192.168.1.102",
            "mac": "AA:BB:CC:DD:EE:FF"
        }

        response = master_admin_client.post("/api/v1/devices", json=device_data)
        assert response.status_code == 201
        data = response.json()
        assert data["name"] == "New Device"
        assert data["is_active"] is True

    def test_create_device_as_admin(
        self, regular_admin_client: E2ETestClient
    ):
        """Test creating device as regular admin."""
        device_data = {
            "name": "Admin Device",
            "brand": "BrandX",
            "model": "ModelY",
            "serial_number": "SN444555666",
            "ip": "192.168.1.103",
            "mac": "11:22:33:44:55:66"
        }

        response = regular_admin_client.post("/api/v1/devices", json=device_data)
        assert response.status_code == 201

    def test_create_device_as_manager(
        self, manager_client: E2ETestClient
    ):
        """Test creating device as manager."""
        device_data = {
            "name": "Manager Device",
            "brand": "BrandX",
            "model": "ModelY",
            "serial_number": "SN777888999",
            "ip": "192.168.1.104",
            "mac": "22:33:44:55:66:77"
        }

        response = manager_client.post("/api/v1/devices", json=device_data)
        assert response.status_code == 201

    def test_create_device_as_user_forbidden(
        self, user_client: E2ETestClient
    ):
        """Test creating device as user (should be forbidden)."""
        device_data = {
            "name": "User Device",
            "brand": "BrandX",
            "model": "ModelY",
            "serial_number": "SN000111222",
            "ip": "192.168.1.105",
            "mac": "33:44:55:66:77:88"
        }

        response = user_client.post("/api/v1/devices", json=device_data)
        assert response.status_code == 403

    def test_create_device_missing_required_field(
        self, master_admin_client: E2ETestClient
    ):
        """Test creating device with missing required field."""
        device_data = {
            "brand": "BrandX",
            "model": "ModelY",
            "serial_number": "SN333444555",
            "ip": "192.168.1.106",
            "mac": "44:55:66:77:88:99"
        }

        response = master_admin_client.post("/api/v1/devices", json=device_data)
        assert response.status_code == 422

    def test_create_device_duplicate_serial_number(
        self, master_admin_client: E2ETestClient
    ):
        """Test creating device with duplicate serial number."""
        device_data = {
            "name": "Device 1",
            "brand": "BrandX",
            "model": "ModelY",
            "serial_number": "SN_DUPLICATE",
            "ip": "192.168.1.107",
            "mac": "55:66:77:88:99:AA"
        }

        # Create first device
        response1 = master_admin_client.post("/api/v1/devices", json=device_data)
        assert response1.status_code == 201

        # Try to create duplicate
        device_data["name"] = "Device 2"
        device_data["mac"] = "66:77:88:99:AA:BB"
        response2 = master_admin_client.post("/api/v1/devices", json=device_data)
        assert response2.status_code == 500

    def test_create_device_duplicate_mac(
        self, master_admin_client: E2ETestClient
    ):
        """Test creating device with duplicate MAC address."""
        device_data = {
            "name": "Device 3",
            "brand": "BrandX",
            "model": "ModelY",
            "serial_number": "SN_UNIQUE1",
            "ip": "192.168.1.108",
            "mac": "AA:BB:CC:DD:EE:11"
        }

        # Create first device
        response1 = master_admin_client.post("/api/v1/devices", json=device_data)
        assert response1.status_code == 201

        # Try to create duplicate
        device_data["name"] = "Device 4"
        device_data["serial_number"] = "SN_UNIQUE2"
        response2 = master_admin_client.post("/api/v1/devices", json=device_data)
        assert response2.status_code == 500


class TestDeviceUpdate:
    """Test PATCH /devices/{id} endpoint."""

    def test_update_device_partial_as_admin(
        self, master_admin_client: E2ETestClient
    ):
        """Test updating device with partial fields."""

        # Create device
        device_data = {
            "name": "Original Device",
            "brand": "BrandX",
            "model": "ModelY",
            "serial_number": "SN_UPDATE1",
            "ip": "192.168.1.109",
            "mac": "77:88:99:AA:BB:CC"
        }
        create_response = master_admin_client.post(
            "/api/v1/devices",
            json=device_data)
        device_id = create_response.json()["id"]

        # Update partial
        response = master_admin_client.patch(
            f"/api/v1/devices/{device_id}",
            json={"name": "Updated Device"})
        assert response.status_code == 200

        # Verify
        get_response = master_admin_client.get(f"/api/v1/devices/{device_id}")
        assert get_response.json()["name"] == "Updated Device"

    def test_update_device_full_as_manager(
        self, master_admin_client: E2ETestClient, manager_client: E2ETestClient
    ):
        """Test updating multiple device fields as manager."""
        # Create device as admin
        device_data = {
            "name": "Manager Update Device",
            "brand": "BrandX",
            "model": "ModelY",
            "serial_number": "SN_UPDATE2",
            "ip": "192.168.1.110",
            "mac": "88:99:AA:BB:CC:DD"
        }
        create_response = master_admin_client.post(
            "/api/v1/devices",
            json=device_data)
        device_id = create_response.json()["id"]

        # Update as manager
        response = manager_client.patch(
            f"/api/v1/devices/{device_id}",
            json={
                "name": "Manager Updated",
                "brand": "NewBrand",
                "ip": "192.168.1.200"
            })
        assert response.status_code == 200

        # Verify
        get_response = manager_client.get(f"/api/v1/devices/{device_id}")
        data = get_response.json()
        assert data["name"] == "Manager Updated"
        assert data["brand"] == "NewBrand"

    def test_update_device_deactivate(
        self, master_admin_client: E2ETestClient
    ):
        """Test deactivating a device."""

        # Create device
        device_data = {
            "name": "Deactivate Device",
            "brand": "BrandX",
            "model": "ModelY",
            "serial_number": "SN_DEACTIVATE",
            "ip": "192.168.1.111",
            "mac": "99:AA:BB:CC:DD:EE"
        }
        create_response = master_admin_client.post(
            "/api/v1/devices",
            json=device_data)
        device_id = create_response.json()["id"]

        # Deactivate
        response = master_admin_client.patch(
            f"/api/v1/devices/{device_id}",
            json={"is_active": False})
        assert response.status_code == 200

        # Verify
        get_response = master_admin_client.get(f"/api/v1/devices/{device_id}")
        assert get_response.json()["is_active"] is False

    def test_update_device_as_user_forbidden(
        self, master_admin_client: E2ETestClient, user_client: E2ETestClient
    ):
        """Test updating device as user (forbidden)."""
        # Create device as admin
        device_data = {
            "name": "User Update Device",
            "brand": "BrandX",
            "model": "ModelY",
            "serial_number": "SN_USER_UPDATE",
            "ip": "192.168.1.112",
            "mac": "AA:BB:CC:DD:EE:FF"
        }
        create_response = master_admin_client.post(
            "/api/v1/devices",
            json=device_data)
        device_id = create_response.json()["id"]

        # Try to update as user
        response = user_client.patch(
            f"/api/v1/devices/{device_id}",
            json={"name": "Forbidden Update"})
        assert response.status_code == 403

    def test_update_device_not_found(
        self, master_admin_client: E2ETestClient
    ):
        """Test updating non-existent device."""
        response = master_admin_client.patch(
            f"/api/v1/devices/{uuid4()}",
            json={"name": "Not Found"})
        assert response.status_code == 404


class TestDeviceDelete:
    """Test DELETE /devices/{id} endpoint."""

    def test_delete_device_as_master_admin(
        self, master_admin_client: E2ETestClient
    ):
        """Test deleting device as master admin."""

        # Create device
        device_data = {
            "name": "Delete Device",
            "brand": "BrandX",
            "model": "ModelY",
            "serial_number": "SN_DELETE1",
            "ip": "192.168.1.113",
            "mac": "BB:CC:DD:EE:FF:00"
        }
        create_response = master_admin_client.post(
            "/api/v1/devices",
            json=device_data)
        device_id = create_response.json()["id"]

        # Delete
        response = master_admin_client.delete(f"/api/v1/devices/{device_id}")
        assert response.status_code == 204

        # Verify deletion
        get_response = master_admin_client.get(f"/api/v1/devices/{device_id}")
        assert get_response.status_code == 404

    def test_delete_device_as_admin(
        self, regular_admin_client: E2ETestClient
    ):
        """Test deleting device as regular admin."""

        # Create device
        device_data = {
            "name": "Admin Delete Device",
            "brand": "BrandX",
            "model": "ModelY",
            "serial_number": "SN_DELETE2",
            "ip": "192.168.1.114",
            "mac": "CC:DD:EE:FF:00:11"
        }
        create_response = regular_admin_client.post(
            "/api/v1/devices",
            json=device_data)
        device_id = create_response.json()["id"]

        # Delete
        response = regular_admin_client.delete(f"/api/v1/devices/{device_id}")
        assert response.status_code == 204

    def test_delete_device_as_manager(
        self, master_admin_client: E2ETestClient, manager_client: E2ETestClient
    ):
        """Managers cannot delete devices (Polar policy: deny delete on Device for manager)."""
        device_data = {
            "name": "Manager Delete Device",
            "brand": "BrandX",
            "model": "ModelY",
            "serial_number": "SN_DELETE3",
            "ip": "192.168.1.115",
            "mac": "DD:EE:FF:00:11:22"
        }
        create_response = master_admin_client.post(
            "/api/v1/devices",
            json=device_data)
        device_id = create_response.json()["id"]

        response = manager_client.delete(f"/api/v1/devices/{device_id}")
        assert response.status_code == 403

    def test_delete_device_as_user_forbidden(
        self, master_admin_client: E2ETestClient, user_client: E2ETestClient
    ):
        """Test deleting device as user (forbidden)."""
        # Create device as admin
        device_data = {
            "name": "User Delete Device",
            "brand": "BrandX",
            "model": "ModelY",
            "serial_number": "SN_DELETE4",
            "ip": "192.168.1.116",
            "mac": "EE:FF:00:11:22:33"
        }
        create_response = master_admin_client.post(
            "/api/v1/devices",
            json=device_data)
        device_id = create_response.json()["id"]

        # Try to delete as user
        response = user_client.delete(f"/api/v1/devices/{device_id}")
        assert response.status_code == 403

    def test_delete_device_not_found(
        self, master_admin_client: E2ETestClient
    ):
        """Test deleting non-existent device."""
        response = master_admin_client.delete(f"/api/v1/devices/{uuid4()}")
        assert response.status_code == 404
