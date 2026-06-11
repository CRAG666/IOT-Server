import pytest
from fastapi.testclient import TestClient
from uuid import uuid4

from tests.e2e_client import E2ETestClient


class TestDevicePoliciesAPI:
    """Test OSO policies for Device endpoints at API level."""

    def test_manager_can_list_devices(
        self, manager_client: E2ETestClient
    ):
        """Manager should be able to list devices (read permission)."""
        response = manager_client.get("/api/v1/devices")
        assert response.status_code == 200

    def test_admin_can_delete_devices(
        self, regular_admin_client: E2ETestClient
    ):
        """Admin should be able to delete devices."""
        fake_device_id = str(uuid4())
        response = regular_admin_client.delete(f"/api/v1/devices/{fake_device_id}")
        # 404 because device doesn't exist, but passed authorization check
        assert response.status_code in [404, 422]

    def test_user_can_read_devices(
        self, user_client: E2ETestClient
    ):
        """User should be able to read devices."""
        response = user_client.get("/api/v1/devices")
        assert response.status_code == 200

    def test_user_cannot_create_devices(
        self, user_client: E2ETestClient
    ):
        """User should NOT be able to create devices."""
        response = user_client.post(
            "/api/v1/devices",
            json={
                "name": "Test Device",
                "description": "Test",
                "location": "Test Location",
            })
        assert response.status_code == 403


class TestUserPoliciesAPI:
    """Test OSO policies for User endpoints at API level."""

    def test_manager_can_list_users(
        self, manager_client: E2ETestClient
    ):
        """Manager should be able to list users (read permission)."""
        response = manager_client.get("/api/v1/users")
        assert response.status_code == 200

    def test_manager_cannot_delete_users(
        self, manager_client: E2ETestClient
    ):
        """Manager should NOT be able to delete users."""
        fake_user_id = str(uuid4())
        response = manager_client.delete(f"/api/v1/users/{fake_user_id}")
        assert response.status_code == 403

    def test_admin_can_delete_users(
        self, regular_admin_client: E2ETestClient
    ):
        """Admin should be able to delete users."""
        fake_user_id = str(uuid4())
        response = regular_admin_client.delete(f"/api/v1/users/{fake_user_id}")
        # 404 because user doesn't exist, but passed authorization check
        assert response.status_code in [404, 422]


class TestManagerPoliciesAPI:
    """Test OSO policies for Manager endpoints at API level."""

    def test_manager_cannot_delete_managers(
        self, manager_client: E2ETestClient
    ):
        """Manager should NOT be able to delete other managers."""
        fake_manager_id = str(uuid4())
        response = manager_client.delete(f"/api/v1/managers/{fake_manager_id}")
        assert response.status_code == 403

    def test_admin_can_delete_managers(
        self, regular_admin_client: E2ETestClient
    ):
        """Admin should be able to delete managers."""
        fake_manager_id = str(uuid4())
        response = regular_admin_client.delete(f"/api/v1/managers/{fake_manager_id}")
        # 404 because manager doesn't exist, but passed authorization check
        assert response.status_code in [404, 422]

    def test_user_cannot_list_managers(
        self, user_client: E2ETestClient
    ):
        """Regular user should NOT be able to list managers."""
        response = user_client.get("/api/v1/managers")
        assert response.status_code == 403


class TestAdministratorPoliciesAPI:
    """Test OSO policies for Administrator endpoints at API level."""

    def test_regular_admin_can_read_administrators(
        self, regular_admin_client: E2ETestClient
    ):
        """Regular admin should be able to read administrators."""
        response = regular_admin_client.get("/api/v1/administrators")
        assert response.status_code == 200

    def test_regular_admin_cannot_create_administrators(
        self, regular_admin_client: E2ETestClient
    ):
        """Regular admin should NOT be able to create administrators."""
        response = regular_admin_client.post(
            "/api/v1/administrators",
            json={
                "first_name": "New",
                "last_name": "Admin",
                "email": "new_admin@test.com",
                "password": "Password123!",
            })
        assert response.status_code == 403

    def test_regular_admin_cannot_delete_administrators(
        self, regular_admin_client: E2ETestClient
    ):
        """Regular admin should NOT be able to delete administrators."""
        fake_admin_id = str(uuid4())
        response = regular_admin_client.delete(
            f"/api/v1/administrators/{fake_admin_id}")
        assert response.status_code == 403

    def test_master_admin_can_delete_administrators(
        self, master_admin_client: E2ETestClient
    ):
        """Master admin should be able to delete administrators."""
        fake_admin_id = str(uuid4())
        response = master_admin_client.delete(
            f"/api/v1/administrators/{fake_admin_id}")
        # 404 because admin doesn't exist, but passed authorization check
        assert response.status_code in [404, 422]

    def test_manager_cannot_read_administrators(
        self, manager_client: E2ETestClient
    ):
        """Manager should NOT be able to read administrators."""
        response = manager_client.get("/api/v1/administrators")
        assert response.status_code == 403

    def test_user_cannot_read_administrators(
        self, user_client: E2ETestClient
    ):
        """Regular user should NOT be able to read administrators."""
        response = user_client.get("/api/v1/administrators")
        assert response.status_code == 403


class TestCrossResourcePolicies:
    """Test OSO policies across different resources to verify consistency."""

    def test_manager_write_permissions_consistent(
        self, manager_client: E2ETestClient
    ):
        """Manager should have consistent write permissions across resources."""

        # Manager CAN create devices
        response = manager_client.post(
            "/api/v1/devices",
            json={
                "name": "Test Device",
                "description": "Test",
                "location": "Test Location",
            })
        assert response.status_code in [200, 201, 422]  # 422 if validation fails

        # Manager CAN create users
        response = manager_client.post(
            "/api/v1/users",
            json={
                "first_name": "Test",
                "last_name": "User",
                "email": "test@example.com",
                "password": "Password123!",
            })
        assert response.status_code in [200, 201, 422]

    def test_master_admin_universal_access(
        self, master_admin_client: E2ETestClient
    ):
        """Master admin should have access to all endpoints."""

        # Can access devices
        response = master_admin_client.get("/api/v1/devices")
        assert response.status_code == 200

        # Can access users
        response = master_admin_client.get("/api/v1/users")
        assert response.status_code == 200

        # Can access managers
        response = master_admin_client.get("/api/v1/managers")
        assert response.status_code == 200

        # Can access administrators
        response = master_admin_client.get("/api/v1/administrators")
        assert response.status_code == 200
