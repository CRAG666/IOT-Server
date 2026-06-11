import pytest
from fastapi.testclient import TestClient
from uuid import uuid4
from datetime import datetime, timezone

from tests.e2e_client import E2ETestClient


class TestManagerList:
    """Test GET /managers endpoint."""

    def test_list_managers_as_master_admin(
        self, master_admin_client: E2ETestClient
    ):
        """Test listing managers as master admin."""
        response = master_admin_client.get("/api/v1/managers")
        assert response.status_code == 200
        data = response.json()
        assert "total" in data
        assert "data" in data
        assert isinstance(data["data"], list)

    def test_list_managers_as_regular_admin(
        self, regular_admin_client: E2ETestClient
    ):
        """Test listing managers as regular admin."""
        response = regular_admin_client.get("/api/v1/managers")
        assert response.status_code == 200
        data = response.json()
        assert "total" in data
        assert "data" in data

    def test_list_managers_as_manager(
        self, manager_client: E2ETestClient
    ):
        """Test listing managers as manager."""
        response = manager_client.get("/api/v1/managers")
        assert response.status_code == 200
        data = response.json()
        assert "total" in data
        assert "data" in data

    def test_list_managers_as_user_forbidden(
        self, user_client: E2ETestClient
    ):
        """Test listing managers as user (forbidden)."""
        response = user_client.get("/api/v1/managers")
        assert response.status_code == 403

    def test_list_managers_without_token(self, client: TestClient):
        """Test listing managers without authentication."""
        response = client.get("/api/v1/managers")
        assert response.status_code == 401

    def test_list_managers_pagination(
        self, master_admin_client: E2ETestClient
    ):
        """Test listing managers with pagination parameters."""
        response = master_admin_client.get("/api/v1/managers?offset=0&limit=10")
        assert response.status_code == 200
        data = response.json()
        assert data["limit"] == 10
        assert data["offset"] == 0


class TestManagerRetrieve:
    """Test GET /managers/{id} endpoint."""

    def test_retrieve_manager_as_master_admin(
        self, master_admin_client: E2ETestClient, manager_client: E2ETestClient
    ):
        """Test retrieving a manager as master admin."""
        response = master_admin_client.get(
            f"/api/v1/managers/{manager_client.account['id']}")
        assert response.status_code == 200
        data = response.json()
        assert data["first_name"] == "Jane"  # From fixture
        assert data["is_active"] is True

    def test_retrieve_manager_not_found(
        self, master_admin_client: E2ETestClient
    ):
        """Test retrieving a non-existent manager."""
        response = master_admin_client.get(
            f"/api/v1/managers/{uuid4()}")
        assert response.status_code == 404

    def test_retrieve_manager_invalid_uuid(
        self, master_admin_client: E2ETestClient
    ):
        """Test retrieving manager with invalid UUID."""
        response = master_admin_client.get("/api/v1/managers/not-a-uuid")
        assert response.status_code == 422

    def test_retrieve_manager_as_manager(
        self, manager_client: E2ETestClient
    ):
        """Test retrieving manager as manager (read-only)."""
        response = manager_client.get(
            f"/api/v1/managers/{manager_client.account['id']}")
        assert response.status_code == 200

    def test_retrieve_manager_as_user_forbidden(
        self, user_client: E2ETestClient, manager_client: E2ETestClient
    ):
        """Test retrieving manager as user (forbidden)."""
        response = user_client.get(
            f"/api/v1/managers/{manager_client.account['id']}")
        assert response.status_code == 403


class TestManagerCreate:
    """Test POST /managers endpoint."""

    def test_create_manager_as_master_admin(
        self, master_admin_client: E2ETestClient
    ):
        """Test creating a new manager as master admin."""
        manager_data = {
            "first_name": "Test",
            "last_name": "Manager",
            "second_last_name": "Name",
            "phone": "+523312345701",
            "address": "123 Test St",
            "city": "Mexico City",
            "state": "Mexico",
            "postal_code": "06500",
            "birth_date": datetime(1990, 6, 15).isoformat(),
            "email": "new_manager@test.com",
            "password": "TestPass123!",
            "curp": "GAEM900615HDFLRN08",
            "rfc": "GAEM900615AB0",
        }

        response = master_admin_client.post("/api/v1/managers", json=manager_data)
        assert response.status_code == 201
        data = response.json()
        assert data["first_name"] == "Test"
        assert data["is_active"] is True

    def test_create_manager_as_admin(
        self, regular_admin_client: E2ETestClient
    ):
        """Test creating manager as regular admin."""
        manager_data = {
            "first_name": "Admin",
            "last_name": "Manager",
            "second_last_name": "Name",
            "phone": "+523312345702",
            "address": "123 Test St",
            "city": "Mexico City",
            "state": "Mexico",
            "postal_code": "06500",
            "birth_date": datetime(1990, 6, 15).isoformat(),
            "email": "admin_manager@test.com",
            "password": "TestPass123!",
            "curp": "HAEM900615HDFLRN00",
            "rfc": "HAEM900615AB0",
        }

        response = regular_admin_client.post("/api/v1/managers", json=manager_data)
        assert response.status_code == 201

    def test_create_manager_as_manager_forbidden(
        self, manager_client: E2ETestClient
    ):
        """Test creating manager as manager (forbidden - read-only)."""
        manager_data = {
            "first_name": "Forbidden",
            "last_name": "Manager",
            "second_last_name": "Name",
            "phone": "+523312345703",
            "address": "123 Test St",
            "city": "Mexico City",
            "state": "Mexico",
            "postal_code": "06500",
            "birth_date": datetime(1990, 6, 15).isoformat(),
            "email": "forbidden_manager@test.com",
            "password": "TestPass123!",
            "curp": "IAEM900615HDFLRN02",
            "rfc": "IAEM900615AB0",
        }

        response = manager_client.post("/api/v1/managers", json=manager_data)
        assert response.status_code == 403

    def test_create_manager_as_user_forbidden(
        self, user_client: E2ETestClient
    ):
        """Test creating manager as user (forbidden)."""
        manager_data = {
            "first_name": "User",
            "last_name": "Manager",
            "second_last_name": "Name",
            "phone": "+523312345704",
            "address": "123 Test St",
            "city": "Mexico City",
            "state": "Mexico",
            "postal_code": "06500",
            "birth_date": datetime(1990, 6, 15).isoformat(),
            "email": "user_manager@test.com",
            "password": "TestPass123!",
            "curp": "JAEM900615HDFLRN04",
            "rfc": "JAEM900615AB0",
        }

        response = user_client.post("/api/v1/managers", json=manager_data)
        assert response.status_code == 403

    def test_create_manager_duplicate_email(
        self, master_admin_client: E2ETestClient, manager_client: E2ETestClient
    ):
        """Test creating manager with duplicate email."""
        manager_data = {
            "first_name": "Duplicate",
            "last_name": "Manager",
            "second_last_name": "Name",
            "phone": "+523312345705",
            "address": "123 Test St",
            "city": "Mexico City",
            "state": "Mexico",
            "postal_code": "06500",
            "birth_date": datetime(1990, 6, 15).isoformat(),
            "email": manager_client.account["email"],
            "password": "TestPass123!",
            "curp": "KAEM900615HDFLRN06",
            "rfc": "KAEM900615AB0",
        }

        response = master_admin_client.post("/api/v1/managers", json=manager_data)
        assert response.status_code == 409

    def test_create_manager_missing_required_field(
        self, master_admin_client: E2ETestClient
    ):
        """Test creating manager with missing required field."""
        manager_data = {
            "last_name": "Manager",
            "second_last_name": "Name",
            "phone": "+523312345706",
            "address": "123 Test St",
            "city": "Mexico City",
            "state": "Mexico",
            "postal_code": "06500",
            "birth_date": datetime(1990, 6, 15).isoformat(),
            "email": "missing@test.com",
            "password": "TestPass123!",
            "curp": "LAEM900615HDFLRN08",
            "rfc": "LAEM900615AB0",
        }

        response = master_admin_client.post("/api/v1/managers", json=manager_data)
        assert response.status_code == 422

    def test_create_manager_invalid_phone(
        self, master_admin_client: E2ETestClient
    ):
        """Test creating manager with invalid phone format."""
        manager_data = {
            "first_name": "Phone",
            "last_name": "Manager",
            "second_last_name": "Name",
            "phone": "ABC123",
            "address": "123 Test St",
            "city": "Mexico City",
            "state": "Mexico",
            "postal_code": "06500",
            "birth_date": datetime(1990, 6, 15).isoformat(),
            "email": "phone_manager@test.com",
            "password": "TestPass123!",
            "curp": "MAEM900615HDFLRN00",
            "rfc": "MAEM900615AB0",
        }

        response = master_admin_client.post("/api/v1/managers", json=manager_data)
        assert response.status_code == 422

    def test_create_manager_invalid_curp(
        self, master_admin_client: E2ETestClient
    ):
        """Test creating manager with invalid CURP."""
        manager_data = {
            "first_name": "Curp",
            "last_name": "Manager",
            "second_last_name": "Name",
            "phone": "+523312345707",
            "address": "123 Test St",
            "city": "Mexico City",
            "state": "Mexico",
            "postal_code": "06500",
            "birth_date": datetime(1990, 6, 15).isoformat(),
            "email": "curp_manager@test.com",
            "password": "TestPass123!",
            "curp": "INVALID",
            "rfc": "CMAN111111AB0",
        }

        response = master_admin_client.post("/api/v1/managers", json=manager_data)
        assert response.status_code == 422


class TestManagerUpdate:
    """Test PATCH /managers/{id} endpoint."""

    def test_update_manager_partial_as_master_admin(
        self, master_admin_client: E2ETestClient, manager_client: E2ETestClient
    ):
        """Test updating manager with partial fields as master admin."""

        response = master_admin_client.patch(
            f"/api/v1/managers/{manager_client.account['id']}",
            json={"first_name": "PartialUpdate"})
        assert response.status_code == 200

        # Verify
        get_response = master_admin_client.get(
            f"/api/v1/managers/{manager_client.account['id']}")
        assert get_response.status_code == 200
        assert get_response.json()["first_name"] == "PartialUpdate"

    def test_update_manager_full_as_admin(
        self, regular_admin_client: E2ETestClient, manager_client: E2ETestClient
    ):
        """Test updating multiple manager fields as admin."""

        response = regular_admin_client.patch(
            f"/api/v1/managers/{manager_client.account['id']}",
            json={
                "first_name": "UpdatedName",
                "last_name": "UpdatedLast",
            })
        assert response.status_code == 200

        # Verify
        get_response = regular_admin_client.get(
            f"/api/v1/managers/{manager_client.account['id']}")
        data = get_response.json()
        assert data["first_name"] == "UpdatedName"
        assert data["last_name"] == "UpdatedLast"

    def test_update_manager_deactivate(
        self, master_admin_client: E2ETestClient, manager_client: E2ETestClient
    ):
        """Test deactivating a manager."""

        response = master_admin_client.patch(
            f"/api/v1/managers/{manager_client.account['id']}",
            json={"is_active": False})
        assert response.status_code == 200

        # Verify
        get_response = master_admin_client.get(
            f"/api/v1/managers/{manager_client.account['id']}")
        assert get_response.json()["is_active"] is False

        # Reactivate for other tests
        master_admin_client.patch(
            f"/api/v1/managers/{manager_client.account['id']}",
            json={"is_active": True})

    def test_update_manager_as_manager_forbidden(
        self, master_admin_client: E2ETestClient, manager_client: E2ETestClient
    ):
        """Test updating manager as manager (forbidden - read-only)."""
        # Create another manager to update
        manager_data = {
            "first_name": "Target",
            "last_name": "Manager",
            "second_last_name": "Name",
            "phone": "+523312345708",
            "address": "123 Test St",
            "city": "Mexico City",
            "state": "Mexico",
            "postal_code": "06500",
            "birth_date": datetime(1990, 6, 15).isoformat(),
            "email": "target_manager@test.com",
            "password": "TestPass123!",
            "curp": "NAEM900615HDFLRN02",
            "rfc": "NAEM900615AB0",
        }
        create_response = master_admin_client.post(
            "/api/v1/managers",
            json=manager_data)
        target_id = create_response.json()["id"]

        # Try to update as manager
        response = manager_client.patch(
            f"/api/v1/managers/{target_id}",
            json={"first_name": "Forbidden"})
        assert response.status_code == 403

    def test_update_manager_as_user_forbidden(
        self, user_client: E2ETestClient, manager_client: E2ETestClient
    ):
        """Test updating manager as user (forbidden)."""
        response = user_client.patch(
            f"/api/v1/managers/{manager_client.account['id']}",
            json={"first_name": "Forbidden"})
        assert response.status_code == 403

    def test_update_manager_not_found(
        self, master_admin_client: E2ETestClient
    ):
        """Test updating non-existent manager."""
        response = master_admin_client.patch(
            f"/api/v1/managers/{uuid4()}",
            json={"first_name": "Not Found"})
        assert response.status_code == 404


class TestManagerDelete:
    """Test DELETE /managers/{id} endpoint."""

    def test_delete_manager_as_master_admin(
        self, master_admin_client: E2ETestClient
    ):
        """Test deleting manager as master admin."""

        # Create manager
        manager_data = {
            "first_name": "Delete",
            "last_name": "Manager",
            "second_last_name": "Name",
            "phone": "+523312345709",
            "address": "123 Test St",
            "city": "Mexico City",
            "state": "Mexico",
            "postal_code": "06500",
            "birth_date": datetime(1990, 6, 15).isoformat(),
            "email": "delete_manager@test.com",
            "password": "TestPass123!",
            "curp": "OAEM900615HDFLRN06",
            "rfc": "OAEM900615AB0",
        }
        create_response = master_admin_client.post(
            "/api/v1/managers",
            json=manager_data)
        manager_id = create_response.json()["id"]

        # Delete
        response = master_admin_client.delete(f"/api/v1/managers/{manager_id}")
        assert response.status_code == 204

        # Verify deletion
        get_response = master_admin_client.get(f"/api/v1/managers/{manager_id}")
        assert get_response.status_code == 404

    def test_delete_manager_as_admin(
        self, regular_admin_client: E2ETestClient
    ):
        """Test deleting manager as regular admin."""

        # Create manager
        manager_data = {
            "first_name": "AdminDelete",
            "last_name": "Manager",
            "second_last_name": "Name",
            "phone": "+523312345710",
            "address": "123 Test St",
            "city": "Mexico City",
            "state": "Mexico",
            "postal_code": "06500",
            "birth_date": datetime(1990, 6, 15).isoformat(),
            "email": "admin_delete_manager@test.com",
            "password": "TestPass123!",
            "curp": "PAEM900615HDFLRN08",
            "rfc": "PAEM900615AB0",
        }
        create_response = regular_admin_client.post(
            "/api/v1/managers",
            json=manager_data)
        manager_id = create_response.json()["id"]

        # Delete
        response = regular_admin_client.delete(f"/api/v1/managers/{manager_id}")
        assert response.status_code == 204

    def test_delete_manager_as_manager_forbidden(
        self, master_admin_client: E2ETestClient, manager_client: E2ETestClient
    ):
        """Test deleting manager as manager (forbidden - read-only)."""
        # Create manager as admin
        manager_data = {
            "first_name": "ManagerDelete",
            "last_name": "Manager",
            "second_last_name": "Name",
            "phone": "+523312345711",
            "address": "123 Test St",
            "city": "Mexico City",
            "state": "Mexico",
            "postal_code": "06500",
            "birth_date": datetime(1990, 6, 15).isoformat(),
            "email": "manager_delete@test.com",
            "password": "TestPass123!",
            "curp": "QAEM900615HDFLRN00",
            "rfc": "QAEM900615AB0",
        }
        create_response = master_admin_client.post(
            "/api/v1/managers",
            json=manager_data)
        manager_id = create_response.json()["id"]

        # Try to delete as manager
        response = manager_client.delete(f"/api/v1/managers/{manager_id}")
        assert response.status_code == 403

    def test_delete_manager_as_user_forbidden(
        self, user_client: E2ETestClient, manager_client: E2ETestClient
    ):
        """Test deleting manager as user (forbidden)."""
        response = user_client.delete(
            f"/api/v1/managers/{manager_client.account['id']}")
        assert response.status_code == 403

    def test_delete_manager_not_found(
        self, master_admin_client: E2ETestClient
    ):
        """Test deleting non-existent manager."""
        response = master_admin_client.delete(f"/api/v1/managers/{uuid4()}")
        assert response.status_code == 404
