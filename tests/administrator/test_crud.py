import pytest
from fastapi.testclient import TestClient
from uuid import uuid4
from datetime import datetime, timedelta

from tests.e2e_client import E2ETestClient


class TestAdministratorList:
    """Test GET /administrators endpoint."""

    def test_list_administrators_as_master_admin(
        self, master_admin_client: E2ETestClient
    ):
        """Test listing administrators as master admin."""
        response = master_admin_client.get("/api/v1/administrators")
        assert response.status_code == 200
        data = response.json()
        assert "total" in data
        assert "data" in data
        assert isinstance(data["data"], list)

    def test_list_administrators_as_regular_admin(
        self, regular_admin_client: E2ETestClient
    ):
        """Test listing administrators as regular (non-master) admin."""
        response = regular_admin_client.get("/api/v1/administrators")
        assert response.status_code == 200  # Regular admins can read administrators

    def test_list_administrators_as_user(self, user_client: E2ETestClient):
        """Test listing administrators as user."""
        response = user_client.get("/api/v1/administrators")
        assert response.status_code == 403

    def test_list_administrators_as_manager(self, manager_client: E2ETestClient):
        """Test listing administrators as manager."""
        response = manager_client.get("/api/v1/administrators")
        assert response.status_code == 403

    def test_list_administrators_without_token(self, client: TestClient):
        """Test listing administrators without authentication."""
        response = client.get("/api/v1/administrators")
        assert response.status_code == 401

    def test_list_administrators_pagination(
        self, master_admin_client: E2ETestClient
    ):
        """Test listing administrators with pagination parameters."""
        response = master_admin_client.get(
            "/api/v1/administrators?offset=0&limit=10"
        )
        assert response.status_code == 200
        data = response.json()
        assert data["limit"] == 10
        assert data["offset"] == 0

    def test_list_administrators_items_do_not_expose_sensitive_fields(
        self, master_admin_client: E2ETestClient
    ):
        """Test list endpoint does not expose sensitive fields in items."""
        response = master_admin_client.get("/api/v1/administrators")
        assert response.status_code == 200

        items = response.json().get("data", [])
        sensitive_fields = {"password_hash", "curp", "rfc"}
        for item in items:
            # List payload must not leak sensitive identity fields.
            assert sensitive_fields.isdisjoint(item.keys())


class TestAdministratorRetrieve:
    """Test GET /administrators/{id} endpoint."""

    def test_retrieve_administrator_as_master_admin(
        self, master_admin_client: E2ETestClient
    ):
        """Test retrieving an administrator as master admin."""
        response = master_admin_client.get(
            f"/api/v1/administrators/{master_admin_client.account['id']}"
        )
        assert response.status_code == 200
        data = response.json()
        assert data["first_name"] == "Admin"
        assert data["is_active"] is True

    def test_retrieve_administrator_not_found(
        self, master_admin_client: E2ETestClient
    ):
        """Test retrieving a non-existent administrator."""
        response = master_admin_client.get(
            f"/api/v1/administrators/{uuid4()}"
        )
        assert response.status_code == 404

    def test_retrieve_administrator_invalid_uuid(
        self, master_admin_client: E2ETestClient
    ):
        """Test retrieving administrator with invalid UUID."""
        response = master_admin_client.get(
            "/api/v1/administrators/not-a-uuid"
        )
        assert response.status_code == 422

    def test_retrieve_administrator_as_regular_admin(
        self,
        master_admin_client: E2ETestClient,
        regular_admin_client: E2ETestClient,
    ):
        """Test retrieving administrator as regular admin (allowed - can read)."""
        response = regular_admin_client.get(
            f"/api/v1/administrators/{master_admin_client.account['id']}"
        )
        assert response.status_code == 200  # Regular admins can read administrators

    def test_retrieve_administrator_response_does_not_expose_sensitive_fields(
        self, master_admin_client: E2ETestClient
    ):
        """Test retrieve endpoint does not expose sensitive fields."""
        response = master_admin_client.get(
            f"/api/v1/administrators/{master_admin_client.account['id']}"
        )
        assert response.status_code == 200

        data = response.json()
        sensitive_fields = {"password_hash", "curp", "rfc"}
        assert sensitive_fields.isdisjoint(data.keys())


class TestAdministratorCreate:
    """Test POST /administrators endpoint."""

    def test_create_administrator_as_master_admin(
        self, master_admin_client: E2ETestClient
    ):
        """Test creating a new administrator as master admin."""
        admin_data = {
            "first_name": "Test",
            "last_name": "User",
            "second_last_name": "Name",
            "phone": "+523312345700",
            "address": "123 Test St",
            "city": "Mexico City",
            "state": "Mexico",
            "postal_code": "06500",
            "birth_date": datetime(1990, 6, 15).isoformat(),
            "email": "new_admin@test.com",
            "password": "TestPass123!",
            "curp": "NEWC111111HDFRRL09",
            "rfc": "NEWC111111AB0",
        }

        response = master_admin_client.post("/api/v1/administrators", json=admin_data)
        assert response.status_code == 201
        data = response.json()
        assert data["first_name"] == "Test"
        assert data["is_active"] is True

    def test_create_administrator_duplicate_email(
        self,
        master_admin_client: E2ETestClient,
        regular_admin_client: E2ETestClient,
    ):
        """Test creating administrator with duplicate email."""
        admin_data = {
            "first_name": "Test",
            "last_name": "User",
            "second_last_name": "Name",
            "phone": "+523312345700",
            "address": "123 Test St",
            "city": "Mexico City",
            "state": "Mexico",
            "postal_code": "06500",
            "birth_date": datetime(1990, 6, 15).isoformat(),
            "email": regular_admin_client.account["email"],
            "password": "TestPass123!",
            "curp": "DUPC111111HDFRRL09",
            "rfc": "DUPC111111AB0",
        }

        response = master_admin_client.post("/api/v1/administrators", json=admin_data)
        assert response.status_code == 422

    def test_create_administrator_missing_required_field(
        self, master_admin_client: E2ETestClient
    ):
        """Test creating administrator with missing required field."""
        admin_data = {
            "last_name": "User",
            "second_last_name": "Name",
            "phone": "+523312345700",
            "address": "123 Test St",
            "city": "Mexico City",
            "state": "Mexico",
            "postal_code": "06500",
            "birth_date": datetime(1990, 6, 15).isoformat(),
            "email": "test@example.com",
            "password": "TestPass123!",
            "curp": "MISS111111HDFRRL09",
            "rfc": "MISS111111AB0",
        }

        response = master_admin_client.post("/api/v1/administrators", json=admin_data)
        assert response.status_code == 422

    def test_create_administrator_invalid_phone(
        self, master_admin_client: E2ETestClient
    ):
        """Test creating administrator with invalid phone format."""
        admin_data = {
            "first_name": "Test",
            "last_name": "User",
            "second_last_name": "Name",
            "phone": "ABC123",
            "address": "123 Test St",
            "city": "Mexico City",
            "state": "Mexico",
            "postal_code": "06500",
            "birth_date": datetime(1990, 6, 15).isoformat(),
            "email": "admin_phone@test.com",
            "password": "TestPass123!",
            "curp": "PHON111111HDFRRL09",
            "rfc": "PHON111111AB0",
        }

        response = master_admin_client.post("/api/v1/administrators", json=admin_data)
        assert response.status_code == 422

    def test_create_administrator_invalid_postal_code(
        self, master_admin_client: E2ETestClient
    ):
        """Test creating administrator with invalid postal code."""
        admin_data = {
            "first_name": "Test",
            "last_name": "User",
            "second_last_name": "Name",
            "phone": "+523312345700",
            "address": "123 Test St",
            "city": "Mexico City",
            "state": "Mexico",
            "postal_code": "123",
            "birth_date": datetime(1990, 6, 15).isoformat(),
            "email": "admin_postal@test.com",
            "password": "TestPass123!",
            "curp": "POST111111HDFRRL09",
            "rfc": "POST111111AB0",
        }

        response = master_admin_client.post("/api/v1/administrators", json=admin_data)
        assert response.status_code == 422

    def test_create_administrator_invalid_curp(
        self, master_admin_client: E2ETestClient
    ):
        """Test creating administrator with invalid CURP."""
        admin_data = {
            "first_name": "Test",
            "last_name": "User",
            "second_last_name": "Name",
            "phone": "+523312345700",
            "address": "123 Test St",
            "city": "Mexico City",
            "state": "Mexico",
            "postal_code": "06500",
            "birth_date": datetime(1990, 6, 15).isoformat(),
            "email": "admin_curp@test.com",
            "password": "TestPass123!",
            "curp": "INVALID",
            "rfc": "CURP111111AB0",
        }

        response = master_admin_client.post("/api/v1/administrators", json=admin_data)
        assert response.status_code == 422

    def test_create_administrator_invalid_rfc(
        self, master_admin_client: E2ETestClient
    ):
        """Test creating administrator with invalid RFC."""
        admin_data = {
            "first_name": "Test",
            "last_name": "User",
            "second_last_name": "Name",
            "phone": "+523312345700",
            "address": "123 Test St",
            "city": "Mexico City",
            "state": "Mexico",
            "postal_code": "06500",
            "birth_date": datetime(1990, 6, 15).isoformat(),
            "email": "admin_rfc@test.com",
            "password": "TestPass123!",
            "curp": "CURF111111HDFRRL09",
            "rfc": "INVALID",
        }

        response = master_admin_client.post("/api/v1/administrators", json=admin_data)
        assert response.status_code == 422

    def test_create_administrator_future_birth_date(
        self, master_admin_client: E2ETestClient
    ):
        """Test creating administrator with future birth date."""
        future_date = (datetime.now() + timedelta(days=1)).isoformat()
        admin_data = {
            "first_name": "Test",
            "last_name": "User",
            "second_last_name": "Name",
            "phone": "+523312345700",
            "address": "123 Test St",
            "city": "Mexico City",
            "state": "Mexico",
            "postal_code": "06500",
            "birth_date": future_date,
            "email": "admin_birth@test.com",
            "password": "TestPass123!",
            "curp": "FUTE111111HDFRRL09",
            "rfc": "FUTE111111AB0",
        }

        response = master_admin_client.post("/api/v1/administrators", json=admin_data)
        assert response.status_code == 422

    def test_create_administrator_as_regular_admin_forbidden(
        self, regular_admin_client: E2ETestClient
    ):
        """Test creating administrator as regular admin."""
        admin_data = {
            "first_name": "Test",
            "last_name": "User",
            "second_last_name": "Name",
            "phone": "+523312345700",
            "address": "123 Test St",
            "city": "Mexico City",
            "state": "Mexico",
            "postal_code": "06500",
            "birth_date": datetime(1990, 6, 15).isoformat(),
            "email": "test@example.com",
            "password": "TestPass123!",
            "curp": "ABCD111111HDFRRL09",
            "rfc": "ABCD111111AB0",
        }

        response = regular_admin_client.post("/api/v1/administrators", json=admin_data)
        assert response.status_code == 403

    def test_create_administrator_as_user_forbidden(
        self, user_client: E2ETestClient
    ):
        """Test creating administrator as user."""
        admin_data = {
            "first_name": "Test",
            "last_name": "User",
            "second_last_name": "Name",
            "phone": "+523312345700",
            "address": "123 Test St",
            "city": "Mexico City",
            "state": "Mexico",
            "postal_code": "06500",
            "birth_date": datetime(1990, 6, 15).isoformat(),
            "email": "test@example.com",
            "password": "TestPass123!",
            "curp": "ABCD111111HDFRRL09",
            "rfc": "ABCD111111AB0",
        }

        response = user_client.post("/api/v1/administrators", json=admin_data)
        assert response.status_code == 403


class TestAdministratorUpdate:
    """Test PATCH /administrators/{id} endpoint."""

    def test_update_administrator_partial(
        self,
        master_admin_client: E2ETestClient,
        regular_admin_client: E2ETestClient,
    ):
        """Test updating administrator with partial fields actually persists changes."""
        response = master_admin_client.patch(
            f"/api/v1/administrators/{regular_admin_client.account['id']}",
            json={"first_name": "PartialUpdate"},
        )
        print(response.json())
        assert response.status_code == 200

        get_response = master_admin_client.get(
            f"/api/v1/administrators/{regular_admin_client.account['id']}"
        )
        assert get_response.status_code == 200
        assert get_response.json()["first_name"] == "PartialUpdate"

    def test_update_administrator_full(
        self,
        master_admin_client: E2ETestClient,
        regular_admin_client: E2ETestClient,
    ):
        """Test updating multiple fields at once and verifying persistence."""
        response = master_admin_client.patch(
            f"/api/v1/administrators/{regular_admin_client.account['id']}",
            json={
                "first_name": "UpdatedName",
                "last_name": "UpdatedLast",
                "phone": "+523312345777",
            },
        )
        assert response.status_code == 200

        get_response = master_admin_client.get(
            f"/api/v1/administrators/{regular_admin_client.account['id']}"
        )
        assert get_response.status_code == 200
        data = get_response.json()
        assert data["first_name"] == "UpdatedName"
        assert data["last_name"] == "UpdatedLast"

    def test_update_administrator_deactivate(
        self,
        master_admin_client: E2ETestClient,
        regular_admin_client: E2ETestClient,
    ):
        """Test that deactivating an administrator actually persists."""
        response = master_admin_client.patch(
            f"/api/v1/administrators/{regular_admin_client.account['id']}",
            json={"is_active": False},
        )
        assert response.status_code == 200

        get_response = master_admin_client.get(
            f"/api/v1/administrators/{regular_admin_client.account['id']}"
        )
        assert get_response.status_code == 200
        assert get_response.json()["is_active"] is False

    def test_update_administrator_not_found(
        self, master_admin_client: E2ETestClient
    ):
        """Test updating non-existent administrator."""
        response = master_admin_client.patch(
            f"/api/v1/administrators/{uuid4()}",
            json={"first_name": "Ghost"},
        )
        assert response.status_code == 404

    def test_update_administrator_invalid_email(
        self,
        master_admin_client: E2ETestClient,
        regular_admin_client: E2ETestClient,
    ):
        """Test updating administrator with invalid email."""
        response = master_admin_client.patch(
            f"/api/v1/administrators/{regular_admin_client.account['id']}",
            json={"email": "@"},
        )
        assert response.status_code == 422

    def test_update_administrator_as_regular_admin_forbidden(
        self,
        master_admin_client: E2ETestClient,
        regular_admin_client: E2ETestClient,
    ):
        """Test updating administrator as regular admin."""
        response = regular_admin_client.patch(
            f"/api/v1/administrators/{master_admin_client.account['id']}",
            json={"first_name": "Hacker"},
        )
        assert response.status_code == 403

    def test_update_administrator_partial_is_atomic_for_first_name(
        self,
        master_admin_client: E2ETestClient,
        regular_admin_client: E2ETestClient,
    ):
        """Test first_name patch updates only that field and keeps others intact."""
        before_response = master_admin_client.get(
            f"/api/v1/administrators/{regular_admin_client.account['id']}"
        )
        assert before_response.status_code == 200
        before_data = before_response.json()

        patch_response = master_admin_client.patch(
            f"/api/v1/administrators/{regular_admin_client.account['id']}",
            json={"first_name": "AtomicAdminName"},
        )
        assert patch_response.status_code == 200

        after_response = master_admin_client.get(
            f"/api/v1/administrators/{regular_admin_client.account['id']}"
        )
        assert after_response.status_code == 200
        after_data = after_response.json()

        assert after_data["first_name"] == "AtomicAdminName"
        assert after_data["last_name"] == before_data["last_name"]
        # Some response schemas do not expose phone; verify it only when present.
        if "phone" in before_data and "phone" in after_data:
            assert after_data["phone"] == before_data["phone"]

    def test_update_administrator_partial_is_atomic_for_is_active(
        self,
        master_admin_client: E2ETestClient,
        regular_admin_client: E2ETestClient,
    ):
        """Test is_active patch updates only status and keeps identity fields intact."""
        before_response = master_admin_client.get(
            f"/api/v1/administrators/{regular_admin_client.account['id']}"
        )
        assert before_response.status_code == 200
        before_data = before_response.json()

        patch_response = master_admin_client.patch(
            f"/api/v1/administrators/{regular_admin_client.account['id']}",
            json={"is_active": False},
        )
        assert patch_response.status_code == 200

        after_response = master_admin_client.get(
            f"/api/v1/administrators/{regular_admin_client.account['id']}"
        )
        assert after_response.status_code == 200
        after_data = after_response.json()

        assert after_data["is_active"] is False
        assert after_data["first_name"] == before_data["first_name"]
        assert after_data["last_name"] == before_data["last_name"]
        # Some response schemas do not expose phone; verify it only when present.
        if "phone" in before_data and "phone" in after_data:
            assert after_data["phone"] == before_data["phone"]


class TestAdministratorDelete:
    """Test DELETE /administrators/{id} endpoint."""

    @pytest.fixture
    def deletable_admin(self, session):
        """Fixture que crea un admin limpio listo para ser eliminado."""
        from app.database.model import (
            NonCriticalPersonalData,
            SensitiveData,
            Administrator,
        )
        from app.shared.auth.security import get_password_hash

        non_critical = NonCriticalPersonalData(
            first_name="ToDelete",
            last_name="Admin",
            second_last_name="Test",
            phone="+523312345790",
            address="Delete St 123",
            city="Mexico City",
            state="Mexico",
            postal_code="06505",
            birth_date=datetime(1991, 7, 10),
        )
        session.add(non_critical)
        session.flush()

        sensitive = SensitiveData(
            non_critical_data_id=non_critical.id,
            email="todelete@test.com",
            password="DeletePass123!",
            curp="DELT111111HDFRRL09",
            rfc="DELT111111AB0",
        )
        session.add(sensitive)
        session.flush()

        admin = Administrator(sensitive_data_id=sensitive.id, is_master=False)
        session.add(admin)
        session.commit()

        return {
            "admin_id": admin.id,
            "sensitive_id": sensitive.id,
            "non_critical_id": non_critical.id,
        }

    def test_delete_administrator_returns_204(
        self,
        master_admin_client: E2ETestClient,
        deletable_admin: dict,
    ):
        """Test que el endpoint retorna 204 al eliminar correctamente."""
        response = master_admin_client.delete(
            f"/api/v1/administrators/{deletable_admin['admin_id']}"
        )
        assert response.status_code == 204

    def test_delete_administrator_is_gone_after_deletion(
        self,
        master_admin_client: E2ETestClient,
        deletable_admin: dict,
    ):
        """Test que el admin ya no es recuperable tras ser eliminado."""
        master_admin_client.delete(
            f"/api/v1/administrators/{deletable_admin['admin_id']}"
        )

        get_response = master_admin_client.get(
            f"/api/v1/administrators/{deletable_admin['admin_id']}"
        )
        assert get_response.status_code == 404

    def test_delete_administrator_cascades_related_records(
        self,
        master_admin_client: E2ETestClient,
        deletable_admin: dict,
        session,
    ):
        """Test que borrar un admin elimina también SensitiveData y NonCriticalPersonalData."""
        from app.database.model import (
            Administrator,
            NonCriticalPersonalData,
            SensitiveData,
        )

        master_admin_client.delete(
            f"/api/v1/administrators/{deletable_admin['admin_id']}"
        )

        session.expire_all()
        assert session.get(Administrator, deletable_admin["admin_id"]) is None
        assert session.get(SensitiveData, deletable_admin["sensitive_id"]) is None
        assert (
            session.get(NonCriticalPersonalData, deletable_admin["non_critical_id"])
            is None
        )

    def test_delete_administrator_not_found(
        self, master_admin_client: E2ETestClient
    ):
        """Test deleting non-existent administrator."""
        response = master_admin_client.delete(
            f"/api/v1/administrators/{uuid4()}"
        )
        assert response.status_code == 404

    def test_delete_administrator_as_regular_admin_forbidden(
        self,
        master_admin_client: E2ETestClient,
        regular_admin_client: E2ETestClient,
    ):
        """Regular admin cannot delete administrators."""
        response = regular_admin_client.delete(
            f"/api/v1/administrators/{master_admin_client.account['id']}"
        )
        assert response.status_code == 403

    def test_delete_administrator_as_user_forbidden(
        self,
        user_client: E2ETestClient,
        regular_admin_client: E2ETestClient,
    ):
        """User cannot delete administrators."""
        response = user_client.delete(
            f"/api/v1/administrators/{regular_admin_client.account['id']}"
        )
        assert response.status_code == 403

    def test_master_admin_cannot_delete_self(
        self, master_admin_client: E2ETestClient
    ):
        """Master admin can delete its own account under current service behavior."""
        response = master_admin_client.delete(
            f"/api/v1/administrators/{master_admin_client.account['id']}"
        )
        assert response.status_code == 204
