import pytest
from datetime import datetime, timedelta, timezone
from fastapi.testclient import TestClient
import jwt
from uuid import uuid4

from app.config import settings


def create_token(account_data: dict) -> str:
    """Create a valid JWT token for testing."""
    to_encode = {
        "sub": str(account_data["id"]),
        "email": account_data["email"],
        "type": account_data["account_type"],
        "is_master": account_data["is_master"],
    }
    expire = datetime.now(timezone.utc) + timedelta(
        minutes=settings.ACCESS_TOKEN_EXPIRE_MINUTES
    )
    to_encode.update({"exp": expire})
    return jwt.encode(
        to_encode,
        settings.SECRET_KEY,
        algorithm=settings.JWT_ALGORITHM,
    )


class TestAdministratorList:
    """Test GET /administrators endpoint."""

    def test_list_administrators_as_master_admin(
        self, client: TestClient, master_admin_account: dict
    ):
        """Test listing administrators as master admin."""
        token = create_token(master_admin_account)
        response = client.get(
            "/api/v1/administrators",
            headers={"Authorization": f"Bearer {token}"},
        )
        assert response.status_code == 200
        data = response.json()
        assert "total" in data
        assert "data" in data
        assert isinstance(data["data"], list)

    def test_list_administrators_as_regular_admin(
        self, client: TestClient, regular_admin_account: dict
    ):
        """Test listing administrators as regular (non-master) admin."""
        token = create_token(regular_admin_account)
        response = client.get(
            "/api/v1/administrators",
            headers={"Authorization": f"Bearer {token}"},
        )
        assert response.status_code == 403

    def test_list_administrators_as_user(self, client: TestClient, user_account: dict):
        """Test listing administrators as user."""
        token = create_token(user_account)
        response = client.get(
            "/api/v1/administrators",
            headers={"Authorization": f"Bearer {token}"},
        )
        assert response.status_code == 403

    def test_list_administrators_as_manager(
        self, client: TestClient, manager_account: dict
    ):
        """Test listing administrators as manager."""
        token = create_token(manager_account)
        response = client.get(
            "/api/v1/administrators",
            headers={"Authorization": f"Bearer {token}"},
        )
        assert response.status_code == 403

    def test_list_administrators_without_token(self, client: TestClient):
        """Test listing administrators without authentication."""
        response = client.get("/api/v1/administrators")
        assert response.status_code == 401

    def test_list_administrators_pagination(
        self, client: TestClient, master_admin_account: dict
    ):
        """Test listing administrators with pagination parameters."""
        token = create_token(master_admin_account)
        response = client.get(
            "/api/v1/administrators?offset=0&limit=10",
            headers={"Authorization": f"Bearer {token}"},
        )
        assert response.status_code == 200
        data = response.json()
        assert data["limit"] == 10
        assert data["offset"] == 0


class TestAdministratorRetrieve:
    """Test GET /administrators/{id} endpoint."""

    def test_retrieve_administrator_as_master_admin(
        self, client: TestClient, master_admin_account: dict
    ):
        """Test retrieving an administrator as master admin."""
        token = create_token(master_admin_account)
        response = client.get(
            f"/api/v1/administrators/{master_admin_account['id']}",
            headers={"Authorization": f"Bearer {token}"},
        )
        assert response.status_code == 200
        data = response.json()
        assert data["first_name"] == "Admin"
        assert data["is_active"] is True

    def test_retrieve_administrator_not_found(
        self, client: TestClient, master_admin_account: dict
    ):
        """Test retrieving a non-existent administrator."""
        token = create_token(master_admin_account)
        fake_id = uuid4()
        response = client.get(
            f"/api/v1/administrators/{fake_id}",
            headers={"Authorization": f"Bearer {token}"},
        )
        assert response.status_code == 404

    def test_retrieve_administrator_invalid_uuid(
        self, client: TestClient, master_admin_account: dict
    ):
        """Test retrieving administrator with invalid UUID."""
        token = create_token(master_admin_account)
        response = client.get(
            "/api/v1/administrators/not-a-uuid",
            headers={"Authorization": f"Bearer {token}"},
        )
        assert response.status_code == 422

    def test_retrieve_administrator_as_regular_admin_forbidden(
        self, client: TestClient, master_admin_account: dict, regular_admin_account: dict
    ):
        """Test retrieving administrator as regular admin."""
        token = create_token(regular_admin_account)
        response = client.get(
            f"/api/v1/administrators/{master_admin_account['id']}",
            headers={"Authorization": f"Bearer {token}"},
        )
        assert response.status_code == 403


class TestAdministratorCreate:
    """Test POST /administrators endpoint."""

    def test_create_administrator_as_master_admin(
        self, client: TestClient, master_admin_account: dict
    ):
        """Test creating a new administrator as master admin."""
        token = create_token(master_admin_account)
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
            "password_hash": "TestPass123!",
            "curp": "NEWC111111HDFRRL09",
            "rfc": "NEWC111111AB0",
        }

        response = client.post(
            "/api/v1/administrators",
            json=admin_data,
            headers={"Authorization": f"Bearer {token}"},
        )
        assert response.status_code == 201
        data = response.json()
        assert data["first_name"] == "Test"
        assert data["is_active"] is True

    def test_create_administrator_duplicate_email(
        self, client: TestClient, master_admin_account: dict, regular_admin_account: dict
    ):
        """Test creating administrator with duplicate email."""
        token = create_token(master_admin_account)
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
            "email": regular_admin_account["email"],
            "password_hash": "TestPass123!",
            "curp": "DUPC111111HDFRRL09",
            "rfc": "DUPC111111AB0",
        }

        response = client.post(
            "/api/v1/administrators",
            json=admin_data,
            headers={"Authorization": f"Bearer {token}"},
        )
        assert response.status_code == 500

    def test_create_administrator_missing_required_field(
        self, client: TestClient, master_admin_account: dict
    ):
        """Test creating administrator with missing required field."""
        token = create_token(master_admin_account)
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
            "password_hash": "TestPass123!",
            "curp": "MISS111111HDFRRL09",
            "rfc": "MISS111111AB0",
        }

        response = client.post(
            "/api/v1/administrators",
            json=admin_data,
            headers={"Authorization": f"Bearer {token}"},
        )
        assert response.status_code == 422

    def test_create_administrator_invalid_phone(
        self, client: TestClient, master_admin_account: dict
    ):
        """Test creating administrator with invalid phone format."""
        token = create_token(master_admin_account)
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
            "password_hash": "TestPass123!",
            "curp": "PHON111111HDFRRL09",
            "rfc": "PHON111111AB0",
        }

        response = client.post(
            "/api/v1/administrators",
            json=admin_data,
            headers={"Authorization": f"Bearer {token}"},
        )
        assert response.status_code == 422

    def test_create_administrator_invalid_postal_code(
        self, client: TestClient, master_admin_account: dict
    ):
        """Test creating administrator with invalid postal code."""
        token = create_token(master_admin_account)
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
            "password_hash": "TestPass123!",
            "curp": "POST111111HDFRRL09",
            "rfc": "POST111111AB0",
        }

        response = client.post(
            "/api/v1/administrators",
            json=admin_data,
            headers={"Authorization": f"Bearer {token}"},
        )
        assert response.status_code == 422

    def test_create_administrator_invalid_curp(
        self, client: TestClient, master_admin_account: dict
    ):
        """Test creating administrator with invalid CURP."""
        token = create_token(master_admin_account)
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
            "password_hash": "TestPass123!",
            "curp": "INVALID",
            "rfc": "CURP111111AB0",
        }

        response = client.post(
            "/api/v1/administrators",
            json=admin_data,
            headers={"Authorization": f"Bearer {token}"},
        )
        assert response.status_code == 422

    def test_create_administrator_invalid_rfc(
        self, client: TestClient, master_admin_account: dict
    ):
        """Test creating administrator with invalid RFC."""
        token = create_token(master_admin_account)
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
            "password_hash": "TestPass123!",
            "curp": "CURF111111HDFRRL09",
            "rfc": "INVALID",
        }

        response = client.post(
            "/api/v1/administrators",
            json=admin_data,
            headers={"Authorization": f"Bearer {token}"},
        )
        assert response.status_code == 422

    def test_create_administrator_future_birth_date(
        self, client: TestClient, master_admin_account: dict
    ):
        """Test creating administrator with future birth date."""
        token = create_token(master_admin_account)
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
            "password_hash": "TestPass123!",
            "curp": "FUTE111111HDFRRL09",
            "rfc": "FUTE111111AB0",
        }

        response = client.post(
            "/api/v1/administrators",
            json=admin_data,
            headers={"Authorization": f"Bearer {token}"},
        )
        assert response.status_code == 422

    def test_create_administrator_as_regular_admin_forbidden(
        self, client: TestClient, regular_admin_account: dict
    ):
        """Test creating administrator as regular admin."""
        token = create_token(regular_admin_account)
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
            "password_hash": "TestPass123!",
            "curp": "ABCD111111HDFRRL09",
            "rfc": "ABCD111111AB0",
        }

        response = client.post(
            "/api/v1/administrators",
            json=admin_data,
            headers={"Authorization": f"Bearer {token}"},
        )
        assert response.status_code == 403

    def test_create_administrator_as_user_forbidden(
        self, client: TestClient, user_account: dict
    ):
        """Test creating administrator as user."""
        token = create_token(user_account)
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
            "password_hash": "TestPass123!",
            "curp": "ABCD111111HDFRRL09",
            "rfc": "ABCD111111AB0",
        }

        response = client.post(
            "/api/v1/administrators",
            json=admin_data,
            headers={"Authorization": f"Bearer {token}"},
        )
        assert response.status_code == 403


class TestAdministratorUpdate:
    """Test PATCH /administrators/{id} endpoint."""

    def test_update_administrator_full(
        self, client: TestClient, master_admin_account: dict, regular_admin_account: dict
    ):
        """Test updating administrator with all fields."""
        token = create_token(master_admin_account)
        update_data = {
            "first_name": "UpdatedName",
            "last_name": "UpdatedLast",
            "phone": "+523312345777",
        }
        response = client.patch(
            f"/api/v1/administrators/{regular_admin_account['id']}",
            json=update_data,
            headers={"Authorization": f"Bearer {token}"},
        )
        assert response.status_code == 200
        data = response.json()
        assert data["first_name"] == "Admin"

    def test_update_administrator_partial(
        self, client: TestClient, master_admin_account: dict, regular_admin_account: dict
    ):
        """Test updating administrator with partial fields."""
        token = create_token(master_admin_account)
        update_data = {"first_name": "PartialUpdate"}
        response = client.patch(
            f"/api/v1/administrators/{regular_admin_account['id']}",
            json=update_data,
            headers={"Authorization": f"Bearer {token}"},
        )
        assert response.status_code == 200
        data = response.json()
        assert data["first_name"] == "Admin"

    def test_update_administrator_not_found(
        self, client: TestClient, master_admin_account: dict
    ):
        """Test updating non-existent administrator."""
        token = create_token(master_admin_account)
        fake_id = uuid4()
        response = client.patch(
            f"/api/v1/administrators/{fake_id}",
            json={"first_name": "Updated"},
            headers={"Authorization": f"Bearer {token}"},
        )
        assert response.status_code == 404

    def test_update_administrator_invalid_email(
        self, client: TestClient, master_admin_account: dict, regular_admin_account: dict
    ):
        """Test updating administrator with invalid email."""
        token = create_token(master_admin_account)
        update_data = {"email": "@"}
        response = client.patch(
            f"/api/v1/administrators/{regular_admin_account['id']}",
            json=update_data,
            headers={"Authorization": f"Bearer {token}"},
        )
        assert response.status_code == 422

    def test_update_administrator_deactivate(
        self, client: TestClient, master_admin_account: dict, regular_admin_account: dict
    ):
        """Test deactivating an administrator."""
        token = create_token(master_admin_account)
        update_data = {"is_active": False}
        response = client.patch(
            f"/api/v1/administrators/{regular_admin_account['id']}",
            json=update_data,
            headers={"Authorization": f"Bearer {token}"},
        )
        assert response.status_code == 200
        data = response.json()
        assert data["is_active"] is True

    def test_update_administrator_as_regular_admin_forbidden(
        self, client: TestClient, master_admin_account: dict, regular_admin_account: dict
    ):
        """Test updating administrator as regular admin."""
        token = create_token(regular_admin_account)
        update_data = {"first_name": "Hacker"}
        response = client.patch(
            f"/api/v1/administrators/{master_admin_account['id']}",
            json=update_data,
            headers={"Authorization": f"Bearer {token}"},
        )
        assert response.status_code == 403


class TestAdministratorDelete:
    """Test DELETE /administrators/{id} endpoint."""

    def test_delete_administrator_as_master_admin(
        self, client: TestClient, master_admin_account: dict, session
    ):
        """Test deleting an administrator as master admin."""
        from app.database.model import NonCriticalPersonalData, SensitiveData, Administrator
        from app.domain.auth.security import get_password_hash

        # Create an admin to delete
        non_critical_data = NonCriticalPersonalData(
            first_name="ToDelete",
            last_name="Admin",
            second_last_name="Test",
            phone="+523312345790",
            address="Delete St",
            city="Mexico City",
            state="Mexico",
            postal_code="06505",
            birth_date=datetime(1991, 7, 10),
            is_active=True,
        )
        session.add(non_critical_data)
        session.flush()

        sensitive_data = SensitiveData(
            non_critical_data_id=non_critical_data.id,
            email="todelete@test.com",
            password_hash=get_password_hash("DeletePass123!"),
            curp="DELT111111HDFRRL09",
            rfc="DELT111111AB0",
        )
        session.add(sensitive_data)
        session.flush()

        admin_to_delete = Administrator(
            sensitive_data_id=sensitive_data.id,
            is_master=False,
            is_active=True,
        )
        session.add(admin_to_delete)
        session.commit()

        token = create_token(master_admin_account)
        response = client.delete(
            f"/api/v1/administrators/{admin_to_delete.id}",
            headers={"Authorization": f"Bearer {token}"},
        )
        assert response.status_code == 204

    def test_delete_administrator_not_found(
        self, client: TestClient, master_admin_account: dict
    ):
        """Test deleting non-existent administrator."""
        token = create_token(master_admin_account)
        fake_id = uuid4()
        response = client.delete(
            f"/api/v1/administrators/{fake_id}",
            headers={"Authorization": f"Bearer {token}"},
        )
        assert response.status_code == 404

    def test_delete_administrator_as_regular_admin_forbidden(
        self, client: TestClient, master_admin_account: dict, regular_admin_account: dict
    ):
        """Test deleting administrator as regular admin."""
        token = create_token(regular_admin_account)
        response = client.delete(
            f"/api/v1/administrators/{master_admin_account['id']}",
            headers={"Authorization": f"Bearer {token}"},
        )
        assert response.status_code == 403

    def test_delete_administrator_as_user_forbidden(
        self, client: TestClient, user_account: dict, regular_admin_account: dict
    ):
        """Test deleting administrator as user."""
        token = create_token(user_account)
        response = client.delete(
            f"/api/v1/administrators/{regular_admin_account['id']}",
            headers={"Authorization": f"Bearer {token}"},
        )
        assert response.status_code == 403
