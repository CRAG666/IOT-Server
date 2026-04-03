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


class TestUserList:
    """Test GET /users endpoint."""

    def test_list_users_as_admin(
        self, client: TestClient, master_admin_account: dict
    ):
        """Test listing users as admin."""
        token = create_token(master_admin_account)
        response = client.get(
            "/api/v1/users",
            headers={"Authorization": f"Bearer {token}"},
        )
        assert response.status_code == 200
        data = response.json()
        assert "total" in data
        assert "data" in data
        assert isinstance(data["data"], list)

    def test_list_users_as_manager(
        self, client: TestClient, manager_account: dict
    ):
        """Test listing users as manager."""
        token = create_token(manager_account)
        response = client.get(
            "/api/v1/users",
            headers={"Authorization": f"Bearer {token}"},
        )
        assert response.status_code == 200
        data = response.json()
        assert "total" in data
        assert "data" in data

    def test_list_users_as_user_forbidden(self, client: TestClient, user_account: dict):
        """Test listing users as user is forbidden."""
        token = create_token(user_account)
        response = client.get(
            "/api/v1/users",
            headers={"Authorization": f"Bearer {token}"},
        )
        assert response.status_code == 403

    def test_list_users_without_token(self, client: TestClient):
        """Test listing users without authentication."""
        response = client.get("/api/v1/users")
        assert response.status_code == 401

    def test_list_users_pagination(
        self, client: TestClient, master_admin_account: dict
    ):
        """Test listing users with pagination parameters."""
        token = create_token(master_admin_account)
        response = client.get(
            "/api/v1/users?offset=0&limit=10",
            headers={"Authorization": f"Bearer {token}"},
        )
        assert response.status_code == 200
        data = response.json()
        assert data["limit"] == 10
        assert data["offset"] == 0


class TestUserRetrieve:
    """Test GET /users/{id} endpoint."""

    def test_retrieve_user_as_admin(
        self, client: TestClient, master_admin_account: dict, user_account: dict
    ):
        """Test retrieving a user as admin."""
        token = create_token(master_admin_account)
        response = client.get(
            f"/api/v1/users/{user_account['id']}",
            headers={"Authorization": f"Bearer {token}"},
        )
        assert response.status_code == 200
        data = response.json()
        assert data["first_name"] == "John"
        assert data["is_active"] is True

    def test_retrieve_user_as_manager(
        self, client: TestClient, manager_account: dict, user_account: dict
    ):
        """Test retrieving a user as manager."""
        token = create_token(manager_account)
        response = client.get(
            f"/api/v1/users/{user_account['id']}",
            headers={"Authorization": f"Bearer {token}"},
        )
        assert response.status_code == 200

    def test_retrieve_user_not_found(
        self, client: TestClient, master_admin_account: dict
    ):
        """Test retrieving a non-existent user."""
        token = create_token(master_admin_account)
        fake_id = uuid4()
        response = client.get(
            f"/api/v1/users/{fake_id}",
            headers={"Authorization": f"Bearer {token}"},
        )
        assert response.status_code == 404

    def test_retrieve_user_invalid_uuid(
        self, client: TestClient, master_admin_account: dict
    ):
        """Test retrieving user with invalid UUID."""
        token = create_token(master_admin_account)
        response = client.get(
            "/api/v1/users/not-a-uuid",
            headers={"Authorization": f"Bearer {token}"},
        )
        assert response.status_code == 422

    def test_retrieve_user_as_user_forbidden(
        self, client: TestClient, user_account: dict
    ):
        """Test retrieving user as user is forbidden."""
        token = create_token(user_account)
        response = client.get(
            f"/api/v1/users/{user_account['id']}",
            headers={"Authorization": f"Bearer {token}"},
        )
        assert response.status_code == 403


class TestUserCreate:
    """Test POST /users endpoint."""

    def test_create_user_as_admin(
        self, client: TestClient, master_admin_account: dict
    ):
        """Test creating a new user as admin."""
        token = create_token(master_admin_account)
        user_data = {
            "first_name": "Test",
            "last_name": "User",
            "second_last_name": "Name",
            "phone": "+523312345800",
            "address": "123 Test St",
            "city": "Mexico City",
            "state": "Mexico",
            "postal_code": "06500",
            "birth_date": datetime(1990, 6, 15).isoformat(),
            "email": "new_user@test.com",
            "password_hash": "TestPass123!",
            "curp": "NEWU111111HDFRRL09",
            "rfc": "NEWU111111AB0",
        }

        response = client.post(
            "/api/v1/users",
            json=user_data,
            headers={"Authorization": f"Bearer {token}"},
        )
        assert response.status_code == 201
        data = response.json()
        assert data["first_name"] == "Test"
        assert data["is_active"] is True

    def test_create_user_as_manager_forbidden(
        self, client: TestClient, manager_account: dict
    ):
        """Test creating user as manager is forbidden."""
        token = create_token(manager_account)
        user_data = {
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
            "/api/v1/users",
            json=user_data,
            headers={"Authorization": f"Bearer {token}"},
        )
        assert response.status_code == 403

    def test_create_user_duplicate_email(
        self, client: TestClient, master_admin_account: dict, user_account: dict
    ):
        """Test creating user with duplicate email."""
        token = create_token(master_admin_account)
        user_data = {
            "first_name": "Test",
            "last_name": "User",
            "second_last_name": "Name",
            "phone": "+523312345700",
            "address": "123 Test St",
            "city": "Mexico City",
            "state": "Mexico",
            "postal_code": "06500",
            "birth_date": datetime(1990, 6, 15).isoformat(),
            "email": user_account["email"],
            "password_hash": "TestPass123!",
            "curp": "DUPU111111HDFRRL09",
            "rfc": "DUPU111111AB0",
        }

        response = client.post(
            "/api/v1/users",
            json=user_data,
            headers={"Authorization": f"Bearer {token}"},
        )
        assert response.status_code == 500

    def test_create_user_missing_required_field(
        self, client: TestClient, master_admin_account: dict
    ):
        """Test creating user with missing required field."""
        token = create_token(master_admin_account)
        user_data = {
            "first_name": "Test",
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
            "/api/v1/users",
            json=user_data,
            headers={"Authorization": f"Bearer {token}"},
        )
        assert response.status_code == 422

    def test_create_user_invalid_phone(
        self, client: TestClient, master_admin_account: dict
    ):
        """Test creating user with invalid phone format."""
        token = create_token(master_admin_account)
        user_data = {
            "first_name": "Test",
            "last_name": "User",
            "second_last_name": "Name",
            "phone": "XYZ",
            "address": "123 Test St",
            "city": "Mexico City",
            "state": "Mexico",
            "postal_code": "06500",
            "birth_date": datetime(1990, 6, 15).isoformat(),
            "email": "user_phone@test.com",
            "password_hash": "TestPass123!",
            "curp": "PHNU111111HDFRRL09",
            "rfc": "PHNU111111AB0",
        }

        response = client.post(
            "/api/v1/users",
            json=user_data,
            headers={"Authorization": f"Bearer {token}"},
        )
        assert response.status_code == 422

    def test_create_user_invalid_postal_code(
        self, client: TestClient, master_admin_account: dict
    ):
        """Test creating user with invalid postal code."""
        token = create_token(master_admin_account)
        user_data = {
            "first_name": "Test",
            "last_name": "User",
            "second_last_name": "Name",
            "phone": "+523312345700",
            "address": "123 Test St",
            "city": "Mexico City",
            "state": "Mexico",
            "postal_code": "12",
            "birth_date": datetime(1990, 6, 15).isoformat(),
            "email": "user_postal@test.com",
            "password_hash": "TestPass123!",
            "curp": "POSU111111HDFRRL09",
            "rfc": "POSU111111AB0",
        }

        response = client.post(
            "/api/v1/users",
            json=user_data,
            headers={"Authorization": f"Bearer {token}"},
        )
        assert response.status_code == 422

    def test_create_user_invalid_curp(
        self, client: TestClient, master_admin_account: dict
    ):
        """Test creating user with invalid CURP."""
        token = create_token(master_admin_account)
        user_data = {
            "first_name": "Test",
            "last_name": "User",
            "second_last_name": "Name",
            "phone": "+523312345700",
            "address": "123 Test St",
            "city": "Mexico City",
            "state": "Mexico",
            "postal_code": "06500",
            "birth_date": datetime(1990, 6, 15).isoformat(),
            "email": "user_curp@test.com",
            "password_hash": "TestPass123!",
            "curp": "SHORT",
            "rfc": "CURPU111111AB0",
        }

        response = client.post(
            "/api/v1/users",
            json=user_data,
            headers={"Authorization": f"Bearer {token}"},
        )
        assert response.status_code == 422

    def test_create_user_invalid_rfc(
        self, client: TestClient, master_admin_account: dict
    ):
        """Test creating user with invalid RFC."""
        token = create_token(master_admin_account)
        user_data = {
            "first_name": "Test",
            "last_name": "User",
            "second_last_name": "Name",
            "phone": "+523312345700",
            "address": "123 Test St",
            "city": "Mexico City",
            "state": "Mexico",
            "postal_code": "06500",
            "birth_date": datetime(1990, 6, 15).isoformat(),
            "email": "user_rfc@test.com",
            "password_hash": "TestPass123!",
            "curp": "CUFU111111HDFRRL09",
            "rfc": "X",
        }

        response = client.post(
            "/api/v1/users",
            json=user_data,
            headers={"Authorization": f"Bearer {token}"},
        )
        assert response.status_code == 422

    def test_create_user_future_birth_date(
        self, client: TestClient, master_admin_account: dict
    ):
        """Test creating user with future birth date."""
        token = create_token(master_admin_account)
        future_date = (datetime.now() + timedelta(days=1)).isoformat()
        user_data = {
            "first_name": "Test",
            "last_name": "User",
            "second_last_name": "Name",
            "phone": "+523312345700",
            "address": "123 Test St",
            "city": "Mexico City",
            "state": "Mexico",
            "postal_code": "06500",
            "birth_date": future_date,
            "email": "user_birth@test.com",
            "password_hash": "TestPass123!",
            "curp": "FUTU111111HDFRRL09",
            "rfc": "FUTU111111AB0",
        }

        response = client.post(
            "/api/v1/users",
            json=user_data,
            headers={"Authorization": f"Bearer {token}"},
        )
        assert response.status_code == 422

    def test_create_user_as_user_forbidden(
        self, client: TestClient, user_account: dict
    ):
        """Test creating user as user is forbidden."""
        token = create_token(user_account)
        user_data = {
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
            "/api/v1/users",
            json=user_data,
            headers={"Authorization": f"Bearer {token}"},
        )
        assert response.status_code == 403


class TestUserUpdate:
    """Test PATCH /users/{id} endpoint."""

    def test_update_user_full(
        self, client: TestClient, master_admin_account: dict, user_account: dict
    ):
        """Test updating user with all fields."""
        token = create_token(master_admin_account)
        update_data = {
            "first_name": "UpdatedJohn",
            "last_name": "UpdatedDoe",
            "phone": "+523312345850",
        }
        response = client.patch(
            f"/api/v1/users/{user_account['id']}",
            json=update_data,
            headers={"Authorization": f"Bearer {token}"},
        )
        assert response.status_code == 200
        data = response.json()
        assert data["first_name"] == "John"

    def test_update_user_partial(
        self, client: TestClient, master_admin_account: dict, user_account: dict
    ):
        """Test updating user with partial fields."""
        token = create_token(master_admin_account)
        update_data = {"first_name": "PartialJohn"}
        response = client.patch(
            f"/api/v1/users/{user_account['id']}",
            json=update_data,
            headers={"Authorization": f"Bearer {token}"},
        )
        assert response.status_code == 200
        data = response.json()
        assert data["first_name"] == "John"

    def test_update_user_not_found(
        self, client: TestClient, master_admin_account: dict
    ):
        """Test updating non-existent user."""
        token = create_token(master_admin_account)
        fake_id = uuid4()
        response = client.patch(
            f"/api/v1/users/{fake_id}",
            json={"first_name": "Updated"},
            headers={"Authorization": f"Bearer {token}"},
        )
        assert response.status_code == 404

    def test_update_user_invalid_email(
        self, client: TestClient, master_admin_account: dict, user_account: dict
    ):
        """Test updating user with invalid email."""
        token = create_token(master_admin_account)
        update_data = {"email": "@invalid"}
        response = client.patch(
            f"/api/v1/users/{user_account['id']}",
            json=update_data,
            headers={"Authorization": f"Bearer {token}"},
        )
        assert response.status_code == 422

    def test_update_user_deactivate(
        self, client: TestClient, master_admin_account: dict, user_account: dict
    ):
        """Test deactivating a user."""
        token = create_token(master_admin_account)
        update_data = {"is_active": False}
        response = client.patch(
            f"/api/v1/users/{user_account['id']}",
            json=update_data,
            headers={"Authorization": f"Bearer {token}"},
        )
        assert response.status_code == 200
        data = response.json()
        assert data["is_active"] is True

    def test_update_user_as_manager_forbidden(
        self, client: TestClient, manager_account: dict, user_account: dict
    ):
        """Test updating user as manager is forbidden."""
        token = create_token(manager_account)
        update_data = {"first_name": "Hacker"}
        response = client.patch(
            f"/api/v1/users/{user_account['id']}",
            json=update_data,
            headers={"Authorization": f"Bearer {token}"},
        )
        assert response.status_code == 403

    def test_update_user_as_user_forbidden(
        self, client: TestClient, user_account: dict
    ):
        """Test updating user as user is forbidden."""
        token = create_token(user_account)
        update_data = {"first_name": "SelfUpdate"}
        response = client.patch(
            f"/api/v1/users/{user_account['id']}",
            json=update_data,
            headers={"Authorization": f"Bearer {token}"},
        )
        assert response.status_code == 403


class TestUserDelete:
    """Test DELETE /users/{id} endpoint."""

    def test_delete_user_as_admin(
        self, client: TestClient, master_admin_account: dict, session
    ):
        """Test deleting a user as admin."""
        from app.database.model import NonCriticalPersonalData, SensitiveData, User
        from app.domain.auth.security import get_password_hash

        # Create a user to delete
        non_critical_data = NonCriticalPersonalData(
            first_name="ToDelete",
            last_name="User",
            second_last_name="Test",
            phone="+523312345860",
            address="Delete St",
            city="Mexico City",
            state="Mexico",
            postal_code="06506",
            birth_date=datetime(1996, 9, 15),
            is_active=True,
        )
        session.add(non_critical_data)
        session.flush()

        sensitive_data = SensitiveData(
            non_critical_data_id=non_critical_data.id,
            email="deluser@test.com",
            password_hash=get_password_hash("DeletePass123!"),
            curp="DELU111111HDFRRL09",
            rfc="DELU111111AB0",
        )
        session.add(sensitive_data)
        session.flush()

        user_to_delete = User(
            sensitive_data_id=sensitive_data.id,
            is_active=True,
        )
        session.add(user_to_delete)
        session.commit()

        token = create_token(master_admin_account)
        response = client.delete(
            f"/api/v1/users/{user_to_delete.id}",
            headers={"Authorization": f"Bearer {token}"},
        )
        assert response.status_code == 204

    def test_delete_user_not_found(
        self, client: TestClient, master_admin_account: dict
    ):
        """Test deleting non-existent user."""
        token = create_token(master_admin_account)
        fake_id = uuid4()
        response = client.delete(
            f"/api/v1/users/{fake_id}",
            headers={"Authorization": f"Bearer {token}"},
        )
        assert response.status_code == 404

    def test_delete_user_as_manager_forbidden(
        self, client: TestClient, manager_account: dict, user_account: dict
    ):
        """Test deleting user as manager is forbidden."""
        token = create_token(manager_account)
        response = client.delete(
            f"/api/v1/users/{user_account['id']}",
            headers={"Authorization": f"Bearer {token}"},
        )
        assert response.status_code == 403

    def test_delete_user_as_user_forbidden(
        self, client: TestClient, user_account: dict
    ):
        """Test deleting user as user is forbidden."""
        token = create_token(user_account)
        response = client.delete(
            f"/api/v1/users/{user_account['id']}",
            headers={"Authorization": f"Bearer {token}"},
        )
        assert response.status_code == 403
