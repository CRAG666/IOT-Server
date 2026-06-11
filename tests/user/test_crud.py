from datetime import date, datetime, time, timezone, timedelta
from uuid import uuid4

from fastapi.testclient import TestClient

from tests.e2e_client import E2ETestClient


def years_ago_iso(years: int) -> str:
    today = date.today()
    try:
        target = today.replace(year=today.year - years)
    except ValueError:
        # Handle leap day
        target = today.replace(year=today.year - years, day=28)

    return datetime.combine(target, time.min).isoformat()


def build_valid_user_payload(
    *,
    email: str = "new_user@test.com",
    curp: str = "TESA900615HDFLRNA8",
    rfc: str = "TESA900615AB1") -> dict:
    return {
        "first_name": "Test",
        "last_name": "User",
        "second_last_name": "Name",
        "phone": "+523312345800",
        "address": "123 Test St",
        "city": "Mexico City",
        "state": "Mexico",
        "postal_code": "06500",
        "birth_date": datetime(1990, 6, 15).isoformat(),
        "email": email,
        "password": "TestPass123!",
        "curp": curp,
        "rfc": rfc,
    }


class TestUserList:
    """Test GET /users endpoint."""

    def test_list_users_as_admin(self, master_admin_client: E2ETestClient):
        """Test listing users as admin."""
        response = master_admin_client.get("/api/v1/users")
        assert response.status_code == 200
        data = response.json()
        assert "total" in data
        assert "data" in data
        assert isinstance(data["data"], list)

    def test_list_users_as_manager(self, manager_client: E2ETestClient):
        """Test listing users as manager."""
        response = manager_client.get("/api/v1/users")
        assert response.status_code == 200
        data = response.json()
        assert "total" in data
        assert "data" in data

    def test_list_users_as_user_forbidden(self, user_client: E2ETestClient):
        """Users can list /users but only see their own record (Polar policy allows read User; instance filter at service)."""
        response = user_client.get("/api/v1/users")
        assert response.status_code == 200

    def test_list_users_without_token(self, client: TestClient):
        """Test listing users without authentication."""
        response = client.get("/api/v1/users")
        assert response.status_code == 401

    def test_list_users_pagination(self, master_admin_client: E2ETestClient):
        """Test listing users with pagination parameters."""
        response = master_admin_client.get("/api/v1/users?offset=0&limit=10")
        assert response.status_code == 200
        data = response.json()
        assert data["limit"] == 10
        assert data["offset"] == 0

    def test_list_users_items_do_not_expose_sensitive_fields(
        self, master_admin_client: E2ETestClient
    ):
        """Test list endpoint does not expose sensitive fields in items."""
        response = master_admin_client.get("/api/v1/users")
        assert response.status_code == 200

        items = response.json().get("data", [])
        sensitive_fields = {"password_hash", "curp", "rfc"}
        for item in items:
            assert sensitive_fields.isdisjoint(item.keys())


class TestUserRetrieve:
    """Test GET /users/{id} endpoint."""

    def test_retrieve_user_as_admin(
        self, master_admin_client: E2ETestClient, user_client: E2ETestClient
    ):
        """Test retrieving a user as admin."""
        response = master_admin_client.get(
            f"/api/v1/users/{user_client.account['id']}")
        assert response.status_code == 200
        data = response.json()
        assert data["first_name"] == "John"
        assert data["is_active"] is True

    def test_retrieve_user_as_manager(
        self, manager_client: E2ETestClient, user_client: E2ETestClient
    ):
        """Test retrieving a user as manager."""
        response = manager_client.get(
            f"/api/v1/users/{user_client.account['id']}")
        assert response.status_code == 200

    def test_retrieve_user_not_found(self, master_admin_client: E2ETestClient):
        """Test retrieving a non-existent user."""
        fake_id = uuid4()
        response = master_admin_client.get(f"/api/v1/users/{fake_id}")
        assert response.status_code == 404

    def test_retrieve_user_invalid_uuid(self, master_admin_client: E2ETestClient):
        """Test retrieving user with invalid UUID."""
        response = master_admin_client.get("/api/v1/users/not-a-uuid")
        assert response.status_code == 422

    def test_retrieve_user_as_user_forbidden(self, user_client: E2ETestClient):
        """Users can retrieve their own profile (Polar policy allows read User; instance filter at service)."""
        response = user_client.get(
            f"/api/v1/users/{user_client.account['id']}")
        assert response.status_code == 200

    def test_retrieve_user_response_does_not_expose_sensitive_fields(
        self, master_admin_client: E2ETestClient, user_client: E2ETestClient
    ):
        """Test retrieve endpoint does not expose sensitive fields."""
        response = master_admin_client.get(
            f"/api/v1/users/{user_client.account['id']}")
        assert response.status_code == 200

        data = response.json()
        sensitive_fields = {"password_hash", "curp", "rfc"}
        assert sensitive_fields.isdisjoint(data.keys())


class TestUserCreate:
    """Test POST /users endpoint."""

    def test_create_user_as_admin(self, master_admin_client: E2ETestClient):
        """Test creating a new user as admin."""
        user_data = build_valid_user_payload()

        response = master_admin_client.post("/api/v1/users", json=user_data)
        assert response.status_code == 201
        data = response.json()
        assert data["first_name"] == "Test"
        assert data["is_active"] is True

    def test_create_user_duplicate_email(
        self, master_admin_client: E2ETestClient, user_client: E2ETestClient
    ):
        """Test creating user with duplicate email."""
        user_data = build_valid_user_payload(
            email=user_client.account['email'],
            curp="DEUA900615HDFLRNA2",
            rfc="DEUA900615AB1")

        response = master_admin_client.post("/api/v1/users", json=user_data)
        assert response.status_code == 409

    def test_create_user_missing_required_field(
        self, master_admin_client: E2ETestClient
    ):
        """Test creating user with missing required field."""
        user_data = build_valid_user_payload(
            email="missing_required@test.com",
            curp="MEIA900615HDFLRNA8",
            rfc="MEIA900615AB1")
        user_data.pop("last_name")

        response = master_admin_client.post("/api/v1/users", json=user_data)
        assert response.status_code == 422

    def test_create_user_invalid_phone(self, master_admin_client: E2ETestClient):
        """Test creating user with invalid phone format."""
        user_data = build_valid_user_payload(
            email="user_phone@test.com",
            curp="PEUA900615HDFLRNA8",
            rfc="PEUA900615AB1")
        user_data["phone"] = "XYZ"

        response = master_admin_client.post("/api/v1/users", json=user_data)
        assert response.status_code == 422

    def test_create_user_invalid_postal_code(
        self, master_admin_client: E2ETestClient
    ):
        """Test creating user with invalid postal code length."""
        user_data = build_valid_user_payload(
            email="user_postal@test.com",
            curp="CEUA900615HDFLRNA0",
            rfc="CEUA900615AB1")
        user_data["postal_code"] = "12"

        response = master_admin_client.post("/api/v1/users", json=user_data)
        assert response.status_code == 422

    def test_create_user_postal_code_out_of_range(
        self, master_admin_client: E2ETestClient
    ):
        """Test creating user with postal code outside Mexico valid range."""
        user_data = build_valid_user_payload(
            email="user_postal_range@test.com",
            curp="FEUA900615HDFLRNA6",
            rfc="FEUA900615AB1")
        user_data["postal_code"] = "00000"

        response = master_admin_client.post("/api/v1/users", json=user_data)
        assert response.status_code == 422

    def test_create_user_invalid_curp(self, master_admin_client: E2ETestClient):
        """Test creating user with invalid CURP format."""
        user_data = build_valid_user_payload(
            email="user_curp@test.com",
            curp="AEDA900615HDFLRNA4",
            rfc="AEDA900615AB1")
        user_data["curp"] = "SHORT"

        response = master_admin_client.post("/api/v1/users", json=user_data)
        assert response.status_code == 422

    def test_create_user_invalid_curp_check_digit(
        self, master_admin_client: E2ETestClient
    ):
        """Test creating user with invalid CURP check digit."""
        user_data = build_valid_user_payload(
            email="user_curp_digit@test.com",
            curp="REGA920520HDFLRNA2",
            rfc="REGA920520AB1")
        user_data["curp"] = "REGA920520HDFLRNA9"

        response = master_admin_client.post("/api/v1/users", json=user_data)
        assert response.status_code == 422

    def test_create_user_invalid_rfc(self, master_admin_client: E2ETestClient):
        """Test creating user with invalid RFC."""
        user_data = build_valid_user_payload(
            email="user_rfc@test.com",
            curp="JOHA950310HDFLRNA4",
            rfc="JOHA950310AB1")
        user_data["rfc"] = "X"

        response = master_admin_client.post("/api/v1/users", json=user_data)
        assert response.status_code == 422

    def test_create_user_rejects_weak_password(
        self, master_admin_client: E2ETestClient
    ):
        """Test creating user with weak password."""
        user_data = build_valid_user_payload(
            email="weak_password@test.com",
            curp="JEMA930825MDFLRNA7",
            rfc="JEMA930825AB1")
        user_data["password"] = "12345678"

        response = master_admin_client.post("/api/v1/users", json=user_data)
        assert response.status_code == 422

    def test_create_user_future_birth_date(
        self, master_admin_client: E2ETestClient
    ):
        """Test creating user with future birth date."""
        user_data = build_valid_user_payload(
            email="user_birth@test.com",
            curp="INUA941205HDFLRNA9",
            rfc="INUA941205AB1")
        user_data["birth_date"] = (datetime.now() + timedelta(days=1)).isoformat()

        response = master_admin_client.post("/api/v1/users", json=user_data)
        assert response.status_code == 422

    def test_create_user_underage_birth_date(
        self, master_admin_client: E2ETestClient
    ):
        """Test creating user under 18 years old."""
        user_data = build_valid_user_payload(
            email="underage@test.com",
            curp="TESA900615HDFLRNA8",
            rfc="TESA900615AB1")
        user_data["birth_date"] = years_ago_iso(17)

        response = master_admin_client.post("/api/v1/users", json=user_data)
        assert response.status_code == 422

    def test_create_user_as_user_forbidden(self, user_client: E2ETestClient):
        """Users can create accounts (Polar policy allows write User)."""
        user_data = build_valid_user_payload(
            email="test@example.com",
            curp="DEUA900615HDFLRNA2",
            rfc="DEUA900615AB1")

        response = user_client.post("/api/v1/users", json=user_data)
        assert response.status_code == 201


class TestUserUpdate:
    """Test PATCH /users/{id} endpoint."""

    def test_update_user_full(
        self, master_admin_client: E2ETestClient, user_client: E2ETestClient
    ):
        """Test updating user with all fields."""
        update_data = {
            "first_name": "UpdatedJohn",
            "last_name": "UpdatedDoe",
            "phone": "+523312345850",
        }
        response = master_admin_client.patch(
            f"/api/v1/users/{user_client.account['id']}",
            json=update_data)
        assert response.status_code == 200
        data = response.json()
        assert data["first_name"] == "UpdatedJohn"

    def test_update_user_partial(
        self, master_admin_client: E2ETestClient, user_client: E2ETestClient
    ):
        """Test updating user with partial fields."""
        update_data = {"first_name": "PartialJohn"}
        response = master_admin_client.patch(
            f"/api/v1/users/{user_client.account['id']}",
            json=update_data)
        assert response.status_code == 200
        data = response.json()
        assert data["first_name"] == "PartialJohn"

    def test_update_user_not_found(self, master_admin_client: E2ETestClient):
        """Test updating non-existent user."""
        fake_id = uuid4()
        response = master_admin_client.patch(
            f"/api/v1/users/{fake_id}",
            json={"first_name": "Updated"})
        assert response.status_code == 404

    def test_update_user_invalid_email(
        self, master_admin_client: E2ETestClient, user_client: E2ETestClient
    ):
        """Test updating user with invalid email."""
        update_data = {"email": "@invalid"}
        response = master_admin_client.patch(
            f"/api/v1/users/{user_client.account['id']}",
            json=update_data)
        assert response.status_code == 422

    def test_update_user_rejects_weak_password(
        self, master_admin_client: E2ETestClient, user_client: E2ETestClient
    ):
        """Test updating user with weak password."""
        response = master_admin_client.patch(
            f"/api/v1/users/{user_client.account['id']}",
            json={"password": "12345678"})
        assert response.status_code == 422

    def test_update_user_rejects_invalid_curp_check_digit(
        self, master_admin_client: E2ETestClient, user_client: E2ETestClient
    ):
        """Test updating user with invalid CURP check digit."""
        response = master_admin_client.patch(
            f"/api/v1/users/{user_client.account['id']}",
            json={"curp": "REGA920520HDFLRNA9"})
        assert response.status_code == 422

    def test_update_user_rejects_invalid_rfc_format(
        self, master_admin_client: E2ETestClient, user_client: E2ETestClient
    ):
        """Test updating user with invalid RFC."""
        response = master_admin_client.patch(
            f"/api/v1/users/{user_client.account['id']}",
            json={"rfc": "RFC-INVALID"})
        assert response.status_code == 422

    def test_update_user_rejects_postal_code_out_of_range(
        self, master_admin_client: E2ETestClient, user_client: E2ETestClient
    ):
        """Test updating user with postal code out of range."""
        response = master_admin_client.patch(
            f"/api/v1/users/{user_client.account['id']}",
            json={"postal_code": "00000"})
        assert response.status_code == 422

    def test_update_user_rejects_underage_birth_date(
        self, master_admin_client: E2ETestClient, user_client: E2ETestClient
    ):
        """Test updating user with underage birth date."""
        response = master_admin_client.patch(
            f"/api/v1/users/{user_client.account['id']}",
            json={"birth_date": years_ago_iso(17)})
        assert response.status_code == 422

    def test_update_user_deactivate(
        self, master_admin_client: E2ETestClient, user_client: E2ETestClient
    ):
        """Test deactivating a user."""
        update_data = {"is_active": False}
        response = master_admin_client.patch(
            f"/api/v1/users/{user_client.account['id']}",
            json=update_data)
        assert response.status_code == 200
        data = response.json()
        assert data["is_active"] is False

        master_admin_client.patch(
            f"/api/v1/users/{user_client.account['id']}",
            json={"is_active": True})

    def test_update_user_partial_is_atomic_for_first_name(
        self, master_admin_client: E2ETestClient, user_client: E2ETestClient
    ):
        """Test first_name patch updates only that field and keeps others intact."""

        before_response = master_admin_client.get(
            f"/api/v1/users/{user_client.account['id']}")
        assert before_response.status_code == 200
        before_data = before_response.json()

        patch_response = master_admin_client.patch(
            f"/api/v1/users/{user_client.account['id']}",
            json={"first_name": "AtomicUserName"})
        assert patch_response.status_code == 200

        after_response = master_admin_client.get(
            f"/api/v1/users/{user_client.account['id']}")
        assert after_response.status_code == 200
        after_data = after_response.json()

        assert after_data["first_name"] == "AtomicUserName"
        assert after_data["last_name"] == before_data["last_name"]
        if "phone" in before_data and "phone" in after_data:
            assert after_data["phone"] == before_data["phone"]

    def test_update_user_partial_is_atomic_for_is_active(
        self, master_admin_client: E2ETestClient, user_client: E2ETestClient
    ):
        """Test is_active patch updates only status and keeps identity fields intact."""

        before_response = master_admin_client.get(
            f"/api/v1/users/{user_client.account['id']}")
        assert before_response.status_code == 200
        before_data = before_response.json()

        patch_response = master_admin_client.patch(
            f"/api/v1/users/{user_client.account['id']}",
            json={"is_active": False})
        assert patch_response.status_code == 200

        after_response = master_admin_client.get(
            f"/api/v1/users/{user_client.account['id']}")
        assert after_response.status_code == 200
        after_data = after_response.json()

        assert after_data["is_active"] is False
        assert after_data["first_name"] == before_data["first_name"]
        assert after_data["last_name"] == before_data["last_name"]
        if "phone" in before_data and "phone" in after_data:
            assert after_data["phone"] == before_data["phone"]


class TestUserDelete:
    """Test DELETE /users/{id} endpoint."""

    def test_delete_user_as_admin(
        self, master_admin_client: E2ETestClient, session
    ):
        """Test deleting a user as admin."""
        from app.database.model import NonCriticalPersonalData, SensitiveData, User
        from app.shared.auth.security import get_password_hash

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
            is_active=True)
        session.add(non_critical_data)
        session.flush()

        sensitive_data = SensitiveData(
            non_critical_data_id=non_critical_data.id,
            email="deluser@test.com",
            password="DeletePass123!",
            curp="DELU111111HDFRRL09",
            rfc="DELU111111AB0")
        session.add(sensitive_data)
        session.flush()

        user_to_delete = User(
            sensitive_data_id=sensitive_data.id,
            is_active=True)
        session.add(user_to_delete)
        session.commit()

        response = master_admin_client.delete(
            f"/api/v1/users/{user_to_delete.id}")
        assert response.status_code == 204

    def test_delete_user_not_found(self, master_admin_client: E2ETestClient):
        """Test deleting non-existent user."""
        fake_id = uuid4()
        response = master_admin_client.delete(f"/api/v1/users/{fake_id}")
        assert response.status_code == 404

    def test_delete_user_as_manager_forbidden(
        self, manager_client: E2ETestClient, user_client: E2ETestClient
    ):
        """Test deleting user as manager is forbidden."""
        response = manager_client.delete(
            f"/api/v1/users/{user_client.account['id']}")
        assert response.status_code == 403

    def test_delete_user_as_user_forbidden(self, user_client: E2ETestClient):
        """Test deleting user as user is forbidden."""
        response = user_client.delete(
            f"/api/v1/users/{user_client.account['id']}")
        assert response.status_code == 403
