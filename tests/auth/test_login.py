import jwt
import pytest
from datetime import datetime, timedelta, timezone
from fastapi.testclient import TestClient

from app.config import settings
from app.domain.auth.security import get_password_hash, verify_password


class TestLogin:
    """Test cases for the /auth/login endpoint."""

    def test_login_successful_master_admin(
        self, client: TestClient, master_admin_account: dict
    ):
        """Test successful login with master admin credentials."""
        response = client.post(
            "/api/v1/auth/login",
            json={
                "email": master_admin_account["email"],
                "password": master_admin_account["password"],
            },
        )
        assert response.status_code == 200
        data = response.json()
        assert "access_token" in data
        assert data["token_type"] == "bearer"
        assert data["account_type"] == "administrator"
        assert data["is_master"] is True

        # Verify token is valid JWT
        decoded = jwt.decode(
            data["access_token"],
            settings.SECRET_KEY,
            algorithms=[settings.JWT_ALGORITHM],
        )
        assert decoded["email"] == master_admin_account["email"]
        assert decoded["is_master"] is True

    def test_login_successful_regular_admin(
        self, client: TestClient, regular_admin_account: dict
    ):
        """Test successful login with regular admin credentials."""
        response = client.post(
            "/api/v1/auth/login",
            json={
                "email": regular_admin_account["email"],
                "password": regular_admin_account["password"],
            },
        )
        assert response.status_code == 200
        data = response.json()
        assert data["account_type"] == "administrator"
        assert data["is_master"] is False

    def test_login_successful_user(self, client: TestClient, user_account: dict):
        """Test successful login with regular user credentials."""
        response = client.post(
            "/api/v1/auth/login",
            json={
                "email": user_account["email"],
                "password": user_account["password"],
            },
        )
        assert response.status_code == 200
        data = response.json()
        assert data["account_type"] == "user"
        assert data["is_master"] is False

    def test_login_successful_manager(
        self, client: TestClient, manager_account: dict
    ):
        """Test successful login with manager credentials."""
        response = client.post(
            "/api/v1/auth/login",
            json={
                "email": manager_account["email"],
                "password": manager_account["password"],
            },
        )
        assert response.status_code == 200
        data = response.json()
        assert data["account_type"] == "manager"
        assert data["is_master"] is False

    def test_login_email_not_found(self, client: TestClient):
        """Test login with non-existent email."""
        response = client.post(
            "/api/v1/auth/login",
            json={
                "email": "nonexistent@test.com",
                "password": "SomePassword123!",
            },
        )
        assert response.status_code == 400
        assert "Credenciales inválidas" in response.json()["detail"]

    def test_login_wrong_password(self, client: TestClient, master_admin_account: dict):
        """Test login with correct email but wrong password."""
        response = client.post(
            "/api/v1/auth/login",
            json={
                "email": master_admin_account["email"],
                "password": "WrongPassword123!",
            },
        )
        assert response.status_code == 400
        assert "Credenciales inválidas" in response.json()["detail"]

    def test_login_inactive_account(
        self, client: TestClient, inactive_user_account: dict
    ):
        """Test login with inactive account."""
        response = client.post(
            "/api/v1/auth/login",
            json={
                "email": inactive_user_account["email"],
                "password": inactive_user_account["password"],
            },
        )
        assert response.status_code == 400
        assert "inactiva" in response.json()["detail"]

    def test_login_email_too_short(self, client: TestClient):
        """Test login with email shorter than minimum length."""
        response = client.post(
            "/api/v1/auth/login",
            json={
                "email": "a@b.c",  # 5 characters
                "password": "ValidPass123!",
            },
        )
        assert response.status_code == 422

    def test_login_email_without_at_symbol(self, client: TestClient):
        """Test login with invalid email format (no @)."""
        response = client.post(
            "/api/v1/auth/login",
            json={
                "email": "invalidemail123",
                "password": "ValidPass123!",
            },
        )
        assert response.status_code == 422

    def test_login_email_starting_with_at(self, client: TestClient):
        """Test login with invalid email starting with @."""
        response = client.post(
            "/api/v1/auth/login",
            json={
                "email": "@example.com",
                "password": "ValidPass123!",
            },
        )
        assert response.status_code == 422

    def test_login_email_ending_with_at(self, client: TestClient):
        """Test login with invalid email ending with @."""
        response = client.post(
            "/api/v1/auth/login",
            json={
                "email": "user@",
                "password": "ValidPass123!",
            },
        )
        assert response.status_code == 422

    def test_login_password_too_short(self, client: TestClient):
        """Test login with password shorter than minimum length."""
        response = client.post(
            "/api/v1/auth/login",
            json={
                "email": "valid@example.com",
                "password": "Short1!",  # 7 characters
            },
        )
        assert response.status_code == 422

    def test_login_extra_fields_rejected(self, client: TestClient):
        """Test login rejects extra fields in request."""
        response = client.post(
            "/api/v1/auth/login",
            json={
                "email": "valid@example.com",
                "password": "ValidPass123!",
                "extra_field": "should_be_rejected",
            },
        )
        assert response.status_code == 422

    def test_login_email_normalized(self, client: TestClient, master_admin_account: dict):
        """Test login with email in different cases (normalization)."""
        response = client.post(
            "/api/v1/auth/login",
            json={
                "email": master_admin_account["email"].upper(),
                "password": master_admin_account["password"],
            },
        )
        assert response.status_code == 200

    def test_login_email_trimmed(self, client: TestClient, master_admin_account: dict):
        """Test login with email containing whitespace (trimmed)."""
        response = client.post(
            "/api/v1/auth/login",
            json={
                "email": f"  {master_admin_account['email']}  ",
                "password": master_admin_account["password"],
            },
        )
        assert response.status_code == 200
