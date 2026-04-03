import pytest
from datetime import datetime, timedelta, timezone
from fastapi.testclient import TestClient
import jwt

from app.config import settings
from app.domain.auth.security import get_password_hash


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


class TestChangePassword:
    """Test cases for the /auth/change-password endpoint."""

    def test_change_password_successful(
        self, client: TestClient, master_admin_account: dict
    ):
        """Test successful password change."""
        token = create_token(master_admin_account)
        response = client.patch(
            "/api/v1/auth/change-password",
            json={
                "current_password": master_admin_account["password"],
                "new_password": "NewPassword123!",
            },
            headers={"Authorization": f"Bearer {token}"},
        )
        assert response.status_code == 200
        data = response.json()
        assert "message" in data
        assert "actualizada" in data["message"].lower()

    def test_change_password_wrong_current_password(
        self, client: TestClient, master_admin_account: dict
    ):
        """Test password change with wrong current password."""
        token = create_token(master_admin_account)
        response = client.patch(
            "/api/v1/auth/change-password",
            json={
                "current_password": "WrongPassword123!",
                "new_password": "NewPassword123!",
            },
            headers={"Authorization": f"Bearer {token}"},
        )
        assert response.status_code == 400
        assert "contraseña actual" in response.json()["detail"].lower()

    def test_change_password_without_token(self, client: TestClient):
        """Test password change without authentication token."""
        response = client.patch(
            "/api/v1/auth/change-password",
            json={
                "current_password": "SomePassword123!",
                "new_password": "NewPassword123!",
            },
        )
        assert response.status_code == 401

    def test_change_password_with_invalid_token(self, client: TestClient):
        """Test password change with invalid token."""
        response = client.patch(
            "/api/v1/auth/change-password",
            json={
                "current_password": "SomePassword123!",
                "new_password": "NewPassword123!",
            },
            headers={"Authorization": "bearer invalid.token.here"},
        )
        assert response.status_code == 401

    def test_change_password_new_too_short(
        self, client: TestClient, master_admin_account: dict
    ):
        """Test password change with new password too short."""
        token = create_token(master_admin_account)
        response = client.patch(
            "/api/v1/auth/change-password",
            json={
                "current_password": master_admin_account["password"],
                "new_password": "Short1!",  # 7 characters
            },
            headers={"Authorization": f"Bearer {token}"},
        )
        assert response.status_code == 422

    def test_change_password_current_too_short(
        self, client: TestClient, master_admin_account: dict
    ):
        """Test password change with current password too short."""
        token = create_token(master_admin_account)
        response = client.patch(
            "/api/v1/auth/change-password",
            json={
                "current_password": "Short1!",  # 7 characters
                "new_password": "NewPassword123!",
            },
            headers={"Authorization": f"Bearer {token}"},
        )
        assert response.status_code == 422

    def test_change_password_extra_fields_rejected(
        self, client: TestClient, master_admin_account: dict
    ):
        """Test password change rejects extra fields."""
        token = create_token(master_admin_account)
        response = client.patch(
            "/api/v1/auth/change-password",
            json={
                "current_password": master_admin_account["password"],
                "new_password": "NewPassword123!",
                "extra_field": "should_be_rejected",
            },
            headers={"Authorization": f"Bearer {token}"},
        )
        assert response.status_code == 422

    def test_change_password_user_account(
        self, client: TestClient, user_account: dict
    ):
        """Test password change works for user accounts."""
        token = create_token(user_account)
        response = client.patch(
            "/api/v1/auth/change-password",
            json={
                "current_password": user_account["password"],
                "new_password": "NewUserPass123!",
            },
            headers={"Authorization": f"Bearer {token}"},
        )
        assert response.status_code == 200

    def test_change_password_manager_account(
        self, client: TestClient, manager_account: dict
    ):
        """Test password change works for manager accounts."""
        token = create_token(manager_account)
        response = client.patch(
            "/api/v1/auth/change-password",
            json={
                "current_password": manager_account["password"],
                "new_password": "NewManagerPass123!",
            },
            headers={"Authorization": f"Bearer {token}"},
        )
        assert response.status_code == 200

    def test_change_password_inactive_user_is_blocked_with_valid_token(
        self, client: TestClient, inactive_user_account: dict
    ):
        """Test that inactive users are blocked by auth middleware."""
        token = create_token(inactive_user_account)
        response = client.patch(
            "/api/v1/auth/change-password",
            json={
                "current_password": inactive_user_account["password"],
                "new_password": "NewInactivePass123!",
            },
            headers={"Authorization": f"Bearer {token}"},
        )
        assert response.status_code == 401
