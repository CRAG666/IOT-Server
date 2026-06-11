"""Tests for PATCH /api/v1/auth/change-password."""


class TestChangePassword:
    def test_change_password_rejects_reusing_current_password(
            self, master_admin_client):
        response = master_admin_client.patch(
            "/api/v1/auth/change-password",
            json={
                "current_password": master_admin_client.account['password'],
                "new_password": master_admin_client.account['password'],
            })
        assert response.status_code == 400
        assert "different" in response.json()["detail"].lower()

    def test_change_password_rejects_wrong_current_password(
            self, master_admin_client):
        response = master_admin_client.patch(
            "/api/v1/auth/change-password",
            json={
                "current_password": "WrongPassword999!",
                "new_password": "NewPassword456!",
            })
        assert response.status_code == 400
        assert "incorrect" in response.json()["detail"].lower()

    def test_change_password_succeeds_with_valid_credentials(
            self, master_admin_client):
        response = master_admin_client.patch(
            "/api/v1/auth/change-password",
            json={
                "current_password": master_admin_client.account['password'],
                "new_password": "NewPassword456!",
            })
        assert response.status_code == 200
        assert "updated" in response.json()["message"].lower()
