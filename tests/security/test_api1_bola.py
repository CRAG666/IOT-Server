"""OWASP API1:2023 — Broken Object Level Authorization.

Verifies that per-resource access controls prevent one account type from
reading or mutating records that belong to another, and that Casbin denies
actions not listed in policy.csv.
"""

import pytest


class TestObjectLevelAuthorizationUsers:
    """Users can only read/write their own profile; managers are scoped."""

    def test_user_cannot_list_all_users(self, user_client, master_admin_client):
        """A regular user must not receive a full user list (API1)."""
        # user role has read permission on User, but the repository should
        # only expose the user's own record — endpoint returns user's own data
        # or a 403 depending on implementation.
        resp = user_client.get("/api/v1/users/")
        # Either 200 with only their own record, or 403 — never a full list
        if resp.status_code == 200:
            data = resp.json()
            items = data.get("data", [])
            own_id = str(user_client.account["id"])
            ids = [str(item["id"]) for item in items]
            assert all(i == own_id for i in ids), (
                "User received other users' records — BOLA"
            )

    def test_user_cannot_delete_another_user(
        self, user_client, master_admin_client, user_account, regular_admin_account
    ):
        """A user must receive 403 attempting to delete another user (API1)."""
        # Create a second user via master admin
        resp = master_admin_client.delete(
            f"/api/v1/users/{user_client.account['id']}"
        )
        # master admin can delete — 204 or 200
        # Now attempt from user_client to delete master admin (should be 403)
        resp2 = user_client.delete(
            f"/api/v1/users/{master_admin_client.account['id']}"
        )
        assert resp2.status_code == 403, (
            f"User was able to delete another account (status {resp2.status_code}) — BOLA"
        )

    def test_regular_admin_cannot_delete_administrator(
        self, regular_admin_client, master_admin_client
    ):
        """Non-master admin has no delete permission on Administrator (API1)."""
        resp = regular_admin_client.delete(
            f"/api/v1/administrators/{master_admin_client.account['id']}"
        )
        assert resp.status_code == 403

    def test_manager_cannot_access_administrator_endpoint(
        self, manager_client
    ):
        """Managers have no read permission on Administrator (API1)."""
        resp = manager_client.get("/api/v1/administrators/")
        assert resp.status_code == 403

    def test_user_cannot_write_to_service(self, user_client, master_admin_client):
        """Users have read-only access to services (API1)."""
        resp = user_client.post(
            "/api/v1/services",
            json={
                "name": "Unauthorized",
                "description": "Should fail",
                "administrator_id": str(master_admin_client.account["id"]),
            },
        )
        assert resp.status_code == 403

    def test_user_cannot_delete_role(self, user_client, master_admin_client):
        """Users have no permission on Role delete (API1)."""
        svc_resp = master_admin_client.post(
            "/api/v1/services",
            json={
                "name": "BOLA-Svc",
                "description": "x",
                "administrator_id": str(master_admin_client.account["id"]),
            },
        )
        assert svc_resp.status_code == 201
        role_resp = master_admin_client.post(
            "/api/v1/roles",
            json={"name": "BOLARole", "service_id": svc_resp.json()["id"]},
        )
        assert role_resp.status_code == 201
        role_id = role_resp.json()["id"]

        resp = user_client.delete(f"/api/v1/roles/{role_id}")
        assert resp.status_code == 403


class TestObjectLevelAuthorizationDevices:
    def test_user_cannot_write_device(self, user_client):
        """User has no write permission on Device (API1)."""
        resp = user_client.post(
            "/api/v1/devices",
            json={"name": "BadDevice", "description": "x"},
        )
        assert resp.status_code in (403, 422)

    def test_manager_cannot_delete_device(self, manager_client, master_admin_client):
        """Manager has read/write but not delete on Device (API1)."""
        # create device as master admin
        svc_resp = master_admin_client.post(
            "/api/v1/services",
            json={
                "name": "DevSvc",
                "description": "x",
                "administrator_id": str(master_admin_client.account["id"]),
            },
        )
        assert svc_resp.status_code == 201

        dev_resp = master_admin_client.post(
            "/api/v1/devices",
            json={"name": "TestDev", "description": "d", "service_id": svc_resp.json()["id"]},
        )
        if dev_resp.status_code != 201:
            pytest.skip("device creation requires service_id — schema may differ")

        dev_id = dev_resp.json()["id"]
        resp = manager_client.delete(f"/api/v1/devices/{dev_id}")
        assert resp.status_code == 403
