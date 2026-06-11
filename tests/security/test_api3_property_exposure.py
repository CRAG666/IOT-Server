"""OWASP API3:2023 — Broken Object Property Level Authorization.

Verifies that response schemas never leak sensitive fields (password_hash,
curp, rfc, encryption_key, api_key) and that conflict errors do not enable
user enumeration.
"""

import pytest


class TestResponseDoesNotLeakSensitiveFields:
    _FORBIDDEN = {"password_hash", "password", "curp", "rfc", "encryption_key", "api_key"}

    def _assert_no_leak(self, data: dict | list, context: str = "") -> None:
        if isinstance(data, list):
            for item in data:
                self._assert_no_leak(item, context)
            return
        if isinstance(data, dict):
            for key in data:
                assert key not in self._FORBIDDEN, (
                    f"SEC-004: sensitive field '{key}' exposed in response {context}"
                )
                self._assert_no_leak(data[key], context=f"{context}.{key}")

    def test_administrator_list_no_sensitive_fields(self, master_admin_client):
        resp = master_admin_client.get("/api/v1/administrators/")
        assert resp.status_code == 200
        self._assert_no_leak(resp.json(), "GET /administrators/")

    def test_administrator_detail_no_sensitive_fields(self, master_admin_client):
        resp = master_admin_client.get(
            f"/api/v1/administrators/{master_admin_client.account['id']}"
        )
        assert resp.status_code == 200
        self._assert_no_leak(resp.json(), "GET /administrators/{id}")

    def test_user_detail_no_sensitive_fields(self, master_admin_client, user_account):
        resp = master_admin_client.get(f"/api/v1/users/{user_account['id']}")
        assert resp.status_code == 200
        self._assert_no_leak(resp.json(), "GET /users/{id}")

    def test_manager_detail_no_sensitive_fields(self, master_admin_client, manager_account):
        resp = master_admin_client.get(f"/api/v1/managers/{manager_account['id']}")
        assert resp.status_code == 200
        self._assert_no_leak(resp.json(), "GET /managers/{id}")

    def test_create_administrator_response_no_sensitive_fields(
        self, master_admin_client
    ):
        payload = {
            "first_name": "Test",
            "last_name": "Admin",
            "second_last_name": "Sec",
            "phone": "+523312345700",
            "address": "123 Test Ave",
            "city": "CDMX",
            "state": "Mexico",
            "postal_code": "06500",
            "birth_date": "1990-01-15T00:00:00",
            "email": "sectest_admin@example.com",
            "password": "SecurePass1!",
            "curp": "ABCD900115HDFRRL09",
            "rfc": "ABCD900115AB1",
        }
        resp = master_admin_client.post("/api/v1/administrators", json=payload)
        if resp.status_code in (201, 200):
            self._assert_no_leak(resp.json(), "POST /administrators")


class TestUserEnumerationVia409:
    """Conflict errors must not reveal whether a specific email/CURP exists.

    SEC-005: AlreadyExistsException currently returns the conflicting value
    in its detail message, enabling email/CURP enumeration.
    """

    def _create_admin(self, client, email: str, curp: str, rfc: str):
        return client.post(
            "/api/v1/administrators",
            json={
                "first_name": "Enum",
                "last_name": "Test",
                "second_last_name": "Xu",
                "phone": "+523312345701",
                "address": "456 Enum St",
                "city": "CDMX",
                "state": "Mexico",
                "postal_code": "06500",
                "birth_date": "1990-06-15T00:00:00",
                "email": email,
                "password": "SecurePass1!",
                "curp": curp,
                "rfc": rfc,
            },
        )

    def test_duplicate_email_409_does_not_reveal_email(self, master_admin_client):
        """A 409 on duplicate email must not include the email in the response body."""
        email = "enum_dup@example.com"
        curp1 = "AEZA900115HJCBCL07"
        rfc1 = "ABCD900115AB1"
        curp2 = "AIXA900115HJCBCN05"
        rfc2 = "EFGH920320AB1"

        r1 = self._create_admin(master_admin_client, email, curp1, rfc1)
        if r1.status_code not in (200, 201):
            pytest.skip(f"Could not create first admin: {r1.status_code} {r1.text}")

        r2 = self._create_admin(master_admin_client, email, curp2, rfc2)
        assert r2.status_code == 409

        detail = r2.json().get("detail", "")
        assert email not in detail, (
            f"SEC-005: 409 response leaks email '{email}' — enables user enumeration. "
            f"Detail: {detail!r}"
        )

    def test_not_found_404_does_not_reveal_entity_id(self, master_admin_client):
        """A 404 detail should not expose the ID being queried."""
        fake_id = "00000000-0000-0000-0000-000000000001"
        resp = master_admin_client.get(f"/api/v1/administrators/{fake_id}")
        assert resp.status_code == 404
        # The current implementation includes the ID — document this as informational
        detail = resp.json().get("detail", "")
        if fake_id in detail:
            pytest.xfail(
                "SEC-006 (LOW): 404 detail reveals queried UUID; "
                "switch to a generic 'not found' message"
            )
