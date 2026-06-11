"""Integration tests for the dynamic Casbin policy management API.

These tests exercise the ``/api/v1/policies`` endpoints using a real
``master_admin_client`` (full E2E auth stack).  All mutating tests use the
``clean_policy`` fixture so they leave the shared enforcer clean.

Authorization matrix under test
--------------------------------
- master_admin : can do everything (``administer`` via wildcard)
- regular_admin: denied (no ``administer`` on ``_Policy``)
- user         : denied
- manager      : denied
"""

import pytest


class TestListPolicies:
    def test_master_admin_can_list(self, master_admin_client):
        resp = master_admin_client.get("/api/v1/policies")
        assert resp.status_code == 200
        data = resp.json()
        assert isinstance(data, list)
        assert len(data) > 0

    def test_response_has_expected_shape(self, master_admin_client):
        resp = master_admin_client.get("/api/v1/policies")
        first = resp.json()[0]
        assert set(first.keys()) == {"role", "resource", "action"}

    def test_seed_rules_present(self, master_admin_client):
        resp = master_admin_client.get("/api/v1/policies")
        rules = {(r["role"], r["resource"], r["action"]) for r in resp.json()}
        assert ("administrator", "User", "read") in rules
        assert ("master_admin", "*", "*") in rules

    def test_regular_admin_denied(self, regular_admin_client):
        resp = regular_admin_client.get("/api/v1/policies")
        assert resp.status_code == 403

    def test_user_denied(self, user_client):
        resp = user_client.get("/api/v1/policies")
        assert resp.status_code == 403

    def test_manager_denied(self, manager_client):
        resp = manager_client.get("/api/v1/policies")
        assert resp.status_code == 403


class TestGetRolePolicies:
    def test_known_role_returns_rules(self, master_admin_client):
        resp = master_admin_client.get("/api/v1/policies/administrator")
        assert resp.status_code == 200
        body = resp.json()
        assert body["role"] == "administrator"
        assert isinstance(body["permissions"], list)
        assert len(body["permissions"]) > 0

    def test_all_returned_rules_belong_to_requested_role(self, master_admin_client):
        resp = master_admin_client.get("/api/v1/policies/manager")
        for rule in resp.json()["permissions"]:
            assert rule["role"] == "manager"

    def test_unknown_role_returns_404(self, master_admin_client):
        resp = master_admin_client.get("/api/v1/policies/ghost_role")
        assert resp.status_code == 404

    def test_regular_admin_denied(self, regular_admin_client):
        resp = regular_admin_client.get("/api/v1/policies/administrator")
        assert resp.status_code == 403


class TestAddPolicy:
    def test_add_new_rule(self, master_admin_client, clean_policy):
        payload = {"role": "support_agent", "resource": "Report", "action": "read"}
        resp = master_admin_client.post("/api/v1/policies", json=payload)
        assert resp.status_code == 201
        body = resp.json()
        assert body == payload

    def test_add_rule_is_idempotent(self, master_admin_client, clean_policy):
        payload = {"role": "manager", "resource": "Device", "action": "read"}
        r1 = master_admin_client.post("/api/v1/policies", json=payload)
        r2 = master_admin_client.post("/api/v1/policies", json=payload)
        assert r1.status_code == 201
        assert r2.status_code == 201

    def test_new_rule_is_enforced(self, master_admin_client, clean_policy):
        """Rule added through the API must immediately affect enforce() decisions."""
        from app.shared.authorization.enforcer import get_enforcer

        payload = {"role": "manager", "resource": "AuditLog", "action": "read"}
        assert not get_enforcer().enforce("manager", "AuditLog", "read")
        master_admin_client.post("/api/v1/policies", json=payload)
        assert get_enforcer().enforce("manager", "AuditLog", "read")

    def test_wildcard_in_role_rejected(self, master_admin_client):
        payload = {"role": "*", "resource": "User", "action": "read"}
        resp = master_admin_client.post("/api/v1/policies", json=payload)
        assert resp.status_code == 422

    def test_wildcard_in_resource_rejected(self, master_admin_client):
        payload = {"role": "manager", "resource": "*", "action": "read"}
        resp = master_admin_client.post("/api/v1/policies", json=payload)
        assert resp.status_code == 422

    def test_invalid_action_rejected(self, master_admin_client):
        payload = {"role": "manager", "resource": "Device", "action": "destroy"}
        resp = master_admin_client.post("/api/v1/policies", json=payload)
        assert resp.status_code == 422

    def test_regular_admin_denied(self, regular_admin_client):
        payload = {"role": "support_agent", "resource": "Report", "action": "read"}
        resp = regular_admin_client.post("/api/v1/policies", json=payload)
        assert resp.status_code == 403


class TestRemovePolicy:
    def test_remove_existing_rule(self, master_admin_client, clean_policy):
        # Add a rule, then remove it.
        payload = {"role": "support_agent", "resource": "Temp", "action": "write"}
        master_admin_client.post("/api/v1/policies", json=payload)

        resp = master_admin_client.delete(
            "/api/v1/policies/support_agent/Temp/write"
        )
        assert resp.status_code == 204

    def test_removed_rule_no_longer_enforced(self, master_admin_client, clean_policy):
        from app.shared.authorization.enforcer import get_enforcer

        payload = {"role": "support_agent", "resource": "TempRes", "action": "delete"}
        master_admin_client.post("/api/v1/policies", json=payload)
        assert get_enforcer().enforce("support_agent", "TempRes", "delete")

        master_admin_client.delete("/api/v1/policies/support_agent/TempRes/delete")
        assert not get_enforcer().enforce("support_agent", "TempRes", "delete")

    def test_remove_nonexistent_rule_returns_404(self, master_admin_client, clean_policy):
        resp = master_admin_client.delete(
            "/api/v1/policies/support_agent/DoesNotExist/administer"
        )
        assert resp.status_code == 404

    def test_cannot_remove_master_admin_wildcard(self, master_admin_client, clean_policy):
        resp = master_admin_client.delete("/api/v1/policies/master_admin/*/")
        # Path param with * may be rejected by router at 404 or 405;
        # even if it reaches the handler the service raises 400.
        assert resp.status_code in {400, 404, 422}

    def test_remove_master_admin_wildcard_via_service_raises(self):
        from app.domain.policy.service import PolicyService
        from app.shared.exceptions import BadRequestException

        svc = PolicyService()
        with pytest.raises(BadRequestException):
            svc.remove_rule("master_admin", "*", "*")

    def test_regular_admin_denied(self, regular_admin_client):
        resp = regular_admin_client.delete(
            "/api/v1/policies/manager/Device/read"
        )
        assert resp.status_code == 403
