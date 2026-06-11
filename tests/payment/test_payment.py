"""Tests para la entidad Payment — SubscriptionType, UserService, Payment, PaymentHistory."""
import pytest


# ── Fixtures ────────────────────────────────────────────────────────


@pytest.fixture
def subscription_type_data(master_admin_client):
    response = master_admin_client.post(
        "/api/v1/payments/subscription-types",
        json={"type": "mensual", "cost": 100.0})
    assert response.status_code == 201
    return response.json()


@pytest.fixture
def service_data(master_admin_client):
    response = master_admin_client.post(
        "/api/v1/services",
        json={
            "name": "Monitoreo",
            "description": "Servicio de monitoreo",
            "administrator_id": str(master_admin_client.account['id']),
        })
    assert response.status_code == 201
    return response.json()


@pytest.fixture
def user_service_data(master_admin_client, user_account, service_data):
    response = master_admin_client.post(
        f"/api/v1/payments/user-services/{user_account['id']}/{service_data['id']}")
    assert response.status_code == 201
    return response.json()


# ── Tests: SubscriptionType ─────────────────────────────────────────


class TestCreateSubscriptionType:

    def test_create_success(self, master_admin_client):
        response = master_admin_client.post(
            "/api/v1/payments/subscription-types",
            json={"type": "mensual", "cost": 100.0})
        assert response.status_code == 201
        data = response.json()
        assert data["type"] == "mensual"
        assert data["cost"] == 100.0

    def test_create_duplicate_fails(self, master_admin_client, subscription_type_data):
        response = master_admin_client.post(
            "/api/v1/payments/subscription-types",
            json={"type": "mensual", "cost": 200.0})
        assert response.status_code == 409


class TestListSubscriptionTypes:

    def test_list_empty(self, master_admin_client):
        response = master_admin_client.get("/api/v1/payments/subscription-types")
        assert response.status_code == 200
        assert response.json() == []

    def test_list_with_data(self, master_admin_client, subscription_type_data):
        response = master_admin_client.get("/api/v1/payments/subscription-types")
        assert response.status_code == 200
        assert len(response.json()) == 1


class TestUpdateSubscriptionType:

    def test_update_cost(self, master_admin_client, subscription_type_data):
        response = master_admin_client.patch(
            f"/api/v1/payments/subscription-types/{subscription_type_data['id']}",
            json={"cost": 150.0})
        assert response.status_code == 200
        assert response.json()["cost"] == 150.0

    def test_update_not_found(self, master_admin_client):
        fake_id = "00000000-0000-0000-0000-000000000000"
        response = master_admin_client.patch(
            f"/api/v1/payments/subscription-types/{fake_id}",
            json={"cost": 150.0})
        assert response.status_code == 404


class TestDeleteSubscriptionType:

    def test_delete_success(self, master_admin_client, subscription_type_data):
        response = master_admin_client.delete(
            f"/api/v1/payments/subscription-types/{subscription_type_data['id']}")
        assert response.status_code == 204

    def test_delete_not_found(self, master_admin_client):
        fake_id = "00000000-0000-0000-0000-000000000000"
        response = master_admin_client.delete(
            f"/api/v1/payments/subscription-types/{fake_id}")
        assert response.status_code == 404


# ── Tests: UserService ──────────────────────────────────────────────


class TestAssignUserService:

    def test_assign_success(self, master_admin_client, user_account, service_data):
        response = master_admin_client.post(
            f"/api/v1/payments/user-services/{user_account['id']}/{service_data['id']}")
        assert response.status_code == 201
        data = response.json()
        assert data["user_id"] == str(user_account['id'])
        assert data["service_id"] == service_data["id"]
        assert data["is_active"] is False

    def test_assign_duplicate_fails(self, master_admin_client, user_service_data, user_account, service_data):
        response = master_admin_client.post(
            f"/api/v1/payments/user-services/{user_account['id']}/{service_data['id']}")
        assert response.status_code == 409

    def test_assign_user_not_found(self, master_admin_client, service_data):
        fake_id = "00000000-0000-0000-0000-000000000000"
        response = master_admin_client.post(
            f"/api/v1/payments/user-services/{fake_id}/{service_data['id']}")
        assert response.status_code == 404

    def test_assign_service_not_found(self, master_admin_client, user_account):
        fake_id = "00000000-0000-0000-0000-000000000000"
        response = master_admin_client.post(
            f"/api/v1/payments/user-services/{user_account['id']}/{fake_id}")
        assert response.status_code == 404


class TestUnassignUserService:

    def test_unassign_success(self, master_admin_client, user_service_data, user_account, service_data):
        response = master_admin_client.delete(
            f"/api/v1/payments/user-services/{user_account['id']}/{service_data['id']}")
        assert response.status_code == 204

    def test_unassign_not_assigned(self, master_admin_client, user_account, service_data):
        response = master_admin_client.delete(
            f"/api/v1/payments/user-services/{user_account['id']}/{service_data['id']}")
        assert response.status_code == 404


class TestListUserServices:

    def test_list_by_user(self, master_admin_client, user_service_data, user_account):
        response = master_admin_client.get(
            f"/api/v1/payments/user-services/user/{user_account['id']}")
        assert response.status_code == 200
        assert len(response.json()) == 1

    def test_list_by_service(self, master_admin_client, user_service_data, service_data):
        response = master_admin_client.get(
            f"/api/v1/payments/user-services/service/{service_data['id']}")
        assert response.status_code == 200
        assert len(response.json()) == 1


# ── Tests: Payment ──────────────────────────────────────────────────


class TestCreatePayment:

    def test_create_payment_activates_user_service(
            self, master_admin_client, user_service_data, subscription_type_data):
        response = master_admin_client.post(
            "/api/v1/payments",
            json={
                "user_service_id": user_service_data["id"],
                "subscription_type_id": subscription_type_data["id"],
                "deposit_id": "BBVA-2026-001",
                "amount": 100.0,
            })
        assert response.status_code == 201
        data = response.json()
        assert data["user_service_id"] == user_service_data["id"]
        assert data["subscription_type_id"] == subscription_type_data["id"]
        assert "expires_at" in data

    def test_create_payment_auto_creates_history(
            self, master_admin_client, user_service_data, subscription_type_data):
        payment_response = master_admin_client.post(
            "/api/v1/payments",
            json={
                "user_service_id": user_service_data["id"],
                "subscription_type_id": subscription_type_data["id"],
                "deposit_id": "BBVA-2026-002",
                "amount": 100.0,
            })
        payment = payment_response.json()

        history_response = master_admin_client.get(
            f"/api/v1/payments/{payment['id']}/history")
        assert history_response.status_code == 200
        history = history_response.json()
        assert len(history) == 1
        assert history[0]["deposit_id"] == "BBVA-2026-002"
        assert history[0]["amount"] == 100.0

    def test_create_payment_user_service_not_found(
            self, master_admin_client, subscription_type_data):
        fake_id = "00000000-0000-0000-0000-000000000000"
        response = master_admin_client.post(
            "/api/v1/payments",
            json={
                "user_service_id": fake_id,
                "subscription_type_id": subscription_type_data["id"],
                "deposit_id": "BBVA-2026-003",
                "amount": 100.0,
            })
        assert response.status_code == 404

    def test_create_payment_subscription_type_not_found(
            self, master_admin_client, user_service_data):
        fake_id = "00000000-0000-0000-0000-000000000000"
        response = master_admin_client.post(
            "/api/v1/payments",
            json={
                "user_service_id": user_service_data["id"],
                "subscription_type_id": fake_id,
                "deposit_id": "BBVA-2026-004",
                "amount": 100.0,
            })
        assert response.status_code == 404


# ── Tests: PaymentHistory ───────────────────────────────────────────


class TestPaymentHistory:

    def test_list_history(self, master_admin_client, user_service_data, subscription_type_data):
        payment_response = master_admin_client.post(
            "/api/v1/payments",
            json={
                "user_service_id": user_service_data["id"],
                "subscription_type_id": subscription_type_data["id"],
                "deposit_id": "BBVA-2026-005",
                "amount": 100.0,
            })
        payment = payment_response.json()

        response = master_admin_client.get(f"/api/v1/payments/{payment['id']}/history")
        assert response.status_code == 200
        data = response.json()
        assert len(data) == 1
        assert data[0]["deposit_id"] == "BBVA-2026-005"

    def test_list_history_payment_not_found(self, master_admin_client):
        fake_id = "00000000-0000-0000-0000-000000000000"
        response = master_admin_client.get(f"/api/v1/payments/{fake_id}/history")
        assert response.status_code == 404
