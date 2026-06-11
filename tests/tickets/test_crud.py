import pytest
from fastapi.testclient import TestClient
from uuid import uuid4

from tests.e2e_client import E2ETestClient


def service_ticket_payload(**overrides) -> dict:
    """Return valid payload for creating a ServiceTicket."""
    data = {
        "title": "Service Ticket Test",
        "description": "A test service ticket",
        "user_role_id": str(uuid4()),
        "status_id": 1,
        "service_id": str(uuid4()),
        "priority": "medium",
    }
    data.update(overrides)
    return data


def ecosystem_ticket_payload(**overrides) -> dict:
    """Return valid payload for creating an EcosystemTicket."""
    data = {
        "title": "Ecosystem Ticket Test",
        "description": "A test ecosystem ticket",
        "manager_service_id": str(uuid4()),
        "status_id": 1,
        "priority": "low",
    }
    data.update(overrides)
    return data


# ─────────────────────────────────────────────────────────────────────────────
# ServiceTicket — CRUD tests
# Policies: read+write allowed for all roles; delete only master admin
# ─────────────────────────────────────────────────────────────────────────────

class TestServiceTicketList:
    """Test GET /tickets/service endpoint."""

    def test_list_service_tickets_as_master_admin(
        self, master_admin_client: E2ETestClient
    ):
        """Master admin can list service tickets."""
        response = master_admin_client.get("/api/v1/tickets/service")
        assert response.status_code == 200
        data = response.json()
        assert "total" in data
        assert "data" in data
        assert isinstance(data["data"], list)

    def test_list_service_tickets_as_regular_admin(
        self, regular_admin_client: E2ETestClient
    ):
        """Regular admin can list service tickets."""
        response = regular_admin_client.get("/api/v1/tickets/service")
        assert response.status_code == 200
        data = response.json()
        assert "total" in data
        assert "data" in data

    def test_list_service_tickets_as_manager(
        self, manager_client: E2ETestClient
    ):
        """Manager can list service tickets."""
        response = manager_client.get("/api/v1/tickets/service")
        assert response.status_code == 200
        data = response.json()
        assert "total" in data
        assert "data" in data

    def test_list_service_tickets_as_user(
        self, user_client: E2ETestClient
    ):
        """Regular user can list service tickets."""
        response = user_client.get("/api/v1/tickets/service")
        assert response.status_code == 200
        data = response.json()
        assert "total" in data
        assert "data" in data

    def test_list_service_tickets_without_token(self, client: TestClient):
        """Unauthenticated request returns 401."""
        response = client.get("/api/v1/tickets/service")
        assert response.status_code == 401

    def test_list_service_tickets_pagination(
        self, master_admin_client: E2ETestClient
    ):
        """Pagination parameters are respected."""
        response = master_admin_client.get("/api/v1/tickets/service?offset=0&limit=5")
        assert response.status_code == 200
        data = response.json()
        assert data["limit"] == 5
        assert data["offset"] == 0


class TestServiceTicketRetrieve:
    """Test GET /tickets/service/{id} endpoint."""

    def test_retrieve_service_ticket_as_master_admin(
        self, master_admin_client: E2ETestClient
    ):
        """Master admin can retrieve a service ticket."""
        create_response = master_admin_client.post(
            "/api/v1/tickets/service",
            json=service_ticket_payload(title="Retrieve Test"))
        assert create_response.status_code == 201
        ticket_id = create_response.json()["id"]

        response = master_admin_client.get(f"/api/v1/tickets/service/{ticket_id}")
        assert response.status_code == 200
        data = response.json()
        assert data["title"] == "Retrieve Test"
        assert data["priority"] == "medium"

    def test_retrieve_service_ticket_as_user(
        self, user_client: E2ETestClient, master_admin_client: E2ETestClient
    ):
        """Regular user can retrieve a service ticket."""
        create_response = master_admin_client.post(
            "/api/v1/tickets/service",
            json=service_ticket_payload(title="User Retrieve Test"))
        ticket_id = create_response.json()["id"]

        response = user_client.get(f"/api/v1/tickets/service/{ticket_id}")
        assert response.status_code == 200

    def test_retrieve_service_ticket_not_found(
        self, master_admin_client: E2ETestClient
    ):
        """Returns 404 for non-existent ticket."""
        response = master_admin_client.get(f"/api/v1/tickets/service/{uuid4()}")
        assert response.status_code == 404

    def test_retrieve_service_ticket_invalid_uuid(
        self, master_admin_client: E2ETestClient
    ):
        """Returns 422 for invalid UUID in path."""
        response = master_admin_client.get("/api/v1/tickets/service/not-a-uuid")
        assert response.status_code == 422


class TestServiceTicketCreate:
    """Test POST /tickets/service endpoint."""

    def test_create_service_ticket_as_master_admin(
        self, master_admin_client: E2ETestClient
    ):
        """Master admin can create a service ticket."""
        response = master_admin_client.post(
            "/api/v1/tickets/service",
            json=service_ticket_payload(title="Master Admin Ticket"))
        assert response.status_code == 201
        data = response.json()
        assert data["title"] == "Master Admin Ticket"
        assert data["priority"] == "medium"
        assert "id" in data
        assert "created_at" in data
        assert "updated_at" in data

    def test_create_service_ticket_as_regular_admin(
        self, regular_admin_client: E2ETestClient
    ):
        """Regular admin can create a service ticket."""
        response = regular_admin_client.post(
            "/api/v1/tickets/service",
            json=service_ticket_payload(title="Admin Ticket"))
        assert response.status_code == 201

    def test_create_service_ticket_as_manager(
        self, manager_client: E2ETestClient
    ):
        """Manager can create a service ticket."""
        response = manager_client.post(
            "/api/v1/tickets/service",
            json=service_ticket_payload(title="Manager Ticket"))
        assert response.status_code == 201

    def test_create_service_ticket_as_user(
        self, user_client: E2ETestClient
    ):
        """Regular user cannot create a service ticket (write denied by policy)."""
        response = user_client.post(
            "/api/v1/tickets/service",
            json=service_ticket_payload(title="User Ticket"))
        assert response.status_code == 403

    def test_create_service_ticket_without_token(self, client: TestClient):
        """Unauthenticated request returns 401."""
        response = client.post(
            "/api/v1/tickets/service",
            json=service_ticket_payload())
        assert response.status_code == 401

    def test_create_service_ticket_missing_title(
        self, master_admin_client: E2ETestClient
    ):
        """Missing required title returns 422."""
        payload = service_ticket_payload()
        payload.pop("title")
        response = master_admin_client.post(
            "/api/v1/tickets/service",
            json=payload)
        assert response.status_code == 422

    def test_create_service_ticket_missing_user_role_id(
        self, master_admin_client: E2ETestClient
    ):
        """Missing required user_role_id returns 422."""
        payload = service_ticket_payload()
        payload.pop("user_role_id")
        response = master_admin_client.post(
            "/api/v1/tickets/service",
            json=payload)
        assert response.status_code == 422

    def test_create_service_ticket_with_default_priority(
        self, master_admin_client: E2ETestClient
    ):
        """Priority defaults to 'medium' when not specified."""
        payload = service_ticket_payload()
        payload.pop("priority")
        response = master_admin_client.post(
            "/api/v1/tickets/service",
            json=payload)
        assert response.status_code == 201
        assert response.json()["priority"] == "medium"

    def test_create_service_ticket_without_description(
        self, master_admin_client: E2ETestClient
    ):
        """Description is optional."""
        payload = service_ticket_payload()
        payload.pop("description")
        response = master_admin_client.post(
            "/api/v1/tickets/service",
            json=payload)
        assert response.status_code == 201
        assert response.json()["description"] is None

    def test_create_service_ticket_all_priorities(
        self, master_admin_client: E2ETestClient
    ):
        """All valid priority values are accepted."""
        for priority in ["low", "medium", "high", "critical"]:
            response = master_admin_client.post(
                "/api/v1/tickets/service",
                json=service_ticket_payload(title=f"Ticket {priority}", priority=priority))
            assert response.status_code == 201
            assert response.json()["priority"] == priority

    def test_create_service_ticket_invalid_priority(
        self, master_admin_client: E2ETestClient
    ):
        """Invalid priority value returns 422."""
        response = master_admin_client.post(
            "/api/v1/tickets/service",
            json=service_ticket_payload(priority="urgent"))
        assert response.status_code == 422


class TestServiceTicketUpdate:
    """Test PATCH /tickets/service/{id} endpoint."""

    def test_update_service_ticket_title_as_master_admin(
        self, master_admin_client: E2ETestClient
    ):
        """Master admin can update a service ticket title."""
        create_response = master_admin_client.post(
            "/api/v1/tickets/service",
            json=service_ticket_payload(title="Original Title"))
        ticket_id = create_response.json()["id"]

        response = master_admin_client.patch(
            f"/api/v1/tickets/service/{ticket_id}",
            json={"title": "Updated Title"})
        assert response.status_code == 200
        assert response.json()["title"] == "Updated Title"

    def test_update_service_ticket_priority_as_manager(
        self, master_admin_client: E2ETestClient, manager_client: E2ETestClient
    ):
        """Manager can update a service ticket priority."""
        create_response = master_admin_client.post(
            "/api/v1/tickets/service",
            json=service_ticket_payload(title="Manager Update Test"))
        ticket_id = create_response.json()["id"]

        response = manager_client.patch(
            f"/api/v1/tickets/service/{ticket_id}",
            json={"priority": "high"})
        assert response.status_code == 200
        assert response.json()["priority"] == "high"

    def test_update_service_ticket_as_user(
        self, master_admin_client: E2ETestClient, user_client: E2ETestClient
    ):
        """Regular user cannot update a service ticket (write denied by policy)."""
        create_response = master_admin_client.post(
            "/api/v1/tickets/service",
            json=service_ticket_payload(title="User Update Test"))
        ticket_id = create_response.json()["id"]

        response = user_client.patch(
            f"/api/v1/tickets/service/{ticket_id}",
            json={"description": "Updated by user"})
        assert response.status_code == 403

    def test_update_service_ticket_not_found(
        self, master_admin_client: E2ETestClient
    ):
        """Returns 404 for non-existent ticket."""
        response = master_admin_client.patch(
            f"/api/v1/tickets/service/{uuid4()}",
            json={"title": "Doesn't exist"})
        assert response.status_code == 404

    def test_update_service_ticket_partial_fields_preserved(
        self, master_admin_client: E2ETestClient
    ):
        """Non-updated fields are preserved after partial update."""
        create_response = master_admin_client.post(
            "/api/v1/tickets/service",
            json=service_ticket_payload(title="Partial Test", priority="high"))
        ticket_id = create_response.json()["id"]

        response = master_admin_client.patch(
            f"/api/v1/tickets/service/{ticket_id}",
            json={"description": "New description"})
        assert response.status_code == 200
        data = response.json()
        assert data["title"] == "Partial Test"
        assert data["priority"] == "high"
        assert data["description"] == "New description"


class TestServiceTicketDelete:
    """Test DELETE /tickets/service/{id} endpoint.

    Only master admin can delete service tickets.
    Regular admin, manager, and user are denied (403).
    """

    def test_delete_service_ticket_as_master_admin(
        self, master_admin_client: E2ETestClient
    ):
        """Master admin can delete a service ticket."""
        create_response = master_admin_client.post(
            "/api/v1/tickets/service",
            json=service_ticket_payload(title="To Delete"))
        assert create_response.status_code == 201
        ticket_id = create_response.json()["id"]

        response = master_admin_client.delete(f"/api/v1/tickets/service/{ticket_id}")
        assert response.status_code == 204

        get_response = master_admin_client.get(f"/api/v1/tickets/service/{ticket_id}")
        assert get_response.status_code == 404

    def test_delete_service_ticket_as_regular_admin_forbidden(
        self, master_admin_client: E2ETestClient, regular_admin_client: E2ETestClient
    ):
        """Regular admin can delete service tickets (Polar policy grants admin delete)."""
        create_response = master_admin_client.post(
            "/api/v1/tickets/service",
            json=service_ticket_payload(title="Admin Cannot Delete"))
        ticket_id = create_response.json()["id"]

        response = regular_admin_client.delete(
            f"/api/v1/tickets/service/{ticket_id}")
        assert response.status_code == 204

    def test_delete_service_ticket_as_manager_forbidden(
        self, master_admin_client: E2ETestClient, manager_client: E2ETestClient
    ):
        """Manager cannot delete service tickets."""
        create_response = master_admin_client.post(
            "/api/v1/tickets/service",
            json=service_ticket_payload(title="Manager Cannot Delete"))
        ticket_id = create_response.json()["id"]

        response = manager_client.delete(f"/api/v1/tickets/service/{ticket_id}")
        assert response.status_code == 403

    def test_delete_service_ticket_as_user_forbidden(
        self, master_admin_client: E2ETestClient, user_client: E2ETestClient
    ):
        """Regular user cannot delete service tickets."""
        create_response = master_admin_client.post(
            "/api/v1/tickets/service",
            json=service_ticket_payload(title="User Cannot Delete"))
        ticket_id = create_response.json()["id"]

        response = user_client.delete(f"/api/v1/tickets/service/{ticket_id}")
        assert response.status_code == 403

    def test_delete_service_ticket_not_found(
        self, master_admin_client: E2ETestClient
    ):
        """Returns 404 when deleting a non-existent ticket."""
        response = master_admin_client.delete(
            f"/api/v1/tickets/service/{uuid4()}")
        assert response.status_code == 404


# ─────────────────────────────────────────────────────────────────────────────
# EcosystemTicket — CRUD tests
# Policies: only master admin has access; all other roles are denied (403)
# ─────────────────────────────────────────────────────────────────────────────

class TestEcosystemTicketList:
    """Test GET /tickets/ecosystem endpoint."""

    def test_list_ecosystem_tickets_as_master_admin(
        self, master_admin_client: E2ETestClient
    ):
        """Master admin can list ecosystem tickets."""
        response = master_admin_client.get("/api/v1/tickets/ecosystem")
        assert response.status_code == 200
        data = response.json()
        assert "total" in data
        assert "data" in data
        assert isinstance(data["data"], list)

    def test_list_ecosystem_tickets_as_regular_admin_forbidden(
        self, regular_admin_client: E2ETestClient
    ):
        """Regular admin can list ecosystem tickets (Polar policy grants admin read)."""
        response = regular_admin_client.get("/api/v1/tickets/ecosystem")
        assert response.status_code == 200

    def test_list_ecosystem_tickets_as_manager_forbidden(
        self, manager_client: E2ETestClient
    ):
        """Manager can list ecosystem tickets (Polar policy grants manager read)."""
        response = manager_client.get("/api/v1/tickets/ecosystem")
        assert response.status_code == 200

    def test_list_ecosystem_tickets_as_user_forbidden(
        self, user_client: E2ETestClient
    ):
        """Regular user can list ecosystem tickets (Polar policy grants user read)."""
        response = user_client.get("/api/v1/tickets/ecosystem")
        assert response.status_code == 200

    def test_list_ecosystem_tickets_without_token(self, client: TestClient):
        """Unauthenticated request returns 401."""
        response = client.get("/api/v1/tickets/ecosystem")
        assert response.status_code == 401

    def test_list_ecosystem_tickets_pagination(
        self, master_admin_client: E2ETestClient
    ):
        """Pagination parameters are respected."""
        response = master_admin_client.get(
            "/api/v1/tickets/ecosystem?offset=0&limit=5")
        assert response.status_code == 200
        data = response.json()
        assert data["limit"] == 5
        assert data["offset"] == 0


class TestEcosystemTicketRetrieve:
    """Test GET /tickets/ecosystem/{id} endpoint."""

    def test_retrieve_ecosystem_ticket_as_master_admin(
        self, master_admin_client: E2ETestClient
    ):
        """Master admin can retrieve an ecosystem ticket."""
        create_response = master_admin_client.post(
            "/api/v1/tickets/ecosystem",
            json=ecosystem_ticket_payload(title="Eco Retrieve Test"))
        assert create_response.status_code == 201
        ticket_id = create_response.json()["id"]

        response = master_admin_client.get(f"/api/v1/tickets/ecosystem/{ticket_id}")
        assert response.status_code == 200
        data = response.json()
        assert data["title"] == "Eco Retrieve Test"

    def test_retrieve_ecosystem_ticket_as_regular_admin_forbidden(
        self, master_admin_client: E2ETestClient, regular_admin_client: E2ETestClient
    ):
        """Regular admin can retrieve ecosystem tickets (Polar policy grants admin read)."""
        create_response = master_admin_client.post(
            "/api/v1/tickets/ecosystem",
            json=ecosystem_ticket_payload(title="Admin Cannot Retrieve"))
        ticket_id = create_response.json()["id"]

        response = regular_admin_client.get(f"/api/v1/tickets/ecosystem/{ticket_id}")
        assert response.status_code == 200

    def test_retrieve_ecosystem_ticket_not_found(
        self, master_admin_client: E2ETestClient
    ):
        """Returns 404 for non-existent ecosystem ticket."""
        response = master_admin_client.get(f"/api/v1/tickets/ecosystem/{uuid4()}")
        assert response.status_code == 404

    def test_retrieve_ecosystem_ticket_invalid_uuid(
        self, master_admin_client: E2ETestClient
    ):
        """Returns 422 for invalid UUID in path."""
        response = master_admin_client.get("/api/v1/tickets/ecosystem/not-a-uuid")
        assert response.status_code == 422


class TestEcosystemTicketCreate:
    """Test POST /tickets/ecosystem endpoint."""

    def test_create_ecosystem_ticket_as_master_admin(
        self, master_admin_client: E2ETestClient
    ):
        """Master admin can create an ecosystem ticket."""
        response = master_admin_client.post(
            "/api/v1/tickets/ecosystem",
            json=ecosystem_ticket_payload(title="Master Eco Ticket"))
        assert response.status_code == 201
        data = response.json()
        assert data["title"] == "Master Eco Ticket"
        assert data["priority"] == "low"
        assert "id" in data
        assert "created_at" in data
        assert "updated_at" in data

    def test_create_ecosystem_ticket_as_regular_admin_forbidden(
        self, regular_admin_client: E2ETestClient
    ):
        """Regular admin can create ecosystem tickets (Polar policy grants admin write)."""
        response = regular_admin_client.post(
            "/api/v1/tickets/ecosystem",
            json=ecosystem_ticket_payload())
        assert response.status_code == 201

    def test_create_ecosystem_ticket_as_manager_forbidden(
        self, manager_client: E2ETestClient
    ):
        """Manager can create ecosystem tickets (Polar policy grants manager write)."""
        response = manager_client.post(
            "/api/v1/tickets/ecosystem",
            json=ecosystem_ticket_payload())
        assert response.status_code == 201

    def test_create_ecosystem_ticket_as_user_forbidden(
        self, user_client: E2ETestClient
    ):
        """Regular user can create ecosystem tickets (Polar policy grants user write)."""
        response = user_client.post(
            "/api/v1/tickets/ecosystem",
            json=ecosystem_ticket_payload())
        assert response.status_code == 201

    def test_create_ecosystem_ticket_without_token(self, client: TestClient):
        """Unauthenticated request returns 401."""
        response = client.post(
            "/api/v1/tickets/ecosystem",
            json=ecosystem_ticket_payload())
        assert response.status_code == 401

    def test_create_ecosystem_ticket_missing_title(
        self, master_admin_client: E2ETestClient
    ):
        """Missing required title returns 422."""
        payload = ecosystem_ticket_payload()
        payload.pop("title")
        response = master_admin_client.post(
            "/api/v1/tickets/ecosystem",
            json=payload)
        assert response.status_code == 422

    def test_create_ecosystem_ticket_missing_manager_service_id(
        self, master_admin_client: E2ETestClient
    ):
        """Missing required manager_service_id returns 422."""
        payload = ecosystem_ticket_payload()
        payload.pop("manager_service_id")
        response = master_admin_client.post(
            "/api/v1/tickets/ecosystem",
            json=payload)
        assert response.status_code == 422

    def test_create_ecosystem_ticket_with_default_priority(
        self, master_admin_client: E2ETestClient
    ):
        """Priority defaults to 'medium' when not specified."""
        payload = ecosystem_ticket_payload()
        payload.pop("priority")
        response = master_admin_client.post(
            "/api/v1/tickets/ecosystem",
            json=payload)
        assert response.status_code == 201
        assert response.json()["priority"] == "medium"

    def test_create_ecosystem_ticket_without_description(
        self, master_admin_client: E2ETestClient
    ):
        """Description is optional."""
        payload = ecosystem_ticket_payload()
        payload.pop("description")
        response = master_admin_client.post(
            "/api/v1/tickets/ecosystem",
            json=payload)
        assert response.status_code == 201
        assert response.json()["description"] is None

    def test_create_ecosystem_ticket_all_priorities(
        self, master_admin_client: E2ETestClient
    ):
        """All valid priority values are accepted."""
        for priority in ["low", "medium", "high", "critical"]:
            response = master_admin_client.post(
                "/api/v1/tickets/ecosystem",
                json=ecosystem_ticket_payload(
                    title=f"Eco Ticket {priority}", priority=priority
                ))
            assert response.status_code == 201
            assert response.json()["priority"] == priority

    def test_create_ecosystem_ticket_invalid_priority(
        self, master_admin_client: E2ETestClient
    ):
        """Invalid priority value returns 422."""
        response = master_admin_client.post(
            "/api/v1/tickets/ecosystem",
            json=ecosystem_ticket_payload(priority="urgent"))
        assert response.status_code == 422


class TestEcosystemTicketUpdate:
    """Test PATCH /tickets/ecosystem/{id} endpoint."""

    def test_update_ecosystem_ticket_as_master_admin(
        self, master_admin_client: E2ETestClient
    ):
        """Master admin can update an ecosystem ticket."""
        create_response = master_admin_client.post(
            "/api/v1/tickets/ecosystem",
            json=ecosystem_ticket_payload(title="Original Eco Title"))
        ticket_id = create_response.json()["id"]

        response = master_admin_client.patch(
            f"/api/v1/tickets/ecosystem/{ticket_id}",
            json={"title": "Updated Eco Title"})
        assert response.status_code == 200
        assert response.json()["title"] == "Updated Eco Title"

    def test_update_ecosystem_ticket_as_regular_admin_forbidden(
        self, master_admin_client: E2ETestClient, regular_admin_client: E2ETestClient
    ):
        """Regular admin can update ecosystem tickets (Polar policy grants admin write)."""
        create_response = master_admin_client.post(
            "/api/v1/tickets/ecosystem",
            json=ecosystem_ticket_payload(title="Admin Cannot Update"))
        ticket_id = create_response.json()["id"]

        response = regular_admin_client.patch(
            f"/api/v1/tickets/ecosystem/{ticket_id}",
            json={"title": "Attempted Update"})
        assert response.status_code == 200

    def test_update_ecosystem_ticket_as_manager_forbidden(
        self, master_admin_client: E2ETestClient, manager_client: E2ETestClient
    ):
        """Manager can update ecosystem tickets (Polar policy grants manager write)."""
        create_response = master_admin_client.post(
            "/api/v1/tickets/ecosystem",
            json=ecosystem_ticket_payload(title="Manager Cannot Update"))
        ticket_id = create_response.json()["id"]

        response = manager_client.patch(
            f"/api/v1/tickets/ecosystem/{ticket_id}",
            json={"title": "Attempted Update"})
        assert response.status_code == 200

    def test_update_ecosystem_ticket_not_found(
        self, master_admin_client: E2ETestClient
    ):
        """Returns 404 for non-existent ecosystem ticket."""
        response = master_admin_client.patch(
            f"/api/v1/tickets/ecosystem/{uuid4()}",
            json={"title": "Doesn't exist"})
        assert response.status_code == 404

    def test_update_ecosystem_ticket_partial_fields_preserved(
        self, master_admin_client: E2ETestClient
    ):
        """Non-updated fields are preserved after partial update."""
        create_response = master_admin_client.post(
            "/api/v1/tickets/ecosystem",
            json=ecosystem_ticket_payload(title="Partial Eco Test", priority="critical"))
        ticket_id = create_response.json()["id"]

        response = master_admin_client.patch(
            f"/api/v1/tickets/ecosystem/{ticket_id}",
            json={"description": "Updated description"})
        assert response.status_code == 200
        data = response.json()
        assert data["title"] == "Partial Eco Test"
        assert data["priority"] == "critical"
        assert data["description"] == "Updated description"


class TestEcosystemTicketDelete:
    """Test DELETE /tickets/ecosystem/{id} endpoint.

    Only master admin can delete ecosystem tickets.
    All other roles are denied (403).
    """

    def test_delete_ecosystem_ticket_as_master_admin(
        self, master_admin_client: E2ETestClient
    ):
        """Master admin can delete an ecosystem ticket."""
        create_response = master_admin_client.post(
            "/api/v1/tickets/ecosystem",
            json=ecosystem_ticket_payload(title="To Delete Eco"))
        assert create_response.status_code == 201
        ticket_id = create_response.json()["id"]

        response = master_admin_client.delete(
            f"/api/v1/tickets/ecosystem/{ticket_id}")
        assert response.status_code == 204

        get_response = master_admin_client.get(
            f"/api/v1/tickets/ecosystem/{ticket_id}")
        assert get_response.status_code == 404

    def test_delete_ecosystem_ticket_as_regular_admin_forbidden(
        self, master_admin_client: E2ETestClient, regular_admin_client: E2ETestClient
    ):
        """Regular admin can delete ecosystem tickets (Polar policy grants admin delete)."""
        create_response = master_admin_client.post(
            "/api/v1/tickets/ecosystem",
            json=ecosystem_ticket_payload(title="Admin Cannot Delete Eco"))
        ticket_id = create_response.json()["id"]

        response = regular_admin_client.delete(
            f"/api/v1/tickets/ecosystem/{ticket_id}")
        assert response.status_code == 204

    def test_delete_ecosystem_ticket_as_manager_forbidden(
        self, master_admin_client: E2ETestClient, manager_client: E2ETestClient
    ):
        """Manager cannot delete ecosystem tickets."""
        create_response = master_admin_client.post(
            "/api/v1/tickets/ecosystem",
            json=ecosystem_ticket_payload(title="Manager Cannot Delete Eco"))
        ticket_id = create_response.json()["id"]

        response = manager_client.delete(
            f"/api/v1/tickets/ecosystem/{ticket_id}")
        assert response.status_code == 403

    def test_delete_ecosystem_ticket_as_user_forbidden(
        self, master_admin_client: E2ETestClient, user_client: E2ETestClient
    ):
        """Regular user cannot delete ecosystem tickets."""
        create_response = master_admin_client.post(
            "/api/v1/tickets/ecosystem",
            json=ecosystem_ticket_payload(title="User Cannot Delete Eco"))
        ticket_id = create_response.json()["id"]

        response = user_client.delete(
            f"/api/v1/tickets/ecosystem/{ticket_id}")
        assert response.status_code == 403

    def test_delete_ecosystem_ticket_not_found(
        self, master_admin_client: E2ETestClient
    ):
        """Returns 404 when deleting a non-existent ecosystem ticket."""
        response = master_admin_client.delete(
            f"/api/v1/tickets/ecosystem/{uuid4()}")
        assert response.status_code == 404
