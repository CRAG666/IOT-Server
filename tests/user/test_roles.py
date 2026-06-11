from fastapi.testclient import TestClient
from sqlmodel import Session

from app.database.model import Role, Service, UserRole
from tests.e2e_client import E2ETestClient


def create_service_and_role(db, administrator_id):
    with Session(db) as session:
        service = Service(
            name="User Role Service",
            description="Service for user-role tests",
            administrator_id=administrator_id,
            is_active=True)
        session.add(service)
        session.flush()

        role = Role(
            name="Operator",
            description="Operator role",
            service_id=service.id,
            is_active=True)
        session.add(role)
        session.commit()
        session.refresh(service)
        session.refresh(role)
        return service.id, role.id


class TestUserRoleEndpoints:
    def test_assign_role_to_user_as_master_admin(
        self,
        db,
        master_admin_client: E2ETestClient,
        user_client: E2ETestClient):
        _, role_id = create_service_and_role(db, master_admin_client.account['id'])

        response = master_admin_client.post(
            f"/api/v1/users/{user_client.account['id']}/roles/{role_id}")

        assert response.status_code == 201
        data = response.json()
        assert data["user_id"] == str(user_client.account['id'])
        assert data["role_id"] == str(role_id)

    def test_assign_role_to_user_rejects_duplicate_assignment(
        self,
        db,
        master_admin_client: E2ETestClient,
        user_client: E2ETestClient):
        _, role_id = create_service_and_role(db, master_admin_client.account['id'])

        first_response = master_admin_client.post(
            f"/api/v1/users/{user_client.account['id']}/roles/{role_id}")
        assert first_response.status_code == 201

        second_response = master_admin_client.post(
            f"/api/v1/users/{user_client.account['id']}/roles/{role_id}")

        assert second_response.status_code == 409
        assert "already assigned" in second_response.json()["detail"].lower()

    def test_list_roles_by_user_returns_assigned_roles(
        self,
        db,
        master_admin_client: E2ETestClient,
        user_client: E2ETestClient):
        _, role_id = create_service_and_role(db, master_admin_client.account['id'])

        with Session(db) as session:
            session.add(UserRole(user_id=user_client.account['id'], role_id=role_id))
            session.commit()

        response = master_admin_client.get(
            f"/api/v1/users/{user_client.account['id']}/roles")

        assert response.status_code == 200
        data = response.json()
        assert len(data) == 1
        assert data[0]["id"] == str(role_id)
        assert data[0]["name"] == "Operator"

    def test_remove_role_from_user_deletes_assignment(
        self,
        db,
        master_admin_client: E2ETestClient,
        user_client: E2ETestClient):
        _, role_id = create_service_and_role(db, master_admin_client.account['id'])

        with Session(db) as session:
            session.add(UserRole(user_id=user_client.account['id'], role_id=role_id))
            session.commit()

        delete_response = master_admin_client.delete(
            f"/api/v1/users/{user_client.account['id']}/roles/{role_id}")

        assert delete_response.status_code == 204

        list_response = master_admin_client.get(
            f"/api/v1/users/{user_client.account['id']}/roles")
        assert list_response.status_code == 200
        assert list_response.json() == []

    def test_assign_role_to_user_as_regular_admin_allowed(
        self,
        db,
        master_admin_client: E2ETestClient,
        regular_admin_client: E2ETestClient,
        user_client: E2ETestClient):
        _, role_id = create_service_and_role(db, master_admin_client.account['id'])

        response = regular_admin_client.post(
            f"/api/v1/users/{user_client.account['id']}/roles/{role_id}")

        assert response.status_code == 201
