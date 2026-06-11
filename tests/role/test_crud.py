"""Tests para la entidad Role — CRUD API, validación de esquemas y asignaciones UserRole."""
import pytest
from uuid import uuid4

from app.domain.role.schemas import RoleCreate, RoleUpdate


# ── Fixtures ────────────────────────────────────────────────────────


@pytest.fixture
def service_id(master_admin_client):
    resp = master_admin_client.post(
        "/api/v1/services",
        json={
            "name": "Svc Role Test",
            "description": "Fixture service for roles",
            "administrator_id": str(master_admin_client.account['id']),
        })
    assert resp.status_code == 201, resp.text
    return resp.json()["id"]


@pytest.fixture
def role_id(master_admin_client, service_id):
    resp = master_admin_client.post(
        "/api/v1/roles",
        json={"name": "Operador", "service_id": service_id})
    assert resp.status_code == 201, resp.text
    return resp.json()["id"]


# ── Tests: Schema validation ─────────────────────────────────────────


class TestRoleSchemaValidation:
    def test_create_accepts_unicode_letters_only(self):
        payload = RoleCreate(
            name="OperadorÓ",
            service_id="00000000-0000-0000-0000-000000000001")
        assert payload.name == "OperadorÓ"

    def test_create_rejects_digit_in_name(self):
        with pytest.raises(ValueError):
            RoleCreate(name="Bad1", service_id=str(uuid4()))

    def test_create_rejects_space_in_name(self):
        with pytest.raises(ValueError):
            RoleCreate(name="Dos Palabras", service_id=str(uuid4()))

    def test_update_optional_name_must_be_valid(self):
        RoleUpdate(description="ok")
        with pytest.raises(ValueError):
            RoleUpdate(name="_bad")


# ── Tests: CRUD ──────────────────────────────────────────────────────


class TestRoleCreateApi:
    def test_create_role_success_master_admin(self, master_admin_client, service_id):
        response = master_admin_client.post(
            "/api/v1/roles",
            json={
                "name": "Moderador",
                "description": "Gestión de contenido",
                "service_id": service_id,
                "is_active": True,
            })
        assert response.status_code == 201, response.text
        data = response.json()
        assert data["name"] == "Moderador"
        assert data["description"] == "Gestión de contenido"
        assert data["service_id"] == service_id
        assert data["is_active"] is True
        assert "id" in data
        assert "created_at" in data

    def test_create_role_invalid_name_returns_422(self, master_admin_client, service_id):
        response = master_admin_client.post(
            "/api/v1/roles",
            json={"name": "Rol-ConGuion", "service_id": service_id})
        assert response.status_code == 422

    def test_create_role_extra_fields_forbidden(self, master_admin_client, service_id):
        response = master_admin_client.post(
            "/api/v1/roles",
            json={"name": "Moderadorextra", "service_id": service_id, "unexpected": True})
        assert response.status_code == 422


class TestRoleListRetrieveApi:
    def test_list_requires_auth(self, client):
        response = client.get("/api/v1/roles")
        assert response.status_code == 401

    def test_list_roles_user_not_allowed(self, master_admin_client, user_client, service_id):
        master_admin_client.post(
            "/api/v1/roles",
            json={"name": "Lector", "service_id": service_id})
        response = user_client.get("/api/v1/roles")
        assert response.status_code == 403


class TestRoleAuthorizationApi:
    def test_user_cannot_create_role(self, user_client, service_id):
        response = user_client.post(
            "/api/v1/roles",
            json={"name": "Forbidden", "service_id": service_id})
        assert response.status_code == 403

    def test_manager_cannot_create_role(self, manager_client, service_id):
        response = manager_client.post(
            "/api/v1/roles",
            json={"name": "Encargado", "service_id": service_id})
        assert response.status_code == 403

    def test_manager_cannot_delete_role(self, master_admin_client, manager_client, service_id):
        create_resp = master_admin_client.post(
            "/api/v1/roles",
            json={"name": "ParaBorrar", "service_id": service_id})
        assert create_resp.status_code == 201
        role_id = create_resp.json()["id"]

        response = manager_client.delete(f"/api/v1/roles/{role_id}")
        assert response.status_code == 403

    def test_regular_admin_cannot_delete_role(
            self, master_admin_client, regular_admin_client, service_id):
        create_resp = master_admin_client.post(
            "/api/v1/roles",
            json={"name": "BorradoAdminRegular", "service_id": service_id})
        role_id = create_resp.json()["id"]

        response = regular_admin_client.delete(f"/api/v1/roles/{role_id}")
        assert response.status_code == 403


class TestRoleUpdateDeleteApi:
    def test_regular_admin_cannot_patch_role(
            self, master_admin_client, regular_admin_client, service_id):
        create_resp = master_admin_client.post(
            "/api/v1/roles",
            json={"name": "NombreInicial", "description": "d", "service_id": service_id})
        role_id = create_resp.json()["id"]

        response = regular_admin_client.patch(
            f"/api/v1/roles/{role_id}",
            json={"description": None, "is_active": False})
        assert response.status_code == 403

    def test_get_role_not_found(self, master_admin_client):
        response = master_admin_client.get(f"/api/v1/roles/{uuid4()}")
        assert response.status_code == 404


# ── Tests: UserRole ───────────────────────────────────────────────────


class TestUserRoleAssignApi:
    """POST /roles/{role_id}/users — asignar usuario a rol."""

    def test_admin_can_assign_user_to_role(
            self, master_admin_client, user_client, role_id):
        response = master_admin_client.post(
            f"/api/v1/roles/{role_id}/users",
            json={"user_id": str(user_client.account['id'])})
        assert response.status_code == 201, response.text
        data = response.json()
        assert data["user_id"] == str(user_client.account['id'])
        assert data["role_id"] == role_id
        assert "id" in data
        assert "created_at" in data

    def test_user_cannot_assign_role(self, user_client, role_id):
        response = user_client.post(
            f"/api/v1/roles/{role_id}/users",
            json={"user_id": str(user_client.account['id'])})
        assert response.status_code == 403

    def test_duplicate_assignment_returns_409(
            self, master_admin_client, user_client, role_id):
        payload = {"user_id": str(user_client.account['id'])}
        master_admin_client.post(f"/api/v1/roles/{role_id}/users", json=payload)
        response = master_admin_client.post(f"/api/v1/roles/{role_id}/users", json=payload)
        assert response.status_code == 409

    def test_assign_nonexistent_user_returns_404(self, master_admin_client, role_id):
        response = master_admin_client.post(
            f"/api/v1/roles/{role_id}/users",
            json={"user_id": str(uuid4())})
        assert response.status_code == 404

    def test_assign_to_nonexistent_role_returns_404(
            self, master_admin_client, user_client):
        response = master_admin_client.post(
            f"/api/v1/roles/{uuid4()}/users",
            json={"user_id": str(user_client.account['id'])})
        assert response.status_code == 404


class TestUserRoleListApi:
    """GET /roles/{role_id}/users — listar asignaciones."""

    def test_admin_can_list_assigned_users(
            self, master_admin_client, user_client, role_id):
        master_admin_client.post(
            f"/api/v1/roles/{role_id}/users",
            json={"user_id": str(user_client.account['id'])})
        response = master_admin_client.get(f"/api/v1/roles/{role_id}/users")
        assert response.status_code == 200
        data = response.json()
        assert isinstance(data, list)
        assert any(item["user_id"] == str(user_client.account['id']) for item in data)

    def test_list_users_role_not_found(self, master_admin_client):
        response = master_admin_client.get(f"/api/v1/roles/{uuid4()}/users")
        assert response.status_code == 404

    def test_list_requires_auth(self, client, role_id):
        response = client.get(f"/api/v1/roles/{role_id}/users")
        assert response.status_code == 401


class TestUserRoleRemoveApi:
    """DELETE /roles/{role_id}/users/{user_id} — quitar usuario de rol."""

    def test_admin_can_remove_user_from_role(
            self, master_admin_client, user_client, role_id):
        master_admin_client.post(
            f"/api/v1/roles/{role_id}/users",
            json={"user_id": str(user_client.account['id'])})
        response = master_admin_client.delete(
            f"/api/v1/roles/{role_id}/users/{user_client.account['id']}")
        assert response.status_code == 204

    def test_user_cannot_remove_assignment(
            self, master_admin_client, user_client, role_id):
        master_admin_client.post(
            f"/api/v1/roles/{role_id}/users",
            json={"user_id": str(user_client.account['id'])})
        response = user_client.delete(
            f"/api/v1/roles/{role_id}/users/{user_client.account['id']}")
        assert response.status_code == 403

    def test_remove_nonexistent_assignment_returns_404(
            self, master_admin_client, user_client, role_id):
        response = master_admin_client.delete(
            f"/api/v1/roles/{role_id}/users/{user_client.account['id']}")
        assert response.status_code == 404
