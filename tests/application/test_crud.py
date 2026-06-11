"""Tests para la entidad Application — CRUD completo con autorización."""
import pytest

APP_BASE = {
    "version": "1.0.0",
    "url": "https://test.com",
    "description": "Test application",
}


class TestCreateApplication:
    """POST /api/v1/applications"""

    def test_create_application_success(self, master_admin_client):
        response = master_admin_client.post(
            "/api/v1/applications",
            json={
                "name": "App de Monitoreo",
                "administrator_id": str(master_admin_client.account['id']),
                **APP_BASE,
            })
        assert response.status_code == 201
        data = response.json()
        assert data["name"] == "App de Monitoreo"
        assert data["version"] == "1.0.0"
        assert data["url"] == "https://test.com"
        assert data["description"] == "Test application"
        assert data["administrator_id"] == str(master_admin_client.account['id'])
        assert data["is_active"] is True
        assert "id" in data
        assert "api_key" in data
        assert "created_at" in data
        assert "updated_at" in data

    def test_create_application_generates_api_key(self, master_admin_client):
        response = master_admin_client.post(
            "/api/v1/applications",
            json={
                "name": "App con API Key",
                "administrator_id": str(master_admin_client.account['id']),
                **APP_BASE,
            })
        assert response.status_code == 201
        data = response.json()
        assert "api_key" in data
        assert len(data["api_key"]) == 64

    def test_create_application_without_name_fails(self, master_admin_client):
        response = master_admin_client.post(
            "/api/v1/applications",
            json={
                "administrator_id": str(master_admin_client.account['id']),
                **APP_BASE,
            })
        assert response.status_code == 422

    def test_create_application_without_administrator_fails(self, master_admin_client):
        response = master_admin_client.post(
            "/api/v1/applications",
            json={"name": "Sin admin", **APP_BASE})
        assert response.status_code == 422

    def test_create_application_duplicate_name_fails(self, master_admin_client):
        admin_id = str(master_admin_client.account['id'])
        master_admin_client.post(
            "/api/v1/applications",
            json={"name": "Duplicada", "administrator_id": admin_id, **APP_BASE})
        response = master_admin_client.post(
            "/api/v1/applications",
            json={"name": "Duplicada", "administrator_id": admin_id, **APP_BASE})
        assert response.status_code == 500

    def test_create_application_without_session_returns_401(self, client):
        response = client.post(
            "/api/v1/applications",
            json={
                "name": "Sin sesion",
                "administrator_id": "00000000-0000-0000-0000-000000000000",
                **APP_BASE,
            })
        assert response.status_code == 401


class TestListApplications:
    """GET /api/v1/applications"""

    def test_list_applications_empty(self, master_admin_client):
        response = master_admin_client.get("/api/v1/applications")
        assert response.status_code == 200
        data = response.json()
        assert data["total"] == 0
        assert data["data"] == []

    def test_list_applications_with_data(self, master_admin_client):
        admin_id = str(master_admin_client.account['id'])
        master_admin_client.post(
            "/api/v1/applications",
            json={"name": "App 1", "administrator_id": admin_id, **APP_BASE})
        master_admin_client.post(
            "/api/v1/applications",
            json={"name": "App 2", "administrator_id": admin_id, **APP_BASE})
        response = master_admin_client.get("/api/v1/applications")
        assert response.status_code == 200
        data = response.json()
        assert data["total"] == 2
        assert len(data["data"]) == 2

    def test_list_applications_pagination(self, master_admin_client):
        admin_id = str(master_admin_client.account['id'])
        for i in range(5):
            master_admin_client.post(
                "/api/v1/applications",
                json={"name": f"App {i}", "administrator_id": admin_id, **APP_BASE})
        response = master_admin_client.get("/api/v1/applications?offset=0&limit=2")
        data = response.json()
        assert data["total"] == 5
        assert len(data["data"]) == 2


class TestGetApplication:
    """GET /api/v1/applications/{id}"""

    def test_get_application_by_id(self, master_admin_client):
        create_response = master_admin_client.post(
            "/api/v1/applications",
            json={
                "name": "Mi App",
                "administrator_id": str(master_admin_client.account['id']),
                **APP_BASE,
            })
        app_id = create_response.json()["id"]
        response = master_admin_client.get(f"/api/v1/applications/{app_id}")
        assert response.status_code == 200
        assert response.json()["name"] == "Mi App"

    def test_get_application_not_found(self, master_admin_client):
        fake_id = "00000000-0000-0000-0000-000000000000"
        response = master_admin_client.get(f"/api/v1/applications/{fake_id}")
        assert response.status_code == 404


class TestUpdateApplication:
    """PATCH /api/v1/applications/{id}"""

    def test_update_application_name(self, master_admin_client):
        create_response = master_admin_client.post(
            "/api/v1/applications",
            json={
                "name": "Nombre Original",
                "administrator_id": str(master_admin_client.account['id']),
                **APP_BASE,
            })
        app_id = create_response.json()["id"]
        response = master_admin_client.patch(
            f"/api/v1/applications/{app_id}",
            json={"name": "Nombre Actualizado"})
        assert response.status_code == 200
        assert response.json()["name"] == "Nombre Actualizado"

    def test_update_application_description(self, master_admin_client):
        create_response = master_admin_client.post(
            "/api/v1/applications",
            json={
                "name": "App Desc",
                "administrator_id": str(master_admin_client.account['id']),
                **APP_BASE,
            })
        app_id = create_response.json()["id"]
        response = master_admin_client.patch(
            f"/api/v1/applications/{app_id}",
            json={"description": "Nueva descripcion"})
        assert response.status_code == 200
        assert response.json()["description"] == "Nueva descripcion"

    def test_update_application_deactivate(self, master_admin_client):
        create_response = master_admin_client.post(
            "/api/v1/applications",
            json={
                "name": "App Activa",
                "administrator_id": str(master_admin_client.account['id']),
                **APP_BASE,
            })
        app_id = create_response.json()["id"]
        response = master_admin_client.patch(
            f"/api/v1/applications/{app_id}",
            json={"is_active": False})
        assert response.status_code == 200
        assert response.json()["is_active"] is False

    def test_update_application_not_found(self, master_admin_client):
        fake_id = "00000000-0000-0000-0000-000000000000"
        response = master_admin_client.patch(
            f"/api/v1/applications/{fake_id}",
            json={"name": "No existe"})
        assert response.status_code == 404


class TestDeleteApplication:
    """DELETE /api/v1/applications/{id}"""

    def test_delete_application(self, master_admin_client):
        create_response = master_admin_client.post(
            "/api/v1/applications",
            json={
                "name": "Para borrar",
                "administrator_id": str(master_admin_client.account['id']),
                **APP_BASE,
            })
        app_id = create_response.json()["id"]
        response = master_admin_client.delete(f"/api/v1/applications/{app_id}")
        assert response.status_code == 204

        get_response = master_admin_client.get(f"/api/v1/applications/{app_id}")
        assert get_response.status_code == 404

    def test_delete_application_not_found(self, master_admin_client):
        fake_id = "00000000-0000-0000-0000-000000000000"
        response = master_admin_client.delete(f"/api/v1/applications/{fake_id}")
        assert response.status_code == 404
