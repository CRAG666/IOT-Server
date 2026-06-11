"""Tests para la entidad Service — CRUD completo con autorización."""
import pytest
from datetime import datetime, timezone


class TestCreateService:
    """POST /api/v1/services"""

    def test_create_service_success(self, master_admin_client):
        response = master_admin_client.post(
            "/api/v1/services",
            json={
                "name": "Monitoreo de Temperatura",
                "description": "Sensores de temperatura",
                "administrator_id": str(master_admin_client.account['id']),
            })
        assert response.status_code == 201
        data = response.json()
        assert data["name"] == "Monitoreo de Temperatura"
        assert data["description"] == "Sensores de temperatura"
        assert data["administrator_id"] == str(master_admin_client.account['id'])
        assert data["is_active"] is True
        assert "id" in data
        assert "created_at" in data
        assert "updated_at" in data

    def test_create_service_without_description(self, master_admin_client):
        response = master_admin_client.post(
            "/api/v1/services",
            json={
                "name": "Servicio sin descripcion",
                "administrator_id": str(master_admin_client.account['id']),
            })
        assert response.status_code == 201
        assert response.json()["description"] is None

    def test_create_service_without_name_fails(self, master_admin_client):
        response = master_admin_client.post(
            "/api/v1/services",
            json={
                "description": "Falta el name",
                "administrator_id": str(master_admin_client.account['id']),
            })
        assert response.status_code == 422

    def test_create_service_without_administrator_fails(self, master_admin_client):
        response = master_admin_client.post(
            "/api/v1/services",
            json={"name": "Sin admin"})
        assert response.status_code == 422

    def test_create_service_duplicate_name_fails(self, master_admin_client):
        admin_id = str(master_admin_client.account['id'])
        master_admin_client.post(
            "/api/v1/services",
            json={"name": "Duplicado", "administrator_id": admin_id})
        response = master_admin_client.post(
            "/api/v1/services",
            json={"name": "Duplicado", "administrator_id": admin_id})
        assert response.status_code == 500

    def test_create_service_without_session_returns_401(self, client):
        response = client.post(
            "/api/v1/services",
            json={"name": "Sin sesion", "administrator_id": "00000000-0000-0000-0000-000000000000"})
        assert response.status_code == 401


class TestListServices:
    """GET /api/v1/services"""

    def test_list_services_empty(self, master_admin_client):
        response = master_admin_client.get("/api/v1/services")
        assert response.status_code == 200
        data = response.json()
        assert data["total"] == 0
        assert data["data"] == []

    def test_list_services_with_data(self, master_admin_client):
        admin_id = str(master_admin_client.account['id'])
        master_admin_client.post(
            "/api/v1/services",
            json={"name": "Servicio 1", "administrator_id": admin_id})
        master_admin_client.post(
            "/api/v1/services",
            json={"name": "Servicio 2", "administrator_id": admin_id})
        response = master_admin_client.get("/api/v1/services")
        assert response.status_code == 200
        data = response.json()
        assert data["total"] == 2
        assert len(data["data"]) == 2

    def test_list_services_pagination(self, master_admin_client):
        admin_id = str(master_admin_client.account['id'])
        for i in range(5):
            master_admin_client.post(
                "/api/v1/services",
                json={"name": f"Servicio {i}", "administrator_id": admin_id})
        response = master_admin_client.get("/api/v1/services?offset=0&limit=2")
        data = response.json()
        assert data["total"] == 5
        assert len(data["data"]) == 2


class TestGetService:
    """GET /api/v1/services/{id}"""

    def test_get_service_by_id(self, master_admin_client):
        create_response = master_admin_client.post(
            "/api/v1/services",
            json={
                "name": "Mi Servicio",
                "administrator_id": str(master_admin_client.account['id']),
            })
        service_id = create_response.json()["id"]
        response = master_admin_client.get(f"/api/v1/services/{service_id}")
        assert response.status_code == 200
        assert response.json()["name"] == "Mi Servicio"

    def test_get_service_not_found(self, master_admin_client):
        fake_id = "00000000-0000-0000-0000-000000000000"
        response = master_admin_client.get(f"/api/v1/services/{fake_id}")
        assert response.status_code == 404


class TestUpdateService:
    """PATCH /api/v1/services/{id}"""

    def test_update_service_name(self, master_admin_client):
        create_response = master_admin_client.post(
            "/api/v1/services",
            json={
                "name": "Nombre Original",
                "administrator_id": str(master_admin_client.account['id']),
            })
        service_id = create_response.json()["id"]
        response = master_admin_client.patch(
            f"/api/v1/services/{service_id}",
            json={"name": "Nombre Actualizado"})
        assert response.status_code == 200
        assert response.json()["name"] == "Nombre Actualizado"

    def test_update_service_description(self, master_admin_client):
        create_response = master_admin_client.post(
            "/api/v1/services",
            json={
                "name": "Servicio Desc",
                "administrator_id": str(master_admin_client.account['id']),
            })
        service_id = create_response.json()["id"]
        response = master_admin_client.patch(
            f"/api/v1/services/{service_id}",
            json={"description": "Nueva descripcion"})
        assert response.status_code == 200
        assert response.json()["description"] == "Nueva descripcion"

    def test_update_service_deactivate(self, master_admin_client):
        create_response = master_admin_client.post(
            "/api/v1/services",
            json={
                "name": "Servicio Activo",
                "administrator_id": str(master_admin_client.account['id']),
            })
        service_id = create_response.json()["id"]
        response = master_admin_client.patch(
            f"/api/v1/services/{service_id}",
            json={"is_active": False})
        assert response.status_code == 200
        assert response.json()["is_active"] is False

    def test_update_service_not_found(self, master_admin_client):
        fake_id = "00000000-0000-0000-0000-000000000000"
        response = master_admin_client.patch(
            f"/api/v1/services/{fake_id}",
            json={"name": "No existe"})
        assert response.status_code == 404


class TestDeleteService:
    """DELETE /api/v1/services/{id}"""

    def test_delete_service(self, master_admin_client):
        create_response = master_admin_client.post(
            "/api/v1/services",
            json={
                "name": "Para borrar",
                "administrator_id": str(master_admin_client.account['id']),
            })
        service_id = create_response.json()["id"]
        response = master_admin_client.delete(f"/api/v1/services/{service_id}")
        assert response.status_code == 204

        get_response = master_admin_client.get(f"/api/v1/services/{service_id}")
        assert get_response.status_code == 404

    def test_delete_service_not_found(self, master_admin_client):
        fake_id = "00000000-0000-0000-0000-000000000000"
        response = master_admin_client.delete(f"/api/v1/services/{fake_id}")
        assert response.status_code == 404
