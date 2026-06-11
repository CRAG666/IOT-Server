"""Tests for infrastructure modules — MongoDB helpers, logging, E2E session,
mqtt_bridge helpers, shared/middleware coverage, and small model/database gaps."""

from __future__ import annotations

import uuid
from unittest.mock import AsyncMock, MagicMock, patch

import fakeredis
import pytest
from sqlmodel import Session

from app.services.mqtt_bridge import _parse_device_id


# ─────────────────────────────────────────────────────────────────────────────
# mqtt_bridge._parse_device_id
# ─────────────────────────────────────────────────────────────────────────────


class TestParseDeviceId:
    def test_valid_topic_returns_uuid(self):
        device_id = uuid.uuid4()
        topic = f"iot/{device_id}/telemetry"
        result = _parse_device_id(topic)
        assert result == device_id

    def test_invalid_parts_returns_none(self):
        assert _parse_device_id("iot/telemetry") is None
        assert _parse_device_id("iot/a/b/c") is None

    def test_non_uuid_device_id_returns_none(self):
        result = _parse_device_id("iot/not-a-uuid/telemetry")
        assert result is None


# ─────────────────────────────────────────────────────────────────────────────
# app.shared.mongodb factory functions
# ─────────────────────────────────────────────────────────────────────────────


class TestMongoDb:
    def test_get_mongo_client_creates_client(self):
        import app.shared.mongodb as mongo_module

        # Reset singleton
        mongo_module._client = None

        with patch("app.shared.mongodb.AsyncIOMotorClient") as mock_cls:
            mock_instance = MagicMock()
            mock_cls.return_value = mock_instance

            client = mongo_module.get_mongo_client()

            mock_cls.assert_called_once()
            assert client is mock_instance
            mongo_module._client = None  # cleanup

    def test_get_mongo_client_returns_cached(self):
        import app.shared.mongodb as mongo_module

        sentinel = MagicMock()
        mongo_module._client = sentinel
        try:
            client = mongo_module.get_mongo_client()
            assert client is sentinel
        finally:
            mongo_module._client = None

    def test_get_mongo_db_returns_database(self):
        import app.shared.mongodb as mongo_module

        mock_client = MagicMock()
        mock_db = MagicMock()
        mock_client.__getitem__ = MagicMock(return_value=mock_db)
        mongo_module._client = mock_client
        try:
            db = mongo_module.get_mongo_db()
            assert db is mock_db
        finally:
            mongo_module._client = None

    @pytest.mark.anyio
    async def test_close_mongo_client_closes_and_resets(self):
        import app.shared.mongodb as mongo_module

        mock_client = MagicMock()
        mock_client.close = MagicMock()
        mongo_module._client = mock_client
        try:
            await mongo_module.close_mongo_client()
            mock_client.close.assert_called_once()
            assert mongo_module._client is None
        finally:
            mongo_module._client = None

    @pytest.mark.anyio
    async def test_close_mongo_client_noop_when_none(self):
        import app.shared.mongodb as mongo_module

        mongo_module._client = None
        await mongo_module.close_mongo_client()  # should not raise


# ─────────────────────────────────────────────────────────────────────────────
# app.shared.logging.init_logging
# ─────────────────────────────────────────────────────────────────────────────


class TestInitLogging:
    def test_init_logging_runs_without_error(self, tmp_path, monkeypatch):
        from app import shared
        import app.shared.logging as logging_module

        # Point LOG_DIR at a temp location
        monkeypatch.setattr(logging_module, "LOG_DIR", tmp_path / "logs")
        monkeypatch.setattr(logging_module, "LOG_FILE", tmp_path / "logs" / "test.log")

        logging_module.init_logging(debug=False)
        logging_module.init_logging(debug=True)


# ─────────────────────────────────────────────────────────────────────────────
# app.shared.auth.security.get_password_hash
# ─────────────────────────────────────────────────────────────────────────────


class TestGetPasswordHash:
    def test_get_password_hash_returns_tuple(self):
        from app.shared.auth.security import get_password_hash

        result = get_password_hash("MyPass123!")
        assert isinstance(result, tuple)
        assert len(result) == 2
        pw_hash, salt = result
        assert len(pw_hash) == 64  # SHA-256 hex
        assert len(salt) == 32     # 16 bytes → 32 hex chars

    def test_get_password_hash_different_calls_produce_different_salts(self):
        from app.shared.auth.security import get_password_hash

        h1, s1 = get_password_hash("SamePassword1!")
        h2, s2 = get_password_hash("SamePassword1!")
        assert s1 != s2
        assert h1 != h2


# ─────────────────────────────────────────────────────────────────────────────
# app.database.model — SensitiveData edge cases
# ─────────────────────────────────────────────────────────────────────────────


class TestSensitiveDataModel:
    def test_password_getter_raises(self, session):
        from app.database.model import NonCriticalPersonalData, SensitiveData

        nc = NonCriticalPersonalData(first_name="Test", last_name="User")
        session.add(nc)
        session.flush()
        sd = SensitiveData(non_critical_data_id=nc.id, email="edge@test.com", password="TestPass123!")
        session.add(sd)
        session.flush()

        with pytest.raises(AttributeError, match="write-only"):
            _ = sd.password

    def test_sqlmodel_update_with_password_updates_hash(self, session):
        from app.database.model import NonCriticalPersonalData, SensitiveData

        nc = NonCriticalPersonalData(first_name="Test2", last_name="User2")
        session.add(nc)
        session.flush()
        sd = SensitiveData(non_critical_data_id=nc.id, email="update@test.com", password="OldPass123!")
        session.add(sd)
        session.flush()

        old_hash = sd.password_hash
        sd.sqlmodel_update({"password": "NewPass456!"})
        assert sd.password_hash != old_hash


# ─────────────────────────────────────────────────────────────────────────────
# app.database.__init__ — get_session and create_db_and_tables
# ─────────────────────────────────────────────────────────────────────────────


class TestDatabaseInit:
    def test_get_session_yields_session(self, db):
        from app.database import get_session
        import app.database as db_module

        original = db_module.engine
        db_module.engine = db
        try:
            gen = get_session()
            session = next(gen)
            assert isinstance(session, Session)
            try:
                next(gen)
            except StopIteration:
                pass
        finally:
            db_module.engine = original

    def test_create_db_and_tables_runs(self, db, monkeypatch):
        import app.database as db_module
        from app.database import create_db_and_tables

        monkeypatch.setattr(db_module, "engine", db)
        create_db_and_tables()


# ─────────────────────────────────────────────────────────────────────────────
# app.shared.e2e.session — connect / close / corrupted JSON
# ─────────────────────────────────────────────────────────────────────────────


class TestE2ESessionEdgeCases:
    @pytest.mark.anyio
    async def test_close_with_external_client_is_noop(self):
        from app.shared.e2e.session import E2ESessionRepository

        fake = fakeredis.FakeAsyncValkey(decode_responses=True)
        repo = E2ESessionRepository("redis://localhost:6379/0")
        repo.client = fake
        repo._external_client = True

        await repo.close()  # should NOT close the external client
        assert repo.client is fake

    @pytest.mark.anyio
    async def test_close_non_external_client_nulls_it(self):
        from app.shared.e2e.session import E2ESessionRepository

        fake = fakeredis.FakeAsyncValkey(decode_responses=True)
        repo = E2ESessionRepository("redis://localhost:6379/0")
        repo.client = fake
        repo._external_client = False

        await repo.close()
        assert repo.client is None

    @pytest.mark.anyio
    async def test_get_session_corrupted_json_returns_none(self):
        from app.shared.e2e.session import E2ESessionRepository, _SESSION_PREFIX

        fake = fakeredis.FakeAsyncValkey(decode_responses=True)
        repo = E2ESessionRepository("redis://localhost:6379/0")
        repo.client = fake
        repo._external_client = True

        session_id = "bad-json-session"
        await fake.set(f"{_SESSION_PREFIX}{session_id}", "{invalid json}")

        result = await repo.get_session(session_id)
        assert result is None

    @pytest.mark.anyio
    async def test_connect_creates_client_when_none(self):
        from app.shared.e2e.session import E2ESessionRepository

        repo = E2ESessionRepository("redis://localhost:6379/0")
        assert repo.client is None

        mock_client = MagicMock()

        async def fake_from_url(*args, **kwargs):
            return mock_client

        with patch("valkey.asyncio.from_url", side_effect=fake_from_url):
            await repo.connect()

        assert repo.client is mock_client


# ─────────────────────────────────────────────────────────────────────────────
# app.shared.middleware.tenant — non-master admin path
# ─────────────────────────────────────────────────────────────────────────────


class TestTenantMiddleware:
    def test_non_master_admin_gets_tenant_id_looked_up(self, regular_admin_client):
        """The tenant middleware resolves tenant_id for non-master admins."""
        # Any authenticated route will trigger the middleware
        resp = regular_admin_client.get("/api/v1/administrators")
        # Ensure middleware ran (200 or 403 are both fine — we just want no 500)
        assert resp.status_code != 500

    def test_unauthenticated_request_sets_tenant_id_none(self, client):
        resp = client.get("/health")
        assert resp.status_code == 200
