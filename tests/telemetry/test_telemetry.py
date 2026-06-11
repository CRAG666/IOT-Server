"""Tests for the telemetry domain — repository and HTTP routes (mocked Motor)."""

from __future__ import annotations

import uuid
from datetime import datetime, timezone
from unittest.mock import AsyncMock, MagicMock

import pytest

from app.main import app
from app.domain.telemetry.controller import _repo as _real_repo
from app.domain.telemetry.repository import TelemetryRepository
from app.domain.telemetry.schemas import TelemetryPage, TelemetryPoint


# ─────────────────────────────────────────────────────────────────────────────
# Motor collection mock helpers
# ─────────────────────────────────────────────────────────────────────────────


def _mock_col() -> MagicMock:
    col = MagicMock()
    col.create_indexes = AsyncMock(return_value=None)
    col.insert_one = AsyncMock(return_value=MagicMock(inserted_id="abc"))
    col.count_documents = AsyncMock(return_value=0)
    cursor = MagicMock()
    cursor.sort = MagicMock(return_value=cursor)
    cursor.skip = MagicMock(return_value=cursor)
    cursor.limit = MagicMock(return_value=cursor)
    cursor.to_list = AsyncMock(return_value=[])
    col.find = MagicMock(return_value=cursor)
    return col


def _mock_db(col: MagicMock | None = None) -> MagicMock:
    col = col or _mock_col()
    db = MagicMock()
    db.__getitem__ = MagicMock(return_value=col)
    return db


# ─────────────────────────────────────────────────────────────────────────────
# TelemetryRepository unit tests
# ─────────────────────────────────────────────────────────────────────────────


class TestTelemetryRepository:
    @pytest.mark.anyio
    async def test_ensure_indexes_calls_create_indexes(self):
        col = _mock_col()
        repo = TelemetryRepository(_mock_db(col))
        await repo.ensure_indexes()
        col.create_indexes.assert_awaited_once()

    @pytest.mark.anyio
    async def test_insert_calls_insert_one(self):
        col = _mock_col()
        repo = TelemetryRepository(_mock_db(col))
        point = TelemetryPoint(
            device_id=uuid.uuid4(),
            service_id=uuid.uuid4(),
            payload={"temp": 22.5},
        )
        await repo.insert(point)
        col.insert_one.assert_awaited_once()
        doc = col.insert_one.call_args[0][0]
        assert isinstance(doc["device_id"], str)
        assert isinstance(doc["service_id"], str)

    @pytest.mark.anyio
    async def test_query_returns_empty_page(self):
        col = _mock_col()
        repo = TelemetryRepository(_mock_db(col))
        device_id = uuid.uuid4()
        page = await repo.query(device_id, None, None, 100, 0)
        assert isinstance(page, TelemetryPage)
        assert page.total == 0
        assert page.data == []

    @pytest.mark.anyio
    async def test_query_with_time_range_adds_filter(self):
        col = _mock_col()
        repo = TelemetryRepository(_mock_db(col))
        device_id = uuid.uuid4()
        since = datetime(2024, 1, 1, tzinfo=timezone.utc)
        until = datetime(2024, 12, 31, tzinfo=timezone.utc)
        await repo.query(device_id, since, until, 50, 10)
        filt = col.count_documents.call_args[0][0]
        assert "$gte" in filt["timestamp"]
        assert "$lte" in filt["timestamp"]

    @pytest.mark.anyio
    async def test_query_with_since_only(self):
        col = _mock_col()
        repo = TelemetryRepository(_mock_db(col))
        device_id = uuid.uuid4()
        since = datetime(2024, 1, 1, tzinfo=timezone.utc)
        await repo.query(device_id, since, None, 100, 0)
        filt = col.count_documents.call_args[0][0]
        assert "$gte" in filt["timestamp"]
        assert "$lte" not in filt["timestamp"]

    @pytest.mark.anyio
    async def test_query_with_docs_returns_points(self):
        col = _mock_col()
        device_id = uuid.uuid4()
        service_id = uuid.uuid4()
        ts = datetime.now(timezone.utc)
        doc = {
            "device_id": str(device_id),
            "service_id": str(service_id),
            "timestamp": ts.isoformat(),
            "payload": {"key": "val"},
        }
        col.count_documents = AsyncMock(return_value=1)
        cursor = MagicMock()
        cursor.sort = MagicMock(return_value=cursor)
        cursor.skip = MagicMock(return_value=cursor)
        cursor.limit = MagicMock(return_value=cursor)
        cursor.to_list = AsyncMock(return_value=[doc])
        col.find = MagicMock(return_value=cursor)
        repo = TelemetryRepository(_mock_db(col))
        page = await repo.query(device_id, None, None, 100, 0)
        assert page.total == 1
        assert len(page.data) == 1
        assert page.data[0].device_id == device_id


# ─────────────────────────────────────────────────────────────────────────────
# Telemetry HTTP routes (via master_admin_client)
# ─────────────────────────────────────────────────────────────────────────────


@pytest.fixture
def mock_telemetry_repo():
    col = _mock_col()
    repo = TelemetryRepository(_mock_db(col))
    app.dependency_overrides[_real_repo] = lambda: repo
    yield repo
    app.dependency_overrides.pop(_real_repo, None)


class TestTelemetryRoutes:
    def test_ingest_telemetry_returns_201(self, master_admin_client, mock_telemetry_repo):
        device_id = uuid.uuid4()
        service_id = uuid.uuid4()
        resp = master_admin_client.post(
            f"/api/v1/telemetry/{device_id}",
            json={"service_id": str(service_id), "payload": {"temp": 22.5}},
        )
        assert resp.status_code == 201

    def test_get_telemetry_returns_200(self, master_admin_client, mock_telemetry_repo):
        device_id = uuid.uuid4()
        resp = master_admin_client.get(f"/api/v1/telemetry/{device_id}")
        assert resp.status_code == 200

    def test_ingest_telemetry_403_for_manager(self, manager_client, mock_telemetry_repo):
        """Managers have read-only Telemetry access — write must be denied."""
        device_id = uuid.uuid4()
        service_id = uuid.uuid4()
        resp = manager_client.post(
            f"/api/v1/telemetry/{device_id}",
            json={"service_id": str(service_id), "payload": {"v": 1}},
        )
        assert resp.status_code == 403

    def test_get_telemetry_with_time_range(self, master_admin_client, mock_telemetry_repo):
        device_id = uuid.uuid4()
        resp = master_admin_client.get(
            f"/api/v1/telemetry/{device_id}?since=2024-01-01T00:00:00Z&until=2024-12-31T23:59:59Z"
        )
        assert resp.status_code == 200
