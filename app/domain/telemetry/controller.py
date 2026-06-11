"""Telemetry endpoints — ingest and query device telemetry from MongoDB."""

from datetime import datetime
from uuid import UUID

from fastapi import APIRouter, Depends, Query
from fastapi import status as http_status

from app.domain.telemetry.repository import TelemetryRepository
from app.domain.telemetry.schemas import TelemetryIngest, TelemetryPage, TelemetryPoint
from app.shared.authorization.dependencies import CurrentAccountDep, require_write, require_read
from app.shared.mongodb import get_mongo_db


# Casbin resource sentinel — name "Telemetry" matches policy.csv entries
class Telemetry:
    pass


telemetry_router = APIRouter(prefix="/telemetry", tags=["Telemetry"])


def _repo() -> TelemetryRepository:
    return TelemetryRepository(get_mongo_db())


@telemetry_router.post(
    "/{device_id}",
    status_code=http_status.HTTP_201_CREATED,
    response_model=TelemetryPoint,
    dependencies=[require_write(Telemetry)],
)
async def ingest_telemetry(
    device_id: UUID,
    body: TelemetryIngest,
    current_account: CurrentAccountDep,
    repo: TelemetryRepository = Depends(_repo),
) -> TelemetryPoint:
    """Ingest a telemetry payload for a device."""
    point = TelemetryPoint(
        device_id=device_id,
        service_id=body.service_id,
        payload=body.payload,
    )
    await repo.insert(point)
    return point


@telemetry_router.get(
    "/{device_id}",
    response_model=TelemetryPage,
    dependencies=[require_read(Telemetry)],
)
async def get_telemetry(
    device_id: UUID,
    current_account: CurrentAccountDep,
    since: datetime | None = Query(default=None),
    until: datetime | None = Query(default=None),
    limit: int = Query(default=100, ge=1, le=1000),
    offset: int = Query(default=0, ge=0),
    repo: TelemetryRepository = Depends(_repo),
) -> TelemetryPage:
    """Query historical telemetry for a device with optional time-range filter."""
    return await repo.query(device_id, since, until, limit, offset)
