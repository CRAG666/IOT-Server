"""Pydantic schemas for device telemetry (MongoDB-backed)."""

from datetime import datetime, timezone
from typing import Any
from uuid import UUID

from pydantic import BaseModel, Field


class TelemetryPoint(BaseModel):
    """A single telemetry record from a device."""

    device_id: UUID
    service_id: UUID
    timestamp: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    payload: dict[str, Any]


class TelemetryIngest(BaseModel):
    """Body accepted by POST /telemetry."""

    service_id: UUID
    payload: dict[str, Any]


class TelemetryQuery(BaseModel):
    """Query parameters for GET /telemetry/{device_id}."""

    since: datetime | None = None
    until: datetime | None = None
    limit: int = Field(default=100, ge=1, le=1000)
    offset: int = Field(default=0, ge=0)


class TelemetryPage(BaseModel):
    """Paginated telemetry response."""

    total: int
    offset: int
    limit: int
    data: list[TelemetryPoint]
