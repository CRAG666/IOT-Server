"""MongoDB repository for device telemetry."""

from datetime import datetime
from uuid import UUID

from motor.motor_asyncio import AsyncIOMotorDatabase
from pymongo import DESCENDING, IndexModel

from app.domain.telemetry.schemas import TelemetryPage, TelemetryPoint

_COLLECTION = "telemetry"


class TelemetryRepository:
    def __init__(self, db: AsyncIOMotorDatabase) -> None:
        self._col = db[_COLLECTION]

    async def ensure_indexes(self) -> None:
        await self._col.create_indexes([
            IndexModel([("device_id", DESCENDING), ("timestamp", DESCENDING)]),
            IndexModel([("service_id", DESCENDING)]),
            IndexModel([("timestamp", DESCENDING)]),
        ])

    async def insert(self, point: TelemetryPoint) -> None:
        doc = point.model_dump(mode="json")
        doc["device_id"] = str(point.device_id)
        doc["service_id"] = str(point.service_id)
        await self._col.insert_one(doc)

    async def query(
        self,
        device_id: UUID,
        since: datetime | None,
        until: datetime | None,
        limit: int,
        offset: int,
    ) -> TelemetryPage:
        filt: dict = {"device_id": str(device_id)}
        if since or until:
            filt["timestamp"] = {}
            if since:
                filt["timestamp"]["$gte"] = since.isoformat()
            if until:
                filt["timestamp"]["$lte"] = until.isoformat()

        total = await self._col.count_documents(filt)
        cursor = self._col.find(filt, {"_id": 0}).sort("timestamp", DESCENDING).skip(offset).limit(limit)
        docs = await cursor.to_list(length=limit)

        return TelemetryPage(
            total=total,
            offset=offset,
            limit=limit,
            data=[TelemetryPoint(**d) for d in docs],
        )
