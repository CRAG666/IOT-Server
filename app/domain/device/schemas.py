from typing import Optional
from uuid import UUID
from pydantic import BaseModel


class DeviceCreate(BaseModel):
    name: str


class DeviceUpdate(BaseModel):
    name: Optional[str] = None


class DeviceResponse(BaseModel):
    id: UUID
    name: str
