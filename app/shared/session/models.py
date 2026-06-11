from datetime import datetime
from typing import Any

from pydantic import BaseModel, Field, field_serializer


class SessionData(BaseModel):
    user_id: str
    token_id: str
    refresh_token: str
    email: str
    account_type: str
    is_master: bool
    ip_address: str
    user_agent: str
    created_at: datetime
    last_activity: datetime

    @field_serializer("created_at", "last_activity")
    def _serialize_datetime(self, value: datetime) -> str:
        return value.isoformat()


class SessionTokens(BaseModel):
    access_token: str
    refresh_token: str
    token_type: str = "bearer"


class UserData(BaseModel):
    user_id: str
    email: str
    account_type: str
    is_master: bool
    token_id: str | None = None


class EntitySessionData(BaseModel):
    session_id: str
    entity_id: str
    key_session: str
    ip_address: str
    metadata: dict[str, Any] = Field(default_factory=dict)
    created_at: datetime
    last_activity: datetime

    @field_serializer("created_at", "last_activity")
    def _serialize_datetime(self, value: datetime) -> str:
        return value.isoformat()


class EntitySessionResponse(BaseModel):
    session_id: str
