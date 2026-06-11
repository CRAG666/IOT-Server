"""Pydantic schemas for webhook CRUD."""

from uuid import UUID

from pydantic import AnyHttpUrl, BaseModel, Field


_VALID_EVENTS = frozenset(
    {"device.telemetry", "service.state_changed", "ticket.created", "payment.completed"}
)


class WebhookCreate(BaseModel):
    url: AnyHttpUrl
    event_types: list[str] = Field(min_length=1)

    def validated_event_types(self) -> str:
        invalid = [e for e in self.event_types if e not in _VALID_EVENTS]
        if invalid:
            raise ValueError(f"Unknown event types: {invalid}. Valid: {sorted(_VALID_EVENTS)}")
        return ",".join(sorted(set(self.event_types)))


class WebhookResponse(BaseModel):
    id: UUID
    url: str
    event_types: list[str]
    is_active: bool

    @classmethod
    def from_model(cls, w) -> "WebhookResponse":
        return cls(
            id=w.id,
            url=w.url,
            event_types=w.event_types.split(","),
            is_active=w.is_active,
        )
