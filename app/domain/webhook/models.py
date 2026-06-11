"""SQLModel table for webhook endpoint registration."""

from uuid import UUID

from sqlmodel import Field

from app.shared.base_domain.model import BaseTable


class WebhookEndpoint(BaseTable, table=True):
    __tablename__ = "webhook_endpoint"  # pyright: ignore[reportAssignmentType]

    # Who registered this webhook
    owner_id: UUID = Field(index=True)

    # Destination
    url: str = Field(max_length=2048)

    # Comma-separated event types, e.g. "device.telemetry,service.state_changed"
    event_types: str

    # HMAC-SHA256 signing secret (per-endpoint)
    secret: str

    is_active: bool = Field(default=True)
