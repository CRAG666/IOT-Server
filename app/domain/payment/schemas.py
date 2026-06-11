from decimal import Decimal
from uuid import UUID
from datetime import datetime
from pydantic import BaseModel
from app.shared.base_domain.schemas import BaseSchemaResponse


class SubscriptionTypeCreate(BaseModel):
    type: str
    cost: Decimal


class SubscriptionTypeUpdate(BaseModel):
    type: str | None = None
    cost: Decimal | None = None


class SubscriptionTypeResponse(BaseSchemaResponse):
    type: str
    cost: float  # serialized as float in JSON for client compatibility


class UserServiceResponse(BaseSchemaResponse):
    user_id: UUID
    service_id: UUID
    is_active: bool


class PaymentCreate(BaseModel):
    user_service_id: UUID
    subscription_type_id: UUID
    deposit_id: str
    amount: Decimal


class PaymentResponse(BaseSchemaResponse):
    user_service_id: UUID
    subscription_type_id: UUID
    expires_at: datetime


class PaymentHistoryResponse(BaseSchemaResponse):
    payment_id: UUID
    deposit_id: str
    amount: float  # serialized as float in JSON for client compatibility
    period_start: datetime
    period_end: datetime
