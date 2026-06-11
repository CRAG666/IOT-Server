"""Webhook CRUD endpoints."""

from uuid import UUID

from fastapi import APIRouter, Depends
from fastapi import status as http_status

from app.database import SessionDep
from app.domain.webhook.schemas import WebhookCreate, WebhookResponse
from app.domain.webhook.service import WebhookService
from app.shared.authorization.dependencies import CurrentAccountDep, require_write, require_read


class _Webhook:
    pass


webhook_router = APIRouter(prefix="/webhooks", tags=["Webhooks"])


@webhook_router.post(
    "/",
    status_code=http_status.HTTP_201_CREATED,
    response_model=WebhookResponse,
    dependencies=[require_write(_Webhook)],
)
def register_webhook(
    body: WebhookCreate,
    current_account: CurrentAccountDep,
    session: SessionDep,
) -> WebhookResponse:
    """Register a new webhook endpoint for the authenticated account."""
    event_types = body.validated_event_types()
    svc = WebhookService(session)
    endpoint = svc.register(current_account.account_id, str(body.url), event_types)
    return WebhookResponse.from_model(endpoint)


@webhook_router.get(
    "/",
    response_model=list[WebhookResponse],
    dependencies=[require_read(_Webhook)],
)
def list_webhooks(
    current_account: CurrentAccountDep,
    session: SessionDep,
) -> list[WebhookResponse]:
    """List webhook endpoints registered by the authenticated account."""
    svc = WebhookService(session)
    return [WebhookResponse.from_model(w) for w in svc.list_for_owner(current_account.account_id)]


@webhook_router.delete(
    "/{webhook_id}",
    status_code=http_status.HTTP_204_NO_CONTENT,
    dependencies=[require_write(_Webhook)],
)
def delete_webhook(
    webhook_id: UUID,
    current_account: CurrentAccountDep,
    session: SessionDep,
) -> None:
    WebhookService(session).delete(webhook_id, current_account.account_id)
