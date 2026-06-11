import re
import uuid
from contextlib import asynccontextmanager

from fastapi import FastAPI, Request, Response
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse

from app.config import settings
from app.database import create_db_and_tables
from app.shared.logging import init_logging
from app.domain.auth.controller import auth_router
from app.domain.device.controller import device_router
from app.domain.user.controller import user_router
from app.domain.administrator.controller import administrator_router
from app.domain.application.controller import application_router
from app.domain.role.controller import role_router
from app.domain.service.controller import service_router
from app.domain.manager.controller import manager_router
from app.domain.tickets.controller import ecosystem_ticket_router, service_ticket_router
from app.domain.payment.controller import payment_router
from app.domain.telemetry.controller import telemetry_router
from app.domain.onboarding.controller import onboarding_router
from app.domain.webhook.controller import webhook_router
from app.domain.policy.controller import policy_router
from app.shared.e2e.middleware import E2EMiddleware
from app.shared.middleware.tenant import TenantContextMiddleware
from app.services.mqtt_bridge import run_bridge
from app.shared.mongodb import close_mongo_client, get_mongo_db
from app.domain.telemetry.repository import TelemetryRepository

_UUID_RE = re.compile(
    r"^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$",
    re.IGNORECASE,
)


@asynccontextmanager
async def lifespan(_: FastAPI):
    import asyncio

    import logging as _logging

    init_logging(debug=settings.DEBUG)
    create_db_and_tables()
    try:
        await TelemetryRepository(get_mongo_db()).ensure_indexes()
    except Exception:  # MongoDB may be unavailable in test / dev environments
        _logging.getLogger(__name__).warning("MongoDB unavailable — telemetry indexes skipped")

    mqtt_task: asyncio.Task | None = None
    if settings.MQTT_ENABLED:
        mqtt_task = asyncio.create_task(run_bridge(), name="mqtt-bridge")

    yield

    if mqtt_task is not None:
        mqtt_task.cancel()
        try:
            await mqtt_task
        except asyncio.CancelledError:
            pass

    await close_mongo_client()


app = FastAPI(
    title=settings.APP_NAME,
    version="0.1.0",
    debug=settings.DEBUG,
    lifespan=lifespan,
    # SEC-013: hide API schema from unauthenticated callers in production
    docs_url="/docs" if settings.DEBUG else None,
    redoc_url="/redoc" if settings.DEBUG else None,
    openapi_url="/openapi.json" if settings.DEBUG else None,
)

# SEC-009: CORS allowlist.  In DEBUG mode a wildcard is still accepted because
# combining allow_credentials with allow_origins=["*"] is rejected by browsers anyway,
# but in production an explicit allowlist is required.
_cors_origins = settings.CORS_ORIGINS
_allow_credentials = settings.CORS_ORIGINS != ["*"]

app.add_middleware(
    CORSMiddleware,
    allow_origins=_cors_origins,
    allow_credentials=_allow_credentials,
    allow_methods=["*"],
    allow_headers=["*"],
)

app.add_middleware(E2EMiddleware)
app.add_middleware(TenantContextMiddleware)


_DOCS_PATHS = {"/docs", "/redoc", "/openapi.json"}


@app.middleware("http")
async def hide_docs_in_production(request: Request, call_next) -> Response:
    """SEC-013: block API schema endpoints when not in debug mode."""
    if not settings.DEBUG and request.url.path in _DOCS_PATHS:
        return JSONResponse({"detail": "Not found"}, status_code=404)
    return await call_next(request)


@app.middleware("http")
async def security_headers_middleware(request: Request, call_next) -> Response:
    """SEC-010: add defensive security headers to every response."""
    response = await call_next(request)
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["X-Frame-Options"] = "DENY"
    response.headers["Referrer-Policy"] = "strict-origin-when-cross-origin"
    return response


@app.middleware("http")
async def request_id_middleware(request: Request, call_next) -> Response:
    """SEC-011: sanitize X-Request-ID — only accept well-formed UUIDs."""
    raw_rid = request.headers.get("X-Request-ID", "")
    request_id = raw_rid if _UUID_RE.match(raw_rid) else str(uuid.uuid4())
    request.state.request_id = request_id
    response = await call_next(request)
    response.headers["X-Request-ID"] = request_id
    return response


api_version_v1_prefix = "/api/v1"


@app.get("/health", tags=["Ops"], include_in_schema=True)
def health() -> JSONResponse:
    return JSONResponse({"status": "ok"})


@app.get("/ready", tags=["Ops"], include_in_schema=True)
def ready() -> JSONResponse:
    return JSONResponse({"status": "ready"})


app.include_router(auth_router, prefix=api_version_v1_prefix)

app.include_router(device_router, prefix=api_version_v1_prefix)
app.include_router(administrator_router, prefix=api_version_v1_prefix)
app.include_router(user_router, prefix=api_version_v1_prefix)
app.include_router(manager_router, prefix=api_version_v1_prefix)
app.include_router(application_router, prefix=api_version_v1_prefix)
app.include_router(role_router, prefix=api_version_v1_prefix)
app.include_router(service_router, prefix=api_version_v1_prefix)
app.include_router(service_ticket_router, prefix=api_version_v1_prefix)
app.include_router(ecosystem_ticket_router, prefix=api_version_v1_prefix)
app.include_router(payment_router, prefix=api_version_v1_prefix)
app.include_router(telemetry_router, prefix=api_version_v1_prefix)
app.include_router(onboarding_router, prefix=api_version_v1_prefix)
app.include_router(webhook_router, prefix=api_version_v1_prefix)
app.include_router(policy_router, prefix=api_version_v1_prefix)
