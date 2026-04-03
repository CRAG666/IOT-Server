from contextlib import asynccontextmanager

from fastapi import FastAPI

from app.config import settings
from app.database import create_db_and_tables
from app.domain.auth.controller import auth_router
from app.domain.device.controller import device_router
from app.domain.user.controller import user_router
from app.domain.administrator.controller import administrator_router
from app.domain.manager.controller import manager_router
from app.shared.middleware.auth.human import Human


@asynccontextmanager
async def lifespan(_: FastAPI):
    create_db_and_tables()
    yield


app = FastAPI(
    title=settings.APP_NAME,
    version="0.1.0",
    debug=settings.DEBUG,
    lifespan=lifespan,
)

app.add_middleware(Human)

api_version_v1_prefix = "/api/v1"

app.include_router(auth_router, prefix=api_version_v1_prefix)
app.include_router(device_router, prefix=api_version_v1_prefix)
app.include_router(administrator_router, prefix=api_version_v1_prefix)
app.include_router(user_router, prefix=api_version_v1_prefix)
app.include_router(manager_router, prefix=api_version_v1_prefix)

