from contextlib import asynccontextmanager
from fastapi import FastAPI
from app.config import settings
from app.database import create_db_and_tables
from app.shared.middleware.cryptography import (
    DecryptionMiddleware,
    EncryptionMiddleware,
)

# Importar todos los modelos para que SQLModel pueda crear las tablas



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

#app.add_middleware(DecryptionMiddleware)  # Comentar si se estan en desarrollo
#app.add_middleware(EncryptionMiddleware)  # Comentar si se estan en desarrollo

#app.include_router(device_router, prefix="/api/v1")
