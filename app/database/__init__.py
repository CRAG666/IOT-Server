from typing import Annotated, Generator
from fastapi import Depends
from sqlmodel import Session, SQLModel, create_engine
from app.config import settings
from app.database.views import create_views
import app.domain.webhook.models  # noqa: F401 — registers WebhookEndpoint in SQLModel metadata

# check_same_thread is a SQLite-only arg; PostgreSQL needs pool settings instead.
_is_sqlite = settings.DATABASE_URL.startswith("sqlite")
_engine_kwargs = (
    {"connect_args": {"check_same_thread": False}}
    if _is_sqlite
    else {"pool_size": 10, "max_overflow": 20, "pool_pre_ping": True}
)

engine = create_engine(settings.DATABASE_URL, echo=settings.DEBUG, **_engine_kwargs)


def create_db_and_tables():
    SQLModel.metadata.create_all(engine)
    with Session(engine) as session:
        create_views(session)


def get_session() -> Generator[Session, None, None]:
    with Session(engine) as session:
        yield session


SessionDep = Annotated[Session, Depends(get_session)]
