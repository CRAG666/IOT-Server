#!/usr/bin/env python
"""Lightweight dev/test server for HTTP E2E tests.

Requires no external services — uses SQLite + fakeredis in-process.

Seeds on first start (idempotent on repeat starts):
  • DB tables via SQLModel.metadata.create_all
  • master_admin  (master_admin@test.com / MasterPassword123!)
  • ticket_status rows 1-4
  • Casbin policy rules from policy.csv

Usage:
    uv run python scripts/dev_server.py [--port PORT] [--host HOST]
    uv run python scripts/dev_server.py --clean   # wipe http_test.db first
"""

import os
import sys
from pathlib import Path

# Add repo root to sys.path so `app` is importable when script is run directly.
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

# Must be set before any app import — Settings() is evaluated at module level.
os.environ.setdefault("DATABASE_URL", "sqlite:///./http_test.db")
os.environ.setdefault("DEBUG", "true")
# Fail fast when MongoDB is unavailable so startup doesn't block for 30 s.
os.environ.setdefault("MONGODB_URL", "mongodb://localhost:27017/?serverSelectionTimeoutMS=500")

import argparse
from datetime import datetime

import fakeredis
import uvicorn
from sqlalchemy import text
from sqlmodel import Session

from app.main import app
from app.database import create_db_and_tables, engine
from app.config import settings
from app.domain.auth.controller import _get_session_repo
from app.shared.e2e.session import E2ESessionRepository
from app.shared.rate_limit import enforce_request_rate_limit, get_rate_limit_repository
from app.shared.authorization import enforcer as _enforcer_module
from app.database.model import (
    Administrator,
    NonCriticalPersonalData,
    SensitiveData,
    TicketStatus,
)
import app.shared.e2e.middleware as _e2e_middleware


class _NoopSessionRepository:
    async def increment_rate_limit(self, key: str, window_seconds: int = 900) -> int:
        return 0

    async def get_rate_limit_ttl(self, key: str) -> int:
        return 0

    async def close(self) -> None:
        pass


def _wire_fakeredis() -> None:
    fake_redis = fakeredis.FakeAsyncValkey(decode_responses=True)
    repo = E2ESessionRepository(settings.VALKEY_URL)
    repo.client = fake_redis
    repo._external_client = True
    _e2e_middleware._session_repo_override = repo
    app.dependency_overrides[_get_session_repo] = lambda: repo


def _disable_rate_limit() -> None:
    app.dependency_overrides[enforce_request_rate_limit] = lambda: None
    app.dependency_overrides[get_rate_limit_repository] = _NoopSessionRepository


def _seed() -> None:
    with Session(engine) as session:
        existing = session.exec(
            text("SELECT COUNT(*) FROM administrator WHERE is_master = 1")
        ).scalar()
        if existing and existing > 0:
            print("  • master_admin already seeded, skipping.")
        else:
            nc = NonCriticalPersonalData(
                first_name="Admin", last_name="Master", second_last_name="Test",
                phone="+523312345678", address="123 Main St", city="Mexico City",
                state="Mexico", postal_code="06500",
                birth_date=datetime(1990, 1, 15), is_active=True)
            session.add(nc)
            session.flush()

            sd = SensitiveData(
                non_critical_data_id=nc.id,
                email="master_admin@test.com",
                password="MasterPassword123!",
                curp="ABCD123456HDFRRL09",
                rfc="ABCD123456AB0")
            session.add(sd)
            session.flush()

            adm = Administrator(sensitive_data_id=sd.id, is_master=True, is_active=True)
            session.add(adm)
            session.commit()
            print("  ✓ master_admin seeded  (master_admin@test.com / MasterPassword123!)")

    with Session(engine) as session:
        statuses = [
            (1, "Open",        "Ticket is open and awaiting assignment"),
            (2, "In Progress", "Ticket is being worked on"),
            (3, "Resolved",    "Ticket has been resolved"),
            (4, "Closed",      "Ticket is closed"),
        ]
        added = 0
        for id_, name, description in statuses:
            if not session.get(TicketStatus, id_):
                session.add(TicketStatus(id=id_, name=name, description=description))
                added += 1
        if added:
            session.commit()
            print(f"  ✓ ticket_status seeded ({added} rows)")
        else:
            print("  • ticket_status already seeded, skipping.")


def main() -> None:
    parser = argparse.ArgumentParser(description="IoTmx dev/test server (SQLite + fakeredis)")
    parser.add_argument("--port", type=int, default=8000)
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--clean", action="store_true",
                        help="Delete http_test.db before starting")
    args = parser.parse_args()

    db_url = settings.DATABASE_URL
    if args.clean and db_url.startswith("sqlite:///"):
        db_path = Path(db_url.replace("sqlite:///", "", 1))
        if db_path.exists():
            db_path.unlink()
            print(f"  • Removed existing database: {db_path}")

    print(f"\nIoTmx dev server")
    print(f"  DB  : {settings.DATABASE_URL}")
    print(f"  URL : http://{args.host}:{args.port}")
    print()

    _wire_fakeredis()
    _disable_rate_limit()

    create_db_and_tables()
    _enforcer_module.reset_enforcer()

    print("Seeding database...")
    _seed()
    print()

    uvicorn.run(app, host=args.host, port=args.port, log_level="warning")


if __name__ == "__main__":
    main()
