import base64
import json
import os
import secrets
import tempfile
from pathlib import Path

# Must be set before any app import so Settings() sees DEBUG=True and skips
# the production secret-key guard (tests intentionally use default secrets).
os.environ.setdefault("DEBUG", "true")
os.environ.setdefault("DATABASE_URL", "sqlite:///./test_run.db")

import fakeredis
import pytest
from copy import deepcopy
from datetime import datetime
from fastapi.testclient import TestClient
from sqlmodel import Session, SQLModel, create_engine

from app.main import app
from app.database import get_session
import app.database as database_module
import app.shared.middleware.auth.human as human_middleware
import app.shared.e2e.middleware as e2e_middleware_module
from app.domain.auth.controller import _get_session_repo
from app.shared.e2e.session import E2ESessionRepository
from app.shared.rate_limit import enforce_request_rate_limit, get_rate_limit_repository
from app.shared.authorization import enforcer as _enforcer_module
from app.shared.session.repository import SessionRepository
from app.shared.crypto import (
    aes_decrypt,
    aes_encrypt,
    derive_session_key,
    derive_temp_key,
    sha256_hex,
)
from app.database.model import (
    NonCriticalPersonalData,
    SensitiveData,
    Administrator,
    User,
    Manager,
)
from tests.e2e_client import E2ETestClient


# ── E2E login helper ──────────────────────────────────────────────────────────


def e2e_login(raw_client: TestClient, account: dict) -> tuple[str, bytes]:
    """Perform the full E2E handshake (v2: AES-GCM + HKDF + salt).

    Steps:
    1. GET /auth/challenge to obtain the user's password salt.
    2. Compute salted_hash = sha256(salt + sha256(password)).
    3. Derive temp_key = HKDF(ikm=(salted_hash + random_hex), salt=user_salt).
    4. Encrypt {"random2": ...} and POST /auth/login.
    5. Decrypt response → extract session_id + random3 → derive session_key.
    """
    from app.shared.crypto import generate_salt

    # Step 1: get the per-user salt from the server
    ch = raw_client.get(f"/api/v1/auth/challenge?email={account['email']}")
    assert ch.status_code == 200, f"Challenge failed: {ch.text}"
    salt: str = ch.json()["salt"]

    # Step 2: client computes salted password hash
    inner_sha256 = sha256_hex(account["password"])
    salted_hash = sha256_hex(salt + inner_sha256)

    random_hex = secrets.token_hex(16)
    random2 = secrets.token_hex(32)

    temp_key = derive_temp_key(salted_hash, random_hex, salt)
    inner = json.dumps({"random2": random2}).encode()
    ct, iv = aes_encrypt(inner, temp_key)

    resp = raw_client.post(
        "/api/v1/auth/login",
        json={
            "username": account["email"],
            "payload": base64.b64encode(ct).decode(),
            "random": random_hex,
            "iv": base64.b64encode(iv).decode(),
        },
    )
    assert resp.status_code == 200, f"E2E login failed ({resp.status_code}): {resp.text}"

    data = resp.json()
    resp_ct = base64.b64decode(data["payload"])
    resp_iv = base64.b64decode(data["iv"])
    decrypted = aes_decrypt(resp_ct, temp_key, resp_iv)
    inner_resp = json.loads(decrypted)

    session_id: str = inner_resp["session-id"]
    random3: str = inner_resp["random3"]
    session_key = derive_session_key(random2, random3)

    return session_id, session_key


# ── Core fixtures ─────────────────────────────────────────────────────────────


@pytest.fixture
def db():
    """Temporary SQLite database for one test, including all views."""
    from app.database.views import create_views

    temp_dir = Path(tempfile.mkdtemp())
    db_file = temp_dir / "test_db.sqlite"
    db_url = f"sqlite:///{db_file}"

    engine = create_engine(db_url, connect_args={"check_same_thread": False})
    SQLModel.metadata.create_all(engine)
    with Session(engine) as view_session:
        create_views(view_session)

    yield engine

    engine.dispose()
    if db_file.exists():
        db_file.unlink()
    temp_dir.rmdir()


@pytest.fixture
def session(db):
    with Session(db) as s:
        yield s


@pytest.fixture
def client(db):
    """Plain TestClient with a real E2E session repo (fakeredis) wired in.

    Use this for unauthenticated calls or as the base for E2ETestClient
    fixtures below.  All subsequent requests go through the full middleware
    stack with no bypass.
    """
    def get_session_override():
        with Session(db) as s:
            yield s

    app.dependency_overrides[get_session] = get_session_override

    original_db_engine = database_module.engine
    original_human_engine = human_middleware.engine
    database_module.engine = db
    human_middleware.engine = db

    # Wire a shared fakeredis into both the middleware and the login dependency.
    fake_redis = fakeredis.FakeAsyncValkey(decode_responses=True)
    e2e_repo = E2ESessionRepository("redis://localhost:6379/0")
    e2e_repo.client = fake_redis
    e2e_repo._external_client = True
    e2e_middleware_module._session_repo_override = e2e_repo
    app.dependency_overrides[_get_session_repo] = lambda: e2e_repo

    raw = TestClient(app, raise_server_exceptions=False)
    yield raw

    e2e_middleware_module._session_repo_override = None
    database_module.engine = original_db_engine
    human_middleware.engine = original_human_engine
    app.dependency_overrides.clear()


class _NoopSessionRepository:
    async def increment_rate_limit(self, key: str, window_seconds: int = 900) -> int:
        return 0

    async def get_rate_limit_ttl(self, key: str) -> int:
        return 0

    async def close(self) -> None:
        pass


@pytest.fixture(autouse=True)
def disable_rate_limit_dependency():
    """Disable rate limiting for every test."""
    app.dependency_overrides[enforce_request_rate_limit] = lambda: None
    app.dependency_overrides[get_rate_limit_repository] = _NoopSessionRepository
    yield
    app.dependency_overrides.pop(enforce_request_rate_limit, None)
    app.dependency_overrides.pop(get_rate_limit_repository, None)


# ── Account data fixtures ─────────────────────────────────────────────────────


@pytest.fixture(name="master_admin_account")
def master_admin_fixture(db):
    with Session(db) as s:
        nc = NonCriticalPersonalData(
            first_name="Admin", last_name="Master", second_last_name="Test",
            phone="+523312345678", address="123 Main St", city="Mexico City",
            state="Mexico", postal_code="06500", birth_date=datetime(1990, 1, 15),
            is_active=True)
        s.add(nc); s.flush()

        sd = SensitiveData(
            non_critical_data_id=nc.id, email="master_admin@test.com",
            password="MasterPassword123!",
            curp="ABCD123456HDFRRL09", rfc="ABCD123456AB0")
        s.add(sd); s.flush()

        adm = Administrator(sensitive_data_id=sd.id, is_master=True, is_active=True)
        s.add(adm); s.commit()

        return {
            "id": adm.id, "email": sd.email, "password": "MasterPassword123!",
            "sensitive_data_id": sd.id, "is_master": True, "account_type": "administrator",
        }


@pytest.fixture(name="regular_admin_account")
def regular_admin_fixture(db):
    with Session(db) as s:
        nc = NonCriticalPersonalData(
            first_name="Admin", last_name="Regular", second_last_name="Test",
            phone="+523312345679", address="456 Oak Ave", city="Mexico City",
            state="Mexico", postal_code="06501", birth_date=datetime(1992, 5, 20),
            is_active=True)
        s.add(nc); s.flush()

        sd = SensitiveData(
            non_critical_data_id=nc.id, email="regular_admin@test.com",
            password="RegularAdmin123!",
            curp="EFGH123456HDFRRL09", rfc="EFGH123456AB0")
        s.add(sd); s.flush()

        adm = Administrator(sensitive_data_id=sd.id, is_master=False, is_active=True)
        s.add(adm); s.commit()

        return {
            "id": adm.id, "email": sd.email, "password": "RegularAdmin123!",
            "sensitive_data_id": sd.id, "is_master": False, "account_type": "administrator",
        }


@pytest.fixture(name="user_account")
def user_fixture(db):
    with Session(db) as s:
        nc = NonCriticalPersonalData(
            first_name="John", last_name="Doe", second_last_name="Smith",
            phone="+523312345680", address="789 Pine St", city="Mexico City",
            state="Mexico", postal_code="06502", birth_date=datetime(1995, 3, 10),
            is_active=True)
        s.add(nc); s.flush()

        sd = SensitiveData(
            non_critical_data_id=nc.id, email="user@test.com",
            password="UserPassword123!",
            curp="IJKL123456HDFRRL09", rfc="IJKL123456AB0")
        s.add(sd); s.flush()

        u = User(sensitive_data_id=sd.id, is_active=True)
        s.add(u); s.commit()

        return {
            "id": u.id, "email": sd.email, "password": "UserPassword123!",
            "sensitive_data_id": sd.id, "is_master": False, "account_type": "user",
        }


@pytest.fixture(name="manager_account")
def manager_fixture(db):
    with Session(db) as s:
        nc = NonCriticalPersonalData(
            first_name="Jane", last_name="Manager", second_last_name="Test",
            phone="+523312345681", address="321 Elm St", city="Mexico City",
            state="Mexico", postal_code="06503", birth_date=datetime(1993, 8, 25),
            is_active=True)
        s.add(nc); s.flush()

        sd = SensitiveData(
            non_critical_data_id=nc.id, email="manager@test.com",
            password="ManagerPass123!",
            curp="MNOP123456HDFRRL09", rfc="MNOP123456AB0")
        s.add(sd); s.flush()

        mgr = Manager(sensitive_data_id=sd.id, is_active=True)
        s.add(mgr); s.commit()

        return {
            "id": mgr.id, "email": sd.email, "password": "ManagerPass123!",
            "sensitive_data_id": sd.id, "is_master": False, "account_type": "manager",
        }


@pytest.fixture(name="inactive_user_account")
def inactive_user_fixture(db):
    with Session(db) as s:
        nc = NonCriticalPersonalData(
            first_name="Inactive", last_name="User", second_last_name="Test",
            phone="+523312345682", address="999 Inactive St", city="Mexico City",
            state="Mexico", postal_code="06504", birth_date=datetime(1994, 12, 5),
            is_active=False)
        s.add(nc); s.flush()

        sd = SensitiveData(
            non_critical_data_id=nc.id, email="inactive@test.com",
            password="InactivePass123!",
            curp="QRST123456HDFRRL09", rfc="QRST123456AB0")
        s.add(sd); s.flush()

        u = User(sensitive_data_id=sd.id, is_active=False)
        s.add(u); s.commit()

        return {
            "id": u.id, "email": sd.email, "password": "InactivePass123!",
            "sensitive_data_id": sd.id, "is_master": False, "account_type": "user",
        }


# ── Authenticated E2ETestClient fixtures ──────────────────────────────────────


@pytest.fixture(name="prod_client")
def prod_client_fixture(client, monkeypatch):
    """TestClient with settings.DEBUG patched to False — simulates production mode.

    The hide_docs_in_production middleware checks settings.DEBUG at request time,
    so patching it here causes /docs, /redoc, /openapi.json to return 404.
    """
    from app.config import settings as _settings
    monkeypatch.setattr(_settings, "DEBUG", False)
    yield client


@pytest.fixture(name="master_admin_client")
def master_admin_client_fixture(client, master_admin_account):
    """E2ETestClient logged in as master administrator."""
    session_id, session_key = e2e_login(client, master_admin_account)
    return E2ETestClient(client, session_id, session_key, master_admin_account)


@pytest.fixture(name="regular_admin_client")
def regular_admin_client_fixture(client, regular_admin_account):
    """E2ETestClient logged in as regular (non-master) administrator."""
    session_id, session_key = e2e_login(client, regular_admin_account)
    return E2ETestClient(client, session_id, session_key, regular_admin_account)


@pytest.fixture(name="user_client")
def user_client_fixture(client, user_account):
    """E2ETestClient logged in as a regular user."""
    session_id, session_key = e2e_login(client, user_account)
    return E2ETestClient(client, session_id, session_key, user_account)


@pytest.fixture(name="manager_client")
def manager_client_fixture(client, manager_account):
    """E2ETestClient logged in as a manager."""
    session_id, session_key = e2e_login(client, manager_account)
    return E2ETestClient(client, session_id, session_key, manager_account)


# ── Shared test data helpers ──────────────────────────────────────────────────


def get_valid_personal_data() -> dict:
    return {
        "first_name": "Test",
        "last_name": "User",
        "second_last_name": "Name",
        "phone": "+523312345699",
        "address": "123 Test St",
        "city": "Mexico City",
        "state": "Mexico",
        "postal_code": "06500",
        "birth_date": datetime(1990, 6, 15).isoformat(),
        "email": "test@example.com",
        "password": "TestPass123!",
        "curp": "PEMJ900615HDFLRN07",
        "rfc": "PEMJ900615AB1",
    }


@pytest.fixture
def valid_personal_data():
    return deepcopy(get_valid_personal_data())


# ── Casbin policy fixtures ────────────────────────────────────────────────────


@pytest.fixture
def clean_policy():
    """Capture all Casbin policies before a test and restore them afterwards.

    Use this in any test that calls ``POST /policies`` or ``DELETE /policies``
    so the policy store is left clean for subsequent tests.
    """
    enforcer = _enforcer_module.get_enforcer()
    # Deep-copy: get_policy() returns a reference to the internal list,
    # so new rules added during the test would otherwise appear in 'saved'.
    saved = [list(r) for r in enforcer.get_policy()]
    yield enforcer
    # Restore: remove rules added by the test, re-add any that were removed.
    current = {tuple(r) for r in enforcer.get_policy()}
    original = {tuple(r) for r in saved}
    for rule in current - original:
        enforcer.remove_policy(*rule)
    for rule in original - current:
        enforcer.add_policy(*rule)
    enforcer.save_policy()
