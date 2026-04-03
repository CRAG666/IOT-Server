import pytest
import tempfile
import os
from datetime import datetime
from fastapi.testclient import TestClient
from sqlmodel import Session, SQLModel, create_engine

from app.main import app
from app.config import settings
from app.database import SessionDep, get_session
import app.database as database_module
import app.shared.middleware.auth.human as human_middleware
from app.database.model import (
    NonCriticalPersonalData,
    SensitiveData,
    Administrator,
    User,
    Manager,
)
from app.domain.auth.security import get_password_hash


@pytest.fixture(scope="session", autouse=True)
def strong_jwt_secret_for_tests():
    """Use a >=32-byte HMAC key in tests to avoid JWT security warnings."""
    original_secret = settings.SECRET_KEY
    settings.SECRET_KEY = "tests-secret-key-at-least-32-bytes-long-12345"
    yield
    settings.SECRET_KEY = original_secret


@pytest.fixture
def db():
    """Create a temporary SQLite database file for testing."""
    # Create a temporary directory and file
    temp_dir = tempfile.mkdtemp()
    db_file = os.path.join(temp_dir, "test_db.sqlite")
    db_url = f"sqlite:///{db_file}"
    
    # Create engine and tables
    engine = create_engine(db_url, connect_args={"check_same_thread": False})
    SQLModel.metadata.create_all(engine)
    
    yield engine
    
    # Cleanup
    engine.dispose()
    if os.path.exists(db_file):
        os.remove(db_file)
    os.rmdir(temp_dir)


@pytest.fixture
def session(db):
    """Create a session for each test."""
    with Session(db) as session:
        yield session


@pytest.fixture
def client(db):
    """Create a test client that uses a new session for each request."""
    def get_session_override():
        with Session(db) as session:
            yield session

    app.dependency_overrides[get_session] = get_session_override

    # Ensure middleware token resolution also queries the test database.
    original_database_engine = database_module.engine
    original_human_engine = human_middleware.engine
    database_module.engine = db
    human_middleware.engine = db

    client = TestClient(app, raise_server_exceptions=False)
    yield client

    database_module.engine = original_database_engine
    human_middleware.engine = original_human_engine
    app.dependency_overrides.clear()


@pytest.fixture(name="master_admin_account")
def master_admin_fixture(db):
    """Create a master administrator account for testing."""
    with Session(db) as session:
        # Create non-critical personal data
        non_critical_data = NonCriticalPersonalData(
            first_name="Admin",
            last_name="Master",
            second_last_name="Test",
            phone="+523312345678",
            address="123 Main St",
            city="Mexico City",
            state="Mexico",
            postal_code="06500",
            birth_date=datetime(1990, 1, 15),
            is_active=True,
        )
        session.add(non_critical_data)
        session.flush()

        # Create sensitive data
        sensitive_data = SensitiveData(
            non_critical_data_id=non_critical_data.id,
            email="master_admin@test.com",
            password_hash=get_password_hash("MasterPassword123!"),
            curp="ABCD123456HDFRRL09",
            rfc="ABCD123456AB0",
        )
        session.add(sensitive_data)
        session.flush()

        # Create administrator
        administrator = Administrator(
            sensitive_data_id=sensitive_data.id,
            is_master=True,
            is_active=True,
        )
        session.add(administrator)
        session.commit()

        return {
            "id": administrator.id,
            "email": sensitive_data.email,
            "password": "MasterPassword123!",
            "sensitive_data_id": sensitive_data.id,
            "is_master": True,
            "account_type": "administrator",
        }


@pytest.fixture(name="regular_admin_account")
def regular_admin_fixture(db):
    """Create a regular (non-master) administrator account for testing."""
    with Session(db) as session:
        non_critical_data = NonCriticalPersonalData(
            first_name="Admin",
            last_name="Regular",
            second_last_name="Test",
            phone="+523312345679",
            address="456 Oak Ave",
            city="Mexico City",
            state="Mexico",
            postal_code="06501",
            birth_date=datetime(1992, 5, 20),
            is_active=True,
        )
        session.add(non_critical_data)
        session.flush()

        sensitive_data = SensitiveData(
            non_critical_data_id=non_critical_data.id,
            email="regular_admin@test.com",
            password_hash=get_password_hash("RegularAdmin123!"),
            curp="EFGH123456HDFRRL09",
            rfc="EFGH123456AB0",
        )
        session.add(sensitive_data)
        session.flush()

        administrator = Administrator(
            sensitive_data_id=sensitive_data.id,
            is_master=False,
            is_active=True,
        )
        session.add(administrator)
        session.commit()

        return {
            "id": administrator.id,
            "email": sensitive_data.email,
            "password": "RegularAdmin123!",
            "sensitive_data_id": sensitive_data.id,
            "is_master": False,
            "account_type": "administrator",
        }


@pytest.fixture(name="user_account")
def user_fixture(db):
    """Create a regular user account for testing."""
    with Session(db) as session:
        non_critical_data = NonCriticalPersonalData(
            first_name="John",
            last_name="Doe",
            second_last_name="Smith",
            phone="+523312345680",
            address="789 Pine St",
            city="Mexico City",
            state="Mexico",
            postal_code="06502",
            birth_date=datetime(1995, 3, 10),
            is_active=True,
        )
        session.add(non_critical_data)
        session.flush()

        sensitive_data = SensitiveData(
            non_critical_data_id=non_critical_data.id,
            email="user@test.com",
            password_hash=get_password_hash("UserPassword123!"),
            curp="IJKL123456HDFRRL09",
            rfc="IJKL123456AB0",
        )
        session.add(sensitive_data)
        session.flush()

        user = User(
            sensitive_data_id=sensitive_data.id,
            is_active=True,
        )
        session.add(user)
        session.commit()

        return {
            "id": user.id,
            "email": sensitive_data.email,
            "password": "UserPassword123!",
            "sensitive_data_id": sensitive_data.id,
            "is_master": False,
            "account_type": "user",
        }


@pytest.fixture(name="manager_account")
def manager_fixture(db):
    """Create a manager account for testing."""
    with Session(db) as session:
        non_critical_data = NonCriticalPersonalData(
            first_name="Jane",
            last_name="Manager",
            second_last_name="Test",
            phone="+523312345681",
            address="321 Elm St",
            city="Mexico City",
            state="Mexico",
            postal_code="06503",
            birth_date=datetime(1993, 8, 25),
            is_active=True,
        )
        session.add(non_critical_data)
        session.flush()

        sensitive_data = SensitiveData(
            non_critical_data_id=non_critical_data.id,
            email="manager@test.com",
            password_hash=get_password_hash("ManagerPass123!"),
            curp="MNOP123456HDFRRL09",
            rfc="MNOP123456AB0",
        )
        session.add(sensitive_data)
        session.flush()

        manager = Manager(
            sensitive_data_id=sensitive_data.id,
            is_active=True,
        )
        session.add(manager)
        session.commit()

        return {
            "id": manager.id,
            "email": sensitive_data.email,
            "password": "ManagerPass123!",
            "sensitive_data_id": sensitive_data.id,
            "is_master": False,
            "account_type": "manager",
        }


@pytest.fixture(name="inactive_user_account")
def inactive_user_fixture(db):
    """Create an inactive user account for testing."""
    with Session(db) as session:
        non_critical_data = NonCriticalPersonalData(
            first_name="Inactive",
            last_name="User",
            second_last_name="Test",
            phone="+523312345682",
            address="999 Inactive St",
            city="Mexico City",
            state="Mexico",
            postal_code="06504",
            birth_date=datetime(1994, 12, 5),
            is_active=False,
        )
        session.add(non_critical_data)
        session.flush()

        sensitive_data = SensitiveData(
            non_critical_data_id=non_critical_data.id,
            email="inactive@test.com",
            password_hash=get_password_hash("InactivePass123!"),
            curp="QRST123456HDFRRL09",
            rfc="QRST123456AB0",
        )
        session.add(sensitive_data)
        session.flush()

        user = User(
            sensitive_data_id=sensitive_data.id,
            is_active=False,
        )
        session.add(user)
        session.commit()

        return {
            "id": user.id,
            "email": sensitive_data.email,
            "password": "InactivePass123!",
            "sensitive_data_id": sensitive_data.id,
            "is_master": False,
            "account_type": "user",
        }


def get_valid_personal_data() -> dict:
    """Return valid personal data for creating new accounts."""
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
        "password_hash": "TestPass123!",
        "curp": "ABCD111111HDFRRL09",
        "rfc": "ABCD111111AB0",
    }
