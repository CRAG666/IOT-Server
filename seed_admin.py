"""Idempotent bootstrap script — creates the first master administrator.

Usage:
    uv run python seed_admin.py

Environment:
    ADMIN_EMAIL     — email for master admin (default: admin@iot.com)
    ADMIN_PASSWORD  — password (default: Admin1234!)
    ADMIN_FIRST     — first name (default: Admin)
    ADMIN_LAST      — last name  (default: Master)
"""

import os
from sqlmodel import Session, select

from app.database import engine, create_db_and_tables
from app.database.model import Administrator, NonCriticalPersonalData, SensitiveData
from app.shared.crypto import generate_salt, hash_password


EMAIL = os.getenv("ADMIN_EMAIL", "admin@iot.com")
PASSWORD = os.getenv("ADMIN_PASSWORD", "Admin1234!")
FIRST_NAME = os.getenv("ADMIN_FIRST", "Admin")
LAST_NAME = os.getenv("ADMIN_LAST", "Master")


def create_initial_admin() -> None:
    create_db_and_tables()

    with Session(engine) as session:
        existing = session.exec(
            select(SensitiveData).where(SensitiveData.email == EMAIL)
        ).first()

        if existing:
            print(f"[skip] Master admin already exists: {EMAIL}")
            return

        personal_data = NonCriticalPersonalData(
            first_name=FIRST_NAME,
            last_name=LAST_NAME,
        )
        session.add(personal_data)
        session.flush()

        salt = generate_salt()
        sensitive_data = SensitiveData(
            non_critical_data_id=personal_data.id,
            email=EMAIL,
            password_hash=hash_password(PASSWORD, salt),
            password_salt=salt,
        )
        session.add(sensitive_data)
        session.flush()

        admin = Administrator(
            sensitive_data_id=sensitive_data.id,
            is_master=True,
            is_active=True,
        )
        session.add(admin)
        session.commit()

        print("[ok] Master admin created:")
        print(f"  Email:    {EMAIL}")
        print(f"  Password: {PASSWORD}")
        print("  Change the password immediately after first login!")


if __name__ == "__main__":
    create_initial_admin()
