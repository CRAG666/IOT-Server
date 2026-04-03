"""
Script para crear un administrador master inicial.
Uso: uv run python seed_admin.py
"""
from sqlmodel import Session, select

from app.database import engine
from app.database.model import Administrator, NonCriticalPersonalData, SensitiveData
from app.domain.auth.security import get_password_hash

EMAIL = "admin@iot.com"
PASSWORD = "Admin1234!"
FIRST_NAME = "Admin"
LAST_NAME = "Master"


def create_initial_admin() -> None:
    with Session(engine) as session:
        # Verificar si ya existe
        existing = session.exec(
            select(SensitiveData).where(SensitiveData.email == EMAIL)
        ).first()
        if existing:
            print(f"Ya existe un usuario con el email '{EMAIL}', no se creó nada.")
            return

        personal_data = NonCriticalPersonalData(
            first_name=FIRST_NAME,
            last_name=LAST_NAME,
        )
        session.add(personal_data)
        session.flush()  # obtener el id antes del commit

        sensitive_data = SensitiveData(
            non_critical_data_id=personal_data.id,
            email=EMAIL,
            password_hash=get_password_hash(PASSWORD),
        )
        session.add(sensitive_data)
        session.flush()

        admin = Administrator(
            sensitive_data_id=sensitive_data.id,
            is_master=True,
        )
        session.add(admin)
        session.commit()

        print("Admin master creado exitosamente:")
        print(f"  Email:    {EMAIL}")
        print(f"  Password: {PASSWORD}")


if __name__ == "__main__":
    create_initial_admin()
