from sqlmodel import Field, Relationship
from app.shared.base_domain.model import BaseTable
from uuid import UUID
from app.domain.personal_data.model import DatosSensibles

class User(BaseTable, table=True):
    __tablename__ = "usuario"

    datos_sensibles_id: UUID = Field(foreign_key="datos_sensibles.id", unique=True)
    activo: bool = Field(default=True)

    datos_sensibles: DatosSensibles = Relationship(back_populates="usuario")
    usuario_roles: list["UsuarioRol"] = Relationship(back_populates="usuario")
