from datetime import datetime
from typing import Optional
from sqlmodel import Field, Relationship
from app.shared.base_domain.model import BaseTable
from uuid import UUID

class DatosPersonalesNoCriticos(BaseTable, table=True):
    __tablename__ = "datos_personales_no_criticos"
    
    nombre: str
    apellido_paterno: str
    apellido_materno: str | None = None
    telefono: str | None = None
    direccion: str | None = None
    ciudad: str | None = None
    estado: str | None = None
    codigo_postal: str | None = None
    fecha_nacimiento: datetime | None = None
    activo: bool = Field(default=True)

    datos_sensibles: Optional["DatosSensibles"] = Relationship(
        back_populates="datos_no_criticos"
    )


class DatosSensibles(BaseTable, table=True):
    __tablename__ = "datos_sensibles"

    datos_no_criticos_id: UUID = Field(
        foreign_key="datos_personales_no_criticos.id", unique=True
    )
    email: str = Field(unique=True)
    password_hash: str
    curp: str | None = Field(default=None, unique=True)
    rfc: str | None = Field(default=None, unique=True)

    datos_no_criticos: DatosPersonalesNoCriticos = Relationship(
        back_populates="datos_sensibles"
    )
    administrador: Optional["Administrador"] = Relationship(
        back_populates="datos_sensibles"
    )
    gerente: Optional["Gerente"] = Relationship(back_populates="datos_sensibles")
    usuario: Optional["Usuario"] = Relationship(back_populates="datos_sensibles")

