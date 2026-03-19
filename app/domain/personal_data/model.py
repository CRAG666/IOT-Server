from typing import Optional
from sqlmodel import Field, Relationship
from app.shared.base_domain.model import BaseTable
from uuid import UUID

class DatosPersonalesNoCriticos(BaseTable, table=True):
    __tablename__ = "datos_personales_no_criticos"
    
    id: str
    username: str
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
    nombre:str| None = Field(default=None, unique=True)
    direccion: str| None = Field(default=None, unique=True)
    fechacreacion: str| None = Field(default=None, unique=True)
    ultimamodificacion: str| None = Field(default=None, unique=True)
    quienmodifico: str | None = Field(default=None, unique=True)

    datos_no_criticos: DatosPersonalesNoCriticos = Relationship(
        back_populates="datos_sensibles"
    )
    administrador: Optional["Admin"] = Relationship(
        back_populates="datos_sensibles"
    )
    gerente: Optional["Manager"] = Relationship(back_populates="datos_sensibles")
    usuario: Optional["User"] = Relationship(back_populates="datos_sensibles")

