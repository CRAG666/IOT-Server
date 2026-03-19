from typing import Optional
from uuid import UUID
from sqlmodel import Field, Relationship
from app.shared.base_domain.model import BaseTable
from app.domain.admin.model import Administrador

class Aplicacion(BaseTable, table=True):
    __tablename__ = "app"

    nombre: str
    version: str | None = None
    url: str | None = None
    descripcion: str | None = None
    administrador_id: UUID = Field(foreign_key="administrador.id")
    activo: bool = Field(default=True)

    registrada_por: Administrador = Relationship(
        back_populates="aplicaciones_registradas"
    )
    aplicacion_servicios: list["AplicacionServicio"] = Relationship(
        back_populates="app"
    )


class AplicacionServicio(BaseTable, table=True):
    __tablename__ = "app_service"

    aplicacion_id: UUID = Field(foreign_key="app.id")
    servicio_id: UUID = Field(foreign_key="service.id")

    aplicacion: Aplicacion = Relationship(back_populates="app_service")
    servicio: Servicio = Relationship(back_populates="app_service")

