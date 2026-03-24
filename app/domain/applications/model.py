from typing import Optional
from uuid import UUID
from sqlmodel import Field, Relationship
from app.shared.base_domain.model import BaseTable

class Aplicacion(BaseTable, table=True):
    __tablename__ = "aplicacion"

    nombre: str
    version: str | None = None
    url: str | None = None
    descripcion: str | None = None
    administrador_id: UUID = Field(foreign_key="administrador.id")
    activo: bool = Field(default=True)

    registrada_por: "Administrador" = Relationship(
        back_populates="aplicaciones_registradas"
    )
    aplicacion_servicios: list["AplicacionServicio"] = Relationship(
        back_populates="aplicacion"
    )


class AplicacionServicio(BaseTable, table=True):
    __tablename__ = "aplicacion_servicio"

    aplicacion_id: UUID = Field(foreign_key="aplicacion.id")
    servicio_id: UUID = Field(foreign_key="servicio.id")

    aplicacion: Aplicacion = Relationship(back_populates="aplicacion_servicios")
    servicio: "Servicio" = Relationship(back_populates="aplicacion_servicios")

