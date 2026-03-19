from datetime import datetime, timezone
from typing import Optional
from uuid import UUID

from sqlmodel import Field, Relationship


class Servicio(BaseTable, table=True):
    __tablename__ = "service"

    nombre: str = Field(unique=True)
    descripcion: str | None = None
    administrador_id: UUID = Field(foreign_key="administrador.id")
    activo: bool = Field(default=True)

    registrado_por: Administrador = Relationship(back_populates="servicios_registrados")
    gerente_servicios: list["GerenteServicio"] = Relationship(back_populates="service")
    aplicacion_servicios: list["AplicacionServicio"] = Relationship(
        back_populates="service"
    )
    dispositivo_servicios: list["DispositivoServicio"] = Relationship(
        back_populates="service"
    )
    roles: list["Rol"] = Relationship(back_populates="service")
    tickets_servicio: list["TicketServicio"] = Relationship(back_populates="service")

