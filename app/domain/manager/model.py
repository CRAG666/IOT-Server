from typing import Optional
from uuid import UUID
from app.shared.base_domain.model import BaseTable
from app.domain.personal_data.model import DatosSensibles
from sqlmodel import Field, Relationship


class Gerente(BaseTable, table=True):
    __tablename__ = "gerente"

    datos_sensibles_id: UUID = Field(foreign_key="datos_sensibles.id", unique=True)
    activo: bool = Field(default=True)

    datos_sensibles: DatosSensibles = Relationship(back_populates="gerente")
    gerente_servicios: list["GerenteServicio"] = Relationship(back_populates="gerente")


class GerenteServicio(BaseTable, table=True):
    __tablename__ = "gerente_servicio"

    gerente_id: UUID = Field(foreign_key="gerente.id")
    servicio_id: UUID = Field(foreign_key="servicio.id")

    gerente: Gerente = Relationship(back_populates="gerente_servicios")
    servicio: "Servicio" = Relationship(back_populates="gerente_servicios")
    tickets_ecosistema: list["TicketEcosistema"] = Relationship(
        back_populates="gerente_servicio"
    )    