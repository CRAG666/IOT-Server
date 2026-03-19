from sqlmodel import Field, Relationship
from app.shared.base_domain.model import BaseTable
from uuid import UUID
from app.domain.personal_data.model import DatosSensibles   

class Admin(BaseTable, table=True):
    __tablename__ = "administrador"

    datos_sensibles_id: UUID = Field(foreign_key="datos_sensibles.id", unique=True)
    master: bool = Field(default=False)
    activo: bool = Field(default=True)

    datos_sensibles: DatosSensibles = Relationship(back_populates="administrador")
    servicios_registrados: list["Servicio"] = Relationship(
        back_populates="registrado_por"
    )
    aplicaciones_registradas: list["Aplicacion"] = Relationship(
        back_populates="registrada_por"
    )
