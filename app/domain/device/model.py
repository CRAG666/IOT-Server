from sqlmodel import Field, Relationship
from app.shared.base_domain.model import BaseTable
from uuid import UUID

class Device(BaseTable, table=True):
    __tablename__ = "dispositivo"

    nombre: str = Field(alias="name")
    marca: str | None = Field(default=None, alias="brand")
    modelo: str | None = Field(default=None, alias="model")
    numero_serie: str | None = Field(default=None, unique=True, alias="serial_number")
    ip: str | None = None
    mac: str | None = Field(default=None, unique=True)
    activo: bool = Field(default=True, alias="is_active")

    dispositivo_servicios: list["DispositivoServicio"] = Relationship(
        back_populates="dispositivo"
    )


class DispositivoServicio(BaseTable, table=True):
    __tablename__ = "dispositivo_servicio"

    dispositivo_id: UUID = Field(foreign_key="dispositivo.id")
    servicio_id: UUID = Field(foreign_key="servicio.id")

    dispositivo: Device = Relationship(back_populates="dispositivo_servicios")
    servicio: "Servicio" = Relationship(back_populates="dispositivo_servicios")
