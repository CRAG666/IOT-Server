from typing import Optional
from uuid import UUID
from sqlmodel import Field, Relationship
from app.shared.base_domain.model import BaseTable


class Rol(BaseTable, table=True):
    __tablename__ = "rol"

    nombre: str
    descripcion: str | None = None
    servicio_id: UUID = Field(foreign_key="servicio.id")
    activo: bool = Field(default=True)

    servicio: "Servicio" = Relationship(back_populates="roles")
    permiso: Optional["PermisoRol"] = Relationship(back_populates="rol")
    usuario_roles: list["UsuarioRol"] = Relationship(back_populates="rol")


class PermisoRol(BaseTable, table=True):
    __tablename__ = "permiso_rol"

    rol_id: UUID = Field(foreign_key="rol.id", unique=True)
    puede_leer: bool = Field(default=False)
    puede_escribir: bool = Field(default=False)
    puede_eliminar: bool = Field(default=False)
    puede_administrar: bool = Field(default=False)

    rol: Rol = Relationship(back_populates="permiso")


class UsuarioRol(BaseTable, table=True):
    __tablename__ = "usuario_rol"

    usuario_id: UUID = Field(foreign_key="usuario.id")
    rol_id: UUID = Field(foreign_key="rol.id")

    usuario: "Usuario" = Relationship(back_populates="usuario_roles")
    rol: Rol = Relationship(back_populates="usuario_roles")
    tickets_servicio: list["TicketServicio"] = Relationship(
        back_populates="usuario_rol"
    )
