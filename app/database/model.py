from typing import Optional
from uuid import UUID
from app.shared.base_domain.model import BaseTable
from datetime import datetime
from sqlmodel import Field, Relationship, SQLModel
from app.database.format import UserPlainAttribute

class NonCriticalPersonalData(BaseTable, table=True):
    __tablename__ = "non_critical_personal_data"

    first_name: str
    last_name: str
    second_last_name: str | None = None
    phone: str | None = None
    address: str | None = None
    city: str | None = None
    state: str | None = None
    postal_code: str | None = None
    birth_date: datetime | None = None
    is_active: bool = Field(default=True)

    sensitive_data: Optional["SensitiveData"] = Relationship(
        back_populates="non_critical_data"
    )


class SensitiveData(BaseTable, table=True):
    __tablename__ = "sensitive_data"

    non_critical_data_id: UUID = Field(
        foreign_key="non_critical_personal_data.id", unique=True
    )
    email: str = Field(unique=True)
    password_hash: str
    curp: str | None = Field(default=None, unique=True)
    rfc: str | None = Field(default=None, unique=True)

    non_critical_data: NonCriticalPersonalData = Relationship(
        back_populates="sensitive_data"
    )
    administrator: Optional["Administrator"] = Relationship(
        back_populates="sensitive_data"
    )
    manager: Optional["Manager"] = Relationship(back_populates="sensitive_data")
    user: Optional["User"] = Relationship(back_populates="sensitive_data")


class Administrator(BaseTable, UserPlainAttribute, table=True):
    __tablename__ = "administrator"

    sensitive_data_id: UUID = Field(foreign_key="sensitive_data.id", unique=True)
    is_master: bool = Field(default=False)
    is_active: bool = Field(default=True)

    sensitive_data: SensitiveData = Relationship(back_populates="administrator")
    manager_services: list["Service"] = Relationship(
        back_populates="registered_by"
    )
    registered_applications: list["Application"] = Relationship(
        back_populates="registered_by"
    )


class Manager(BaseTable, UserPlainAttribute, table=True):
    __tablename__ = "manager"

    sensitive_data_id: UUID = Field(foreign_key="sensitive_data.id", unique=True)
    is_active: bool = Field(default=True)

    sensitive_data: SensitiveData = Relationship(back_populates="manager")
    manager_services: list["ManagerService"] = Relationship(back_populates="manager")


class User(BaseTable, UserPlainAttribute, table=True):
    __tablename__ = "user"

    sensitive_data_id: UUID = Field(foreign_key="sensitive_data.id", unique=True)
    is_active: bool = Field(default=True)

    sensitive_data: SensitiveData = Relationship(back_populates="user")
    user_roles: list["UserRole"] = Relationship(back_populates="user")


class Service(BaseTable, table=True):
    __tablename__ = "service"

    name: str = Field(unique=True)
    description: str | None = None
    administrator_id: UUID = Field(foreign_key="administrator.id")
    is_active: bool = Field(default=True)

    registered_by: Administrator = Relationship(back_populates="manager_services")
    manager_services: list["ManagerService"] = Relationship(back_populates="service")
    application_services: list["ApplicationService"] = Relationship(
        back_populates="service"
    )
    device_services: list["DeviceService"] = Relationship(
        back_populates="service"
    )
    roles: list["Role"] = Relationship(back_populates="service")
    service_tickets: list["ServiceTicket"] = Relationship(back_populates="service")


class ManagerService(BaseTable, table=True):
    __tablename__ = "manager_service"

    manager_id: UUID = Field(foreign_key="manager.id")
    service_id: UUID = Field(foreign_key="service.id")

    manager: Manager = Relationship(back_populates="manager_services")
    service: Service = Relationship(back_populates="manager_services")
    ecosystem_tickets: list["EcosystemTicket"] = Relationship(
        back_populates="manager_service"
    )


class Application(BaseTable, table=True):
    __tablename__ = "application"

    name: str
    version: str | None = None
    url: str | None = None
    description: str | None = None
    administrator_id: UUID = Field(foreign_key="administrator.id")
    is_active: bool = Field(default=True)

    registered_by: Administrator = Relationship(
        back_populates="registered_applications"
    )
    application_services: list["ApplicationService"] = Relationship(
        back_populates="application"
    )


class ApplicationService(BaseTable, table=True):
    __tablename__ = "application_service"

    application_id: UUID = Field(foreign_key="application.id")
    service_id: UUID = Field(foreign_key="service.id")

    application: Application = Relationship(back_populates="application_services")
    service: Service = Relationship(back_populates="application_services")


class Device(BaseTable, table=True):
    __tablename__ = "device"

    name: str
    brand: str | None = None
    model: str | None = None
    serial_number: str | None = Field(default=None, unique=True)
    ip: str | None = None
    mac: str | None = Field(default=None, unique=True)
    is_active: bool = Field(default=True)

    device_services: list["DeviceService"] = Relationship(
        back_populates="device"
    )


class DeviceService(BaseTable, table=True):
    __tablename__ = "device_service"

    device_id: UUID = Field(foreign_key="device.id")
    service_id: UUID = Field(foreign_key="service.id")

    device: Device = Relationship(back_populates="device_services")
    service: Service = Relationship(back_populates="device_services")


class Role(BaseTable, table=True):
    __tablename__ = "role"

    name: str
    description: str | None = None
    service_id: UUID = Field(foreign_key="service.id")
    is_active: bool = Field(default=True)

    service: Service = Relationship(back_populates="roles")
    permission: Optional["RolePermission"] = Relationship(back_populates="role")
    user_roles: list["UserRole"] = Relationship(back_populates="role")


class RolePermission(BaseTable, table=True):
    __tablename__ = "role_permission"

    role_id: UUID = Field(foreign_key="role.id", unique=True)
    can_read: bool = Field(default=False)
    can_write: bool = Field(default=False)
    can_delete: bool = Field(default=False)
    can_administer: bool = Field(default=False)

    role: Role = Relationship(back_populates="permission")


class UserRole(BaseTable, table=True):
    __tablename__ = "user_role"

    user_id: UUID = Field(foreign_key="user.id")
    role_id: UUID = Field(foreign_key="role.id")

    user: User = Relationship(back_populates="user_roles")
    role: Role = Relationship(back_populates="user_roles")
    service_tickets: list["ServiceTicket"] = Relationship(
        back_populates="user_role"
    )


class TicketStatus(SQLModel, table=True):
    __tablename__ = "ticket_status"

    id: int | None = Field(default=None, primary_key=True)
    name: str = Field(unique=True)
    description: str | None = None

    service_tickets: list["ServiceTicket"] = Relationship(back_populates="status")
    ecosystem_tickets: list["EcosystemTicket"] = Relationship(back_populates="status")


class ServiceTicket(BaseTable, table=True):
    __tablename__ = "service_ticket"

    title: str
    description: str | None = None
    user_role_id: UUID = Field(foreign_key="user_role.id")
    status_id: int = Field(foreign_key="ticket_status.id")
    service_id: UUID = Field(foreign_key="service.id")
    priority: str = Field(default="medium")

    user_role: UserRole = Relationship(back_populates="service_tickets")
    status: TicketStatus = Relationship(back_populates="service_tickets")
    service: Service = Relationship(back_populates="service_tickets")


class EcosystemTicket(BaseTable, table=True):
    __tablename__ = "ecosystem_ticket"

    title: str
    description: str | None = None
    manager_service_id: UUID = Field(foreign_key="manager_service.id")
    status_id: int = Field(foreign_key="ticket_status.id")
    priority: str = Field(default="medium")

    manager_service: ManagerService = Relationship(
        back_populates="ecosystem_tickets"
    )
    status: TicketStatus = Relationship(back_populates="ecosystem_tickets")
