from decimal import Decimal
from enum import Enum
from typing import Any, Optional
from uuid import UUID
from app.shared.base_domain.model import BaseTable
from datetime import datetime, timezone
import secrets

from sqlalchemy import Column, Numeric
from sqlmodel import Field, Relationship, SQLModel, UniqueConstraint
from app.database.format import UserPlainAttribute
from app.shared.crypto import generate_salt, hash_password


class NonCriticalPersonalData(BaseTable, table=True):
    __tablename__ = "non_critical_personal_data"  # pyright: ignore[reportAssignmentType]

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
        back_populates="non_critical_data",
        sa_relationship_kwargs={"lazy": "selectin"},
    )


class SensitiveData(BaseTable, table=True):
    __tablename__ = "sensitive_data"  # pyright: ignore[reportAssignmentType]

    non_critical_data_id: UUID = Field(
        foreign_key="non_critical_personal_data.id",
        unique=True,
    )
    email: str = Field(unique=True)
    password_hash: str
    # SEC-001: per-user random salt — prevents rainbow-table attacks on password_hash
    password_salt: str = Field(default="")
    curp: str | None = Field(default=None, unique=True)
    rfc: str | None = Field(default=None, unique=True)

    non_critical_data: NonCriticalPersonalData = Relationship(
        back_populates="sensitive_data",
        sa_relationship_kwargs={"lazy": "selectin"},
    )
    administrator: Optional["Administrator"] = Relationship(
        back_populates="sensitive_data",
        sa_relationship_kwargs={"lazy": "selectin"},
    )
    manager: Optional["Manager"] = Relationship(
        back_populates="sensitive_data",
        sa_relationship_kwargs={"lazy": "selectin"},
    )
    user: Optional["User"] = Relationship(
        back_populates="sensitive_data",
        sa_relationship_kwargs={"lazy": "selectin"},
    )

    def __init__(self, **data: Any):
        password = data.pop("password", None)
        if password is not None:
            salt = generate_salt()
            data["password_salt"] = salt
            data["password_hash"] = hash_password(password, salt)
        super().__init__(**data)

    def sqlmodel_update(
        self,
        obj: dict[str, Any],
        *,
        update: dict[str, Any] | None = None,
    ) -> None:
        password = obj.pop("password", None)
        super().sqlmodel_update(obj, update=update)
        if password is not None:
            self.password = password

    @property
    def password(self) -> str:
        raise AttributeError("password is write-only")

    @password.setter
    def password(self, plain_password: str) -> None:
        salt = generate_salt()
        self.password_salt = salt
        self.password_hash = hash_password(plain_password, salt)


class PersonalData(BaseTable, UserPlainAttribute):
    sensitive_data_id: UUID = Field(foreign_key="sensitive_data.id", unique=True, index=True)

    # Estado XMSS para humanos: Administrator, Manager y User.
    xmss_public_root: str | None = None
    xmss_current_index: int = Field(default=0, ge=0)
    # Valid XMSS tree heights: 2, 4, 8, 10, 16, 20 (must be even positive int)
    xmss_tree_height: int = Field(default=4, ge=2, le=20)


class Tenant(BaseTable, table=True):
    """A customer organisation — top-level multi-tenancy boundary."""

    __tablename__ = "tenant"  # pyright: ignore[reportAssignmentType]

    name: str = Field(unique=True, max_length=255)
    is_active: bool = Field(default=True)

    administrators: list["Administrator"] = Relationship(
        back_populates="tenant",
        sa_relationship_kwargs={"lazy": "selectin"},
    )
    services: list["Service"] = Relationship(
        back_populates="tenant",
        sa_relationship_kwargs={"lazy": "selectin"},
    )


class Administrator(PersonalData, table=True):
    __tablename__ = "administrator"  # pyright: ignore[reportAssignmentType]

    is_master: bool = Field(default=False)
    tenant_id: UUID | None = Field(default=None, foreign_key="tenant.id", index=True)

    sensitive_data: SensitiveData = Relationship(
        back_populates="administrator",
        sa_relationship_kwargs={"lazy": "selectin"},
    )
    tenant: Optional["Tenant"] = Relationship(
        back_populates="administrators",
        sa_relationship_kwargs={"lazy": "selectin"},
    )
    manager_services: list["Service"] = Relationship(
        back_populates="registered_by",
        sa_relationship_kwargs={"lazy": "selectin"},
    )
    registered_applications: list["Application"] = Relationship(
        back_populates="registered_by",
        sa_relationship_kwargs={"lazy": "selectin"},
    )


class Manager(PersonalData, table=True):
    __tablename__ = "manager"  # pyright: ignore[reportAssignmentType]

    sensitive_data: SensitiveData = Relationship(
        back_populates="manager",
        sa_relationship_kwargs={"lazy": "selectin"},
    )
    manager_services: list["ManagerService"] = Relationship(
        back_populates="manager",
        sa_relationship_kwargs={"lazy": "selectin"},
    )


class User(PersonalData, table=True):
    __tablename__ = "user"  # pyright: ignore[reportAssignmentType]

    sensitive_data: SensitiveData = Relationship(
        back_populates="user",
        sa_relationship_kwargs={"lazy": "selectin"},
    )
    user_roles: list["UserRole"] = Relationship(
        back_populates="user",
        sa_relationship_kwargs={"lazy": "selectin"},
    )
    user_services: list["UserService"] = Relationship(
        back_populates="user",
        sa_relationship_kwargs={"lazy": "selectin"},
    )

class Service(BaseTable, table=True):
    __tablename__ = "service"  # pyright: ignore[reportAssignmentType]

    name: str = Field(unique=True)
    description: str | None = None
    administrator_id: UUID = Field(foreign_key="administrator.id")
    tenant_id: UUID | None = Field(default=None, foreign_key="tenant.id", index=True)
    is_active: bool = Field(default=True)

    tenant: Optional["Tenant"] = Relationship(
        back_populates="services",
        sa_relationship_kwargs={"lazy": "selectin"},
    )
    registered_by: Administrator = Relationship(
        back_populates="manager_services",
        sa_relationship_kwargs={"lazy": "selectin"},
    )
    manager_services: list["ManagerService"] = Relationship(
        back_populates="service",
        sa_relationship_kwargs={"lazy": "selectin"},
    )
    application_services: list["ApplicationService"] = Relationship(
        back_populates="service",
        sa_relationship_kwargs={"lazy": "selectin"},
    )
    device_services: list["DeviceService"] = Relationship(
        back_populates="service",
        sa_relationship_kwargs={"lazy": "selectin"},
    )
    roles: list["Role"] = Relationship(
        back_populates="service",
        sa_relationship_kwargs={"lazy": "selectin"},
    )
    service_tickets: list["ServiceTicket"] = Relationship(
        back_populates="service",
        sa_relationship_kwargs={"lazy": "selectin"},
    )
    user_services: list["UserService"] = Relationship(
        back_populates="service",
        sa_relationship_kwargs={"lazy": "selectin"},
    )


class ManagerService(BaseTable, table=True):
    __tablename__ = "manager_service"  # pyright: ignore[reportAssignmentType]
    __table_args__ = (UniqueConstraint("manager_id", "service_id"),)

    manager_id: UUID = Field(foreign_key="manager.id")
    service_id: UUID = Field(foreign_key="service.id")

    manager: Manager = Relationship(
        back_populates="manager_services",
        sa_relationship_kwargs={"lazy": "selectin"},
    )
    service: Service = Relationship(
        back_populates="manager_services",
        sa_relationship_kwargs={"lazy": "selectin"},
    )
    ecosystem_tickets: list["EcosystemTicket"] = Relationship(
        back_populates="manager_service",
        sa_relationship_kwargs={"lazy": "selectin"},
    )


def get_api_key():
    return secrets.token_hex(32)


class Application(BaseTable, table=True):
    __tablename__ = "application"  # pyright: ignore[reportAssignmentType]

    name: str = Field(unique=True)
    version: str
    url: str
    description: str
    api_key: str = Field(default_factory=get_api_key, unique=True, index=True)
    port: int | None = Field(default=None)
    administrator_id: UUID = Field(foreign_key="administrator.id")
    is_active: bool = Field(default=True)

    # Estado XMSS para aplicaciones.
    xmss_public_root: str | None = None
    xmss_current_index: int = Field(default=0)
    xmss_tree_height: int = Field(default=4)

    registered_by: Administrator = Relationship(
        back_populates="registered_applications",
        sa_relationship_kwargs={"lazy": "selectin"},
    )
    application_services: list["ApplicationService"] = Relationship(
        back_populates="application",
        sa_relationship_kwargs={"lazy": "selectin"},
    )


class ApplicationService(BaseTable, table=True):
    __tablename__ = "application_service"  # pyright: ignore[reportAssignmentType]
    __table_args__ = (UniqueConstraint("application_id", "service_id"),)

    application_id: UUID = Field(foreign_key="application.id")
    service_id: UUID = Field(foreign_key="service.id")

    application: Application = Relationship(
        back_populates="application_services",
        sa_relationship_kwargs={"lazy": "selectin"},
    )
    service: Service = Relationship(
        back_populates="application_services",
        sa_relationship_kwargs={"lazy": "selectin"},
    )


class Device(BaseTable, table=True):
    __tablename__ = "device"  # pyright: ignore[reportAssignmentType]

    name: str
    brand: str | None = None
    model: str | None = None
    serial_number: str | None = Field(default=None, unique=True)
    ip: str | None = None
    mac: str | None = Field(default=None, unique=True)
    encryption_key: str | None = None
    is_active: bool = Field(default=True)

    # Estado XMSS para dispositivos.
    xmss_public_root: str | None = None
    xmss_current_index: int = Field(default=0)
    xmss_tree_height: int = Field(default=4)

    device_services: list["DeviceService"] = Relationship(
        back_populates="device",
        sa_relationship_kwargs={"lazy": "selectin"},
    )


class DeviceService(BaseTable, table=True):
    __tablename__ = "device_service"  # pyright: ignore[reportAssignmentType]
    __table_args__ = (UniqueConstraint("device_id", "service_id"),)

    device_id: UUID = Field(foreign_key="device.id")
    service_id: UUID = Field(foreign_key="service.id")

    device: Device = Relationship(
        back_populates="device_services",
        sa_relationship_kwargs={"lazy": "selectin"},
    )
    service: Service = Relationship(
        back_populates="device_services",
        sa_relationship_kwargs={"lazy": "selectin"},
    )


class Role(BaseTable, table=True):
    __tablename__ = "role"  # pyright: ignore[reportAssignmentType]
    __table_args__ = (UniqueConstraint("name", "service_id"),)

    name: str
    description: str | None = None
    service_id: UUID = Field(foreign_key="service.id")
    is_active: bool = Field(default=True)

    service: Service = Relationship(
        back_populates="roles",
        sa_relationship_kwargs={"lazy": "selectin"},
    )
    user_roles: list["UserRole"] = Relationship(
        back_populates="role",
        sa_relationship_kwargs={"lazy": "selectin"},
    )
    permission: Optional["RolePermission"] = Relationship(
        back_populates="role",
        sa_relationship_kwargs={"lazy": "selectin"},
    )


class RolePermission(BaseTable, table=True):
    """Capability flags for a Role — 1:1 with Role."""

    __tablename__ = "role_permission"  # pyright: ignore[reportAssignmentType]

    role_id: UUID = Field(foreign_key="role.id", unique=True)
    can_read: bool = Field(default=False)
    can_write: bool = Field(default=False)
    can_delete: bool = Field(default=False)
    can_administer: bool = Field(default=False)

    role: Role = Relationship(
        back_populates="permission",
        sa_relationship_kwargs={"lazy": "selectin"},
    )


class UserRole(BaseTable, table=True):
    __tablename__ = "user_role"  # pyright: ignore[reportAssignmentType]
    __table_args__ = (UniqueConstraint("user_id", "role_id"),)

    user_id: UUID = Field(foreign_key="user.id")
    role_id: UUID = Field(foreign_key="role.id")

    user: User = Relationship(
        back_populates="user_roles",
        sa_relationship_kwargs={"lazy": "selectin"},
    )
    role: Role = Relationship(
        back_populates="user_roles",
        sa_relationship_kwargs={"lazy": "selectin"},
    )
    service_tickets: list["ServiceTicket"] = Relationship(
        back_populates="user_role",
        sa_relationship_kwargs={"lazy": "selectin"},
    )


class TicketStatus(SQLModel, table=True):
    __tablename__ = "ticket_status"  # pyright: ignore[reportAssignmentType]

    id: int | None = Field(default=None, primary_key=True)
    name: str = Field(unique=True)
    description: str | None = None

    service_tickets: list["ServiceTicket"] = Relationship(
        back_populates="status",
        sa_relationship_kwargs={"lazy": "selectin"},
    )
    ecosystem_tickets: list["EcosystemTicket"] = Relationship(
        back_populates="status",
        sa_relationship_kwargs={"lazy": "selectin"},
    )


class Priority(str, Enum):
    low = "low"
    medium = "medium"
    high = "high"
    critical = "critical"


class ServiceTicket(BaseTable, table=True):
    __tablename__ = "service_ticket"  # pyright: ignore[reportAssignmentType]

    title: str
    description: str | None = None
    user_role_id: UUID = Field(foreign_key="user_role.id")
    status_id: int = Field(foreign_key="ticket_status.id")
    service_id: UUID = Field(foreign_key="service.id")
    priority: Priority = Field(default=Priority.medium)

    user_role: UserRole = Relationship(
        back_populates="service_tickets",
        sa_relationship_kwargs={"lazy": "selectin"},
    )
    status: TicketStatus = Relationship(
        back_populates="service_tickets",
        sa_relationship_kwargs={"lazy": "selectin"},
    )
    service: Service = Relationship(
        back_populates="service_tickets",
        sa_relationship_kwargs={"lazy": "selectin"},
    )


class EcosystemTicket(BaseTable, table=True):
    __tablename__ = "ecosystem_ticket"

    title: str
    description: str | None = None
    manager_service_id: UUID = Field(foreign_key="manager_service.id")
    status_id: int = Field(foreign_key="ticket_status.id")
    priority: Priority = Field(default=Priority.medium)

    manager_service: ManagerService = Relationship(
        back_populates="ecosystem_tickets",
        sa_relationship_kwargs={"lazy": "selectin"},
    )
    status: TicketStatus = Relationship(
        back_populates="ecosystem_tickets",
        sa_relationship_kwargs={"lazy": "selectin"},
    )







class SubscriptionType(BaseTable, table=True):
    __tablename__ = "subscription_type"  # pyright: ignore[reportAssignmentType]
    type: str = Field(unique=True)
    cost: Decimal = Field(
        default=Decimal("0.00"),
        sa_column=Column(Numeric(precision=10, scale=2)),
    )

    payments: list["Payment"] = Relationship(
        back_populates="subscription_type",
        sa_relationship_kwargs={"lazy": "selectin"},
    )


class UserService(BaseTable, table=True):
    __tablename__ = "user_service"  # pyright: ignore[reportAssignmentType]
    __table_args__ = (UniqueConstraint("user_id", "service_id"),)

    user_id: UUID = Field(foreign_key="user.id")
    service_id: UUID = Field(foreign_key="service.id")
    is_active: bool = Field(default=False)

    user: User = Relationship(
        back_populates="user_services",
        sa_relationship_kwargs={"lazy": "selectin"},
    )
    service: Service = Relationship(
        back_populates="user_services",
        sa_relationship_kwargs={"lazy": "selectin"},
    )
    payments: list["Payment"] = Relationship(
        back_populates="user_service",
        sa_relationship_kwargs={"lazy": "selectin"},
    )


class Payment(BaseTable, table=True):
    __tablename__ = "payment"  # pyright: ignore[reportAssignmentType]

    user_service_id: UUID = Field(foreign_key="user_service.id")
    subscription_type_id: UUID = Field(foreign_key="subscription_type.id")
    expires_at: datetime

    user_service: UserService = Relationship(
        back_populates="payments",
        sa_relationship_kwargs={"lazy": "selectin"},
    )
    subscription_type: SubscriptionType = Relationship(
        back_populates="payments",
        sa_relationship_kwargs={"lazy": "selectin"},
    )
    history: list["PaymentHistory"] = Relationship(
        back_populates="payment",
        sa_relationship_kwargs={"lazy": "selectin"},
    )


class PaymentHistory(BaseTable, table=True):
    __tablename__ = "payment_history"  # pyright: ignore[reportAssignmentType]

    payment_id: UUID = Field(foreign_key="payment.id")
    deposit_id: str
    amount: Decimal = Field(
        default=Decimal("0.00"),
        sa_column=Column(Numeric(precision=12, scale=2)),
    )
    period_start: datetime
    period_end: datetime

    payment: Payment = Relationship(
        back_populates="history",
        sa_relationship_kwargs={"lazy": "selectin"},
    )


class AuditLog(BaseTable, table=True):
    """Immutable record of every mutating action taken by an authenticated account."""

    __tablename__ = "audit_log"  # pyright: ignore[reportAssignmentType]

    account_id: UUID = Field(index=True)
    account_type: str
    action: str
    resource_type: str
    resource_id: UUID | None = Field(default=None, index=True)
    details: str | None = None
    ip_address: str | None = None