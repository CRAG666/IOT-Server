from datetime import datetime
from pydantic import BaseModel, ConfigDict, Field, field_validator
from app.shared.base_domain.schemas import BaseSchemaResponse
from uuid import UUID


class NonCriticalPersonalDataCreate(BaseModel):
    model_config = ConfigDict(extra="forbid", str_strip_whitespace=True)

    first_name: str = Field(min_length=2, max_length=60)
    last_name: str = Field(min_length=2, max_length=60)
    second_last_name: str = Field(min_length=2, max_length=60)
    phone: str = Field(pattern=r"^\+?[0-9]{10,15}$")
    address: str = Field(min_length=5, max_length=150)
    city: str = Field(min_length=2, max_length=80)
    state: str = Field(min_length=2, max_length=80)
    postal_code: str = Field(pattern=r"^[0-9]{5}$")
    birth_date: datetime

    @field_validator("birth_date")
    @classmethod
    def validate_birth_date(cls, value: datetime) -> datetime:
        if value > datetime.now():
            raise ValueError("birth_date no puede ser futura")
        return value


class NonCriticalPersonalDataUpdate(BaseModel):
    model_config = ConfigDict(extra="forbid", str_strip_whitespace=True)

    first_name: str | None = Field(default=None, min_length=2, max_length=60)
    last_name: str | None = Field(default=None, min_length=2, max_length=60)
    second_last_name: str | None = Field(default=None, min_length=2, max_length=60)
    phone: str | None = Field(default=None, pattern=r"^\+?[0-9]{10,15}$")
    address: str | None = Field(default=None, min_length=5, max_length=150)
    city: str | None = Field(default=None, min_length=2, max_length=80)
    state: str | None = Field(default=None, min_length=2, max_length=80)
    postal_code: str | None = Field(default=None, pattern=r"^[0-9]{5}$")
    birth_date: datetime | None = None
    is_active: bool | None = None

    @field_validator("birth_date")
    @classmethod
    def validate_birth_date(cls, value: datetime | None) -> datetime | None:
        if value is not None and value > datetime.now():
            raise ValueError("birth_date no puede ser futura")
        return value


class NonCriticalPersonalDataResponse(BaseSchemaResponse):
    first_name: str
    last_name: str
    second_last_name: str | None = None
    is_active: bool


class SensitiveDataCreate(BaseModel):
    model_config = ConfigDict(extra="forbid", str_strip_whitespace=True)

    non_critical_data_id: UUID | None = None
    email: str = Field(min_length=6, max_length=254)
    password_hash: str = Field(min_length=8, max_length=128)
    curp: str = Field(pattern=r"^[A-Z0-9]{18}$")
    rfc: str = Field(pattern=r"^[A-Z0-9]{12,13}$")

    @field_validator("email")
    @classmethod
    def normalize_email(cls, value: str) -> str:
        email = value.strip().lower()
        if "@" not in email or email.startswith("@") or email.endswith("@"):
            raise ValueError("email inválido")
        return email

    @field_validator("curp", "rfc")
    @classmethod
    def normalize_ids(cls, value: str) -> str:
        return value.strip().upper()


class SensitiveDataUpdate(BaseModel):
    model_config = ConfigDict(extra="forbid", str_strip_whitespace=True)

    non_critical_data_id: UUID | None = None
    email: str | None = Field(default=None, min_length=6, max_length=254)
    password_hash: str | None = Field(default=None, min_length=8, max_length=128)
    curp: str | None = Field(default=None, pattern=r"^[A-Z0-9]{18}$")
    rfc: str | None = Field(default=None, pattern=r"^[A-Z0-9]{12,13}$")

    @field_validator("email")
    @classmethod
    def normalize_email(cls, value: str | None) -> str | None:
        if value is None:
            return None
        email = value.strip().lower()
        if "@" not in email or email.startswith("@") or email.endswith("@"):
            raise ValueError("email inválido")
        return email

    @field_validator("curp", "rfc")
    @classmethod
    def normalize_ids(cls, value: str | None) -> str | None:
        if value is None:
            return None
        return value.strip().upper()


class PersonalDataCreate(NonCriticalPersonalDataCreate, SensitiveDataCreate):
    sensitive_data_id: UUID | None = None


class PersonalDataUpdate(NonCriticalPersonalDataUpdate, SensitiveDataUpdate):
    pass
