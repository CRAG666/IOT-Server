"""Schemas for the self-service onboarding flow."""

from pydantic import BaseModel, EmailStr, Field


class RegistrationRequest(BaseModel):
    """Payload for POST /onboarding/register."""

    first_name: str = Field(min_length=1, max_length=100)
    last_name: str = Field(min_length=1, max_length=100)
    email: EmailStr
    password: str = Field(min_length=8, max_length=128)
    phone: str | None = Field(default=None, max_length=20)


class RegistrationResponse(BaseModel):
    message: str
    email: str


class VerificationResponse(BaseModel):
    message: str
