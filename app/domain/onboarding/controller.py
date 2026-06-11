"""Self-service onboarding: register + email verification.

Both endpoints are public (no E2E session required).
"""

from fastapi import APIRouter
from fastapi import status as http_status

from app.database import SessionDep
from app.domain.onboarding.schemas import RegistrationRequest, RegistrationResponse, VerificationResponse
from app.domain.onboarding.service import OnboardingService

onboarding_router = APIRouter(prefix="/onboarding", tags=["Onboarding"])


@onboarding_router.post(
    "/register",
    status_code=http_status.HTTP_202_ACCEPTED,
    response_model=RegistrationResponse,
)
async def register(body: RegistrationRequest, session: SessionDep) -> RegistrationResponse:
    """Create a pending admin account and send an email verification link.

    The account is inactive until the verification link is clicked.
    Returns HTTP 202 regardless of whether the email already exists to prevent
    user enumeration.
    """
    svc = OnboardingService(session)
    try:
        await svc.register(
            first_name=body.first_name,
            last_name=body.last_name,
            email=str(body.email),
            password=body.password,
            phone=body.phone,
        )
    except Exception:
        # Swallow all errors — always return the same message to prevent enumeration
        pass
    return RegistrationResponse(
        message="If this email is not already registered, a verification link has been sent.",
        email=str(body.email),
    )


@onboarding_router.get("/verify", response_model=VerificationResponse)
async def verify_email(token: str, session: SessionDep) -> VerificationResponse:
    """Activate an account using the token sent by email."""
    svc = OnboardingService(session)
    await svc.verify(token)
    return VerificationResponse(message="Email verified. Your account is now active.")
