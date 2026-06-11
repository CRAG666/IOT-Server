"""Outbound email via SMTP (fastapi-mail).

All send functions are no-ops when ``settings.MAIL_ENABLED`` is False so the
app starts cleanly in environments without an SMTP server.
"""

from __future__ import annotations

import logging
from typing import Any

from app.config import settings

logger = logging.getLogger(__name__)


def _get_connection():
    """Return a FastMail instance configured from settings."""
    from fastapi_mail import ConnectionConfig, FastMail

    conf = ConnectionConfig(
        MAIL_USERNAME=settings.MAIL_USERNAME,
        MAIL_PASSWORD=settings.MAIL_PASSWORD,
        MAIL_FROM=settings.MAIL_FROM,
        MAIL_PORT=settings.MAIL_PORT,
        MAIL_SERVER=settings.MAIL_SERVER,
        MAIL_STARTTLS=settings.MAIL_TLS,
        MAIL_SSL_TLS=settings.MAIL_SSL,
        USE_CREDENTIALS=bool(settings.MAIL_USERNAME),
        VALIDATE_CERTS=True,
    )
    return FastMail(conf)


async def _send(to: list[str], subject: str, body: str) -> None:
    from fastapi_mail import MessageSchema, MessageType

    message = MessageSchema(
        subject=subject,
        recipients=to,
        body=body,
        subtype=MessageType.html,
    )
    fm = _get_connection()
    await fm.send_message(message)


async def send_verification_email(to: str, token: str, base_url: str = "") -> None:
    """Send account email-verification link."""
    if not settings.MAIL_ENABLED:
        logger.info("Mail disabled — verification token for %s: %s", to, token)
        return

    link = f"{base_url}/api/v1/onboarding/verify?token={token}"
    body = f"""
    <p>Welcome to IoTmx!</p>
    <p>Please verify your email address by clicking the link below:</p>
    <p><a href="{link}">{link}</a></p>
    <p>This link expires in 24 hours.</p>
    """
    await _send([to], "Verify your IoTmx account", body)


async def send_password_reset_email(to: str, token: str, base_url: str = "") -> None:
    """Send password-reset link."""
    if not settings.MAIL_ENABLED:
        logger.info("Mail disabled — reset token for %s: %s", to, token)
        return

    link = f"{base_url}/api/v1/auth/reset-password?token={token}"
    body = f"""
    <p>You requested a password reset for your IoTmx account.</p>
    <p><a href="{link}">Reset password</a></p>
    <p>This link expires in 1 hour.  If you did not request this, ignore this email.</p>
    """
    await _send([to], "Reset your IoTmx password", body)


async def send_invoice_email(to: str, invoice: dict[str, Any]) -> None:
    """Send a payment invoice to a subscriber."""
    if not settings.MAIL_ENABLED:
        logger.info("Mail disabled — invoice for %s: %s", to, invoice)
        return

    body = f"""
    <p>Thank you for your payment.</p>
    <p><strong>Amount:</strong> {invoice.get('amount')} {invoice.get('currency', 'MXN')}</p>
    <p><strong>Period:</strong> {invoice.get('period_start')} — {invoice.get('period_end')}</p>
    <p>Your service remains active.</p>
    """
    await _send([to], "IoTmx — Payment confirmation", body)
