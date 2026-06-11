"""Tests for app.shared.email — outbound SMTP helpers."""

from __future__ import annotations

from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from app.shared import email as email_module


# ─────────────────────────────────────────────────────────────────────────────
# When MAIL_ENABLED is False (default in tests) — log-only paths
# ─────────────────────────────────────────────────────────────────────────────


class TestMailDisabled:
    @pytest.mark.anyio
    async def test_send_verification_email_logs_and_skips(self, caplog):
        import logging
        with caplog.at_level(logging.INFO):
            await email_module.send_verification_email("user@example.com", "tok123")
        assert "tok123" in caplog.text

    @pytest.mark.anyio
    async def test_send_password_reset_email_logs_and_skips(self, caplog):
        import logging
        with caplog.at_level(logging.INFO):
            await email_module.send_password_reset_email("user@example.com", "reset-tok")
        assert "reset-tok" in caplog.text

    @pytest.mark.anyio
    async def test_send_invoice_email_logs_and_skips(self, caplog):
        import logging
        invoice = {"amount": 99.99, "currency": "MXN"}
        with caplog.at_level(logging.INFO):
            await email_module.send_invoice_email("user@example.com", invoice)
        assert "user@example.com" in caplog.text


# ─────────────────────────────────────────────────────────────────────────────
# When MAIL_ENABLED is True — actual send path (mocked FastMail)
# ─────────────────────────────────────────────────────────────────────────────


@pytest.fixture
def mail_enabled(monkeypatch):
    """Temporarily enable mail and provide a mocked FastMail.send_message."""
    mock_fm = MagicMock()
    mock_fm.send_message = AsyncMock(return_value=None)

    monkeypatch.setattr(email_module.settings, "MAIL_ENABLED", True)

    with patch("app.shared.email._get_connection", return_value=mock_fm):
        yield mock_fm


class TestMailEnabled:
    @pytest.mark.anyio
    async def test_send_verification_email_calls_fastmail(self, mail_enabled):
        await email_module.send_verification_email("alice@example.com", "abc123")
        mail_enabled.send_message.assert_awaited_once()

    @pytest.mark.anyio
    async def test_send_verification_email_includes_token_in_link(self, mail_enabled):
        await email_module.send_verification_email("alice@example.com", "abc123", base_url="https://app.io")
        call = mail_enabled.send_message.call_args
        # The message is the first positional arg
        msg = call[0][0]
        assert "abc123" in msg.body

    @pytest.mark.anyio
    async def test_send_password_reset_calls_fastmail(self, mail_enabled):
        await email_module.send_password_reset_email("bob@example.com", "reset-xyz")
        mail_enabled.send_message.assert_awaited_once()

    @pytest.mark.anyio
    async def test_send_invoice_calls_fastmail(self, mail_enabled):
        invoice = {"amount": 50.0, "currency": "MXN", "period_start": "2024-01", "period_end": "2024-01"}
        await email_module.send_invoice_email("carol@example.com", invoice)
        mail_enabled.send_message.assert_awaited_once()


# ─────────────────────────────────────────────────────────────────────────────
# _get_connection and _send (covered via above but also directly)
# ─────────────────────────────────────────────────────────────────────────────


class TestGetConnection:
    def test_get_connection_returns_fastmail_instance(self):
        with (
            patch("fastapi_mail.ConnectionConfig"),
            patch("fastapi_mail.FastMail") as mock_fm_cls,
        ):
            from app.shared.email import _get_connection
            _get_connection()
            mock_fm_cls.assert_called_once()
