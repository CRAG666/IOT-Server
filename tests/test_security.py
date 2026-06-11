"""Tests for W4 security hardening: config validation, CORS, audit exclusions."""
import pytest
from decimal import Decimal
from pydantic import ValidationError

from app.config import Settings, _DEFAULT_SECRET_KEY, _DEFAULT_ENCRYPTION_KEY
from app.shared.base_domain.service import BaseService
from app.domain.device.service import DeviceService
from app.domain.application.service import ApplicationService
from app.domain.personal_data.sensitive_data_service import SensitiveDataService


class TestProductionSecretGuard:
    """Settings must reject default secrets when DEBUG=False."""

    def test_default_secret_key_rejected_in_production(self):
        with pytest.raises((ValueError, ValidationError)):
            Settings(
                DATABASE_URL="sqlite:///test.db",
                DEBUG=False,
                SECRET_KEY=_DEFAULT_SECRET_KEY,
                ENCRYPTION_KEY="a" * 44)

    def test_default_encryption_key_rejected_in_production(self):
        with pytest.raises((ValueError, ValidationError)):
            Settings(
                DATABASE_URL="sqlite:///test.db",
                DEBUG=False,
                SECRET_KEY="a-valid-32-char-secret-key-here!",
                ENCRYPTION_KEY=_DEFAULT_ENCRYPTION_KEY)

    def test_default_secrets_allowed_when_debug(self):
        s = Settings(
            DATABASE_URL="sqlite:///test.db",
            DEBUG=True,
            SECRET_KEY=_DEFAULT_SECRET_KEY,
            ENCRYPTION_KEY=_DEFAULT_ENCRYPTION_KEY)
        assert s.DEBUG is True

    def test_custom_secrets_accepted_in_production(self):
        s = Settings(
            DATABASE_URL="sqlite:///test.db",
            DEBUG=False,
            SECRET_KEY="a-valid-32-char-secret-key-here!",
            ENCRYPTION_KEY="MDEyMzQ1Njc4OWFiY2RlZjAxMjM0NTY3ODlhYmNkZWY=")
        assert s.DEBUG is False


class TestCorsConfig:
    """CORS origins should come from settings."""

    def test_default_cors_uses_localhost(self):
        s = Settings(
            DATABASE_URL="sqlite:///test.db",
            DEBUG=True,
            CORS_ORIGINS=["http://localhost:3000"])
        assert "http://localhost:3000" in s.CORS_ORIGINS

    def test_cors_origins_configurable(self):
        s = Settings(
            DATABASE_URL="sqlite:///test.db",
            DEBUG=True,
            CORS_ORIGINS=["https://app.example.com"])
        assert s.CORS_ORIGINS == ["https://app.example.com"]


class TestAuditExcludedFields:
    """Each service should exclude only its own sensitive fields."""

    def test_base_service_excludes_only_system_fields(self):
        expected = frozenset({"id", "created_at", "updated_at"})
        assert BaseService.audit_excluded_fields == expected

    def test_device_service_excludes_encryption_key(self):
        assert "encryption_key" in DeviceService.audit_excluded_fields
        assert "id" in DeviceService.audit_excluded_fields

    def test_device_service_does_not_exclude_api_key(self):
        assert "api_key" not in DeviceService.audit_excluded_fields

    def test_application_service_excludes_api_key(self):
        assert "api_key" in ApplicationService.audit_excluded_fields
        assert "id" in ApplicationService.audit_excluded_fields

    def test_application_service_does_not_exclude_encryption_key(self):
        assert "encryption_key" not in ApplicationService.audit_excluded_fields

    def test_sensitive_data_service_excludes_pii(self):
        for field in ("password_hash", "curp", "rfc"):
            assert field in SensitiveDataService.audit_excluded_fields

    def test_sensitive_data_service_keeps_system_fields(self):
        for field in ("id", "created_at", "updated_at"):
            assert field in SensitiveDataService.audit_excluded_fields
