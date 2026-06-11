from typing import Annotated, Self
from pydantic import model_validator
from pydantic_settings import BaseSettings, SettingsConfigDict

_DEFAULT_SECRET_KEY = "change-me-in-env"
_DEFAULT_ENCRYPTION_KEY = "change-me-32-byte-base64-key-here"


class Settings(BaseSettings):
    DATABASE_URL: str
    APP_NAME: str = "IoT Backend"
    DEBUG: bool = False

    SECRET_KEY: str = _DEFAULT_SECRET_KEY

    # SEC-012: default to INFO so sensitive request data is not logged in production.
    # Set LOG_LEVEL=DEBUG explicitly in .env when debugging.
    LOG_LEVEL: str = "INFO"

    # CORS — provide a comma-separated list in the env var or override per-origin
    CORS_ORIGINS: list[str] = ["http://localhost:3000"]

    # Session/Valkey Configuration
    VALKEY_URL: str = "redis://localhost:6379/0"
    ENCRYPTION_KEY: str = _DEFAULT_ENCRYPTION_KEY
    SESSION_TTL_SECONDS: int = 3600  # 1 hour
    METADATA_MAX_KEYS: int = 50
    METADATA_MAX_SIZE_BYTES: int = 4096

    # Authentication method by deployment
    # Allowed values: auth_rc, auth_xmss
    AUTH_ADMINISTRATOR_METHOD: str = "auth_rc"
    AUTH_MANAGER_METHOD: str = "auth_rc"
    AUTH_USER_METHOD: str = "auth_rc"
    AUTH_DEVICE_METHOD: str = "auth_rc"
    AUTH_APPLICATION_METHOD: str = "auth_rc"

    # MongoDB — non-relational store for device telemetry
    MONGODB_URL: str = "mongodb://localhost:27017"
    MONGODB_DB: str = "iotmx"

    # MQTT broker
    MQTT_HOST: str = "localhost"
    MQTT_PORT: int = 1883
    MQTT_USERNAME: str | None = None
    MQTT_PASSWORD: str | None = None
    MQTT_ENABLED: bool = False

    # Email / SMTP
    MAIL_SERVER: str = "localhost"
    MAIL_PORT: int = 587
    MAIL_USERNAME: str = ""
    MAIL_PASSWORD: str = ""
    MAIL_FROM: str = "noreply@iotmx.local"
    MAIL_TLS: bool = True
    MAIL_SSL: bool = False
    MAIL_ENABLED: bool = False

    # Webhooks
    WEBHOOK_SIGNING_SECRET: str = "change-me-webhook-secret"
    WEBHOOK_TIMEOUT_SECONDS: int = 10
    WEBHOOK_MAX_RETRIES: int = 3

    # Observability
    OTEL_ENABLED: bool = False
    OTEL_ENDPOINT: str = "http://localhost:4317"
    METRICS_ENABLED: bool = True

    model_config = SettingsConfigDict(
        env_file=".env",
        extra="ignore",
    )

    @model_validator(mode="after")
    def _reject_default_secrets_in_production(self) -> Self:
        if not self.DEBUG:
            if self.SECRET_KEY == _DEFAULT_SECRET_KEY:
                raise ValueError(
                    "SECRET_KEY must be changed from its default value in production (set DEBUG=True to bypass)"
                )
            if self.ENCRYPTION_KEY == _DEFAULT_ENCRYPTION_KEY:
                raise ValueError(
                    "ENCRYPTION_KEY must be changed from its default value in production (set DEBUG=True to bypass)"
                )
        return self


settings = Settings()  # type: ignore[reportCallIssue]
