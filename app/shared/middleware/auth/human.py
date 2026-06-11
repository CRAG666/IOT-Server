"""Backward-compatible shim — the E2E middleware now handles all auth.

Import ``E2EMiddleware`` directly from ``app.shared.e2e.middleware``.
This module is kept so that existing imports in tests do not break;
``engine`` is re-exported for the conftest fixture that patches it.
"""

from app.database import engine  # noqa: F401 (re-exported for test patching)
from app.shared.e2e.middleware import E2EMiddleware as Human  # noqa: F401

__all__ = ["Human", "engine"]
