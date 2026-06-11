"""Sliding-window rate limiter backed by Valkey.

Public API:

- ``build_rate_limit_key(request)`` — derive the scoped key for a request.
- ``enforce_request_rate_limit(request, repository)`` — async FastAPI dependency
  that increments the counter and raises 429 when the limit is exceeded.
- ``rate_limiter(...)`` — factory for router-level pre-configured dependencies.
"""

from typing import Annotated

from fastapi import Depends, Request

from app.config import settings
from app.shared.session.exceptions import RateLimitExceededException
from app.shared.session.repository import SessionRepository


_MAX_REQUESTS: int = 3
_WINDOW_SECONDS: int = 900  # 15 minutes


def build_rate_limit_key(request: Request) -> str:
    """Build a scoped rate-limit key for *request*.

    The scope is derived from the first route tag (lowercased, spaces → hyphens).
    If the request carries an authenticated account the subject is the account id;
    otherwise the client IP address is used.

    Args:
        request: the current FastAPI/Starlette request.

    Returns:
        A string in the form ``"<scope>:<type>:<identifier>"``.
    """
    route = request.scope.get("route")
    if route and getattr(route, "tags", None):
        scope = str(route.tags[0]).lower().replace(" ", "-")
    else:
        scope = "global"

    current_account = getattr(request.state, "current_account", None)
    if current_account and isinstance(current_account, dict):
        account_id = current_account.get("account_id")
    else:
        account_id = None

    if account_id:
        return f"{scope}:account:{account_id}"

    ip = request.client.host if request.client else "unknown"
    return f"{scope}:ip:{ip}"


def get_rate_limit_repository() -> SessionRepository:
    """FastAPI dependency that provides a Valkey-backed SessionRepository.

    Exposed as a public dependency so tests can override it via
    ``app.dependency_overrides[get_rate_limit_repository]``.

    Returns:
        A new :class:`~app.shared.session.repository.SessionRepository` connected
        to the configured Valkey instance.
    """
    return SessionRepository(settings.VALKEY_URL)


async def enforce_request_rate_limit(
    request: Request,
    repository: Annotated[SessionRepository, Depends(get_rate_limit_repository)],
) -> None:
    """FastAPI dependency: enforce the sliding-window rate limit for *request*.

    Backed by Valkey so limits are shared across all workers.  Raises
    :class:`~app.shared.session.exceptions.RateLimitExceededException` (HTTP 429)
    when ``_MAX_REQUESTS`` is reached within ``_WINDOW_SECONDS``.

    Args:
        request: the current request (used for key derivation).
        repository: Valkey-backed session/rate-limit repository.

    Raises:
        RateLimitExceededException: when the request count exceeds the limit.
    """
    key = build_rate_limit_key(request)
    count = await repository.increment_rate_limit(key, window_seconds=_WINDOW_SECONDS)
    if count > _MAX_REQUESTS:
        ttl = await repository.get_rate_limit_ttl(key)
        raise RateLimitExceededException(retry_after=max(ttl, 1))


def rate_limiter(
    max_requests: int = _MAX_REQUESTS,
    window_seconds: int = _WINDOW_SECONDS,
    scope: str = "default",
):
    """Factory that returns a pre-configured rate-limit dependency.

    Use when a router needs a custom limit that differs from the default
    ``enforce_request_rate_limit`` settings.

    Args:
        max_requests: maximum calls allowed within *window_seconds*.
        window_seconds: length of the sliding window.
        scope: key prefix; overrides the tag-based scope from the request.

    Returns:
        An async FastAPI dependency function.
    """

    async def dependency(
        request: Request,
        repository: Annotated[SessionRepository, Depends(get_rate_limit_repository)],
    ) -> None:
        ip = request.client.host if request.client else "unknown"
        key = f"{scope}:ip:{ip}"
        count = await repository.increment_rate_limit(key, window_seconds=window_seconds)
        if count > max_requests:
            ttl = await repository.get_rate_limit_ttl(key)
            raise RateLimitExceededException(retry_after=max(ttl, 1))

    return dependency
