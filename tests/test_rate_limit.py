from collections import defaultdict
from types import SimpleNamespace

import pytest
from fastapi.routing import APIRoute
from starlette.requests import Request

from app.main import app
from app.shared.rate_limit import build_rate_limit_key, enforce_request_rate_limit
from app.shared.session.exceptions import RateLimitExceededException


class InMemoryRateLimitRepository:
    def __init__(self):
        self.counts: defaultdict[str, int] = defaultdict(int)

    async def increment_rate_limit(self, rate_limit_key: str, window_seconds: int = 1) -> int:
        self.counts[rate_limit_key] += 1
        return self.counts[rate_limit_key]

    async def get_rate_limit_ttl(self, rate_limit_key: str) -> int:
        return 1 if rate_limit_key in self.counts else 0

    async def close(self) -> None:
        return None


def _build_request(
    path: str,
    tags: list[str],
    *,
    ip_address: str = "127.0.0.1",
    account_id: str | None = None) -> Request:
    scope = {
        "type": "http",
        "method": "POST",
        "path": path,
        "headers": [],
        "client": (ip_address, 12345),
        "scheme": "http",
        "server": ("testserver", 80),
        "query_string": b"",
        "route": SimpleNamespace(tags=tags, path_format=path),
    }
    request = Request(scope)
    request.state.current_account = (
        {"account_id": account_id} if account_id else None
    )
    return request


def _find_route(path: str, method: str) -> APIRoute:
    for route in app.routes:
        if isinstance(route, APIRoute) and route.path == path and method in route.methods:
            return route
    raise AssertionError(f"Route {method} {path} not found")


def test_build_rate_limit_key_uses_route_tag_and_ip_address():
    request = _build_request(
        "/api/v1/auth/login",
        ["Auth"],
        ip_address="10.0.0.7")

    assert build_rate_limit_key(request) == "auth:ip:10.0.0.7"


def test_build_rate_limit_key_uses_authenticated_account_when_present():
    request = _build_request(
        "/api/v1/users/",
        ["Users"],
        account_id="user-123")

    assert build_rate_limit_key(request) == "users:account:user-123"


def test_rate_limit_blocks_fourth_request_in_same_group_and_subject():
    repository = InMemoryRateLimitRepository()
    request = _build_request(
        "/api/v1/auth/login",
        ["Auth"],
        ip_address="10.0.0.8")

    for _ in range(3):
        import asyncio

        asyncio.run(enforce_request_rate_limit(request, repository))

    with pytest.raises(RateLimitExceededException) as exc_info:
        import asyncio

        asyncio.run(enforce_request_rate_limit(request, repository))

    assert exc_info.value.status_code == 429
    assert exc_info.value.headers["Retry-After"] == "1"


def test_rate_limit_counts_are_isolated_by_authenticated_account():
    repository = InMemoryRateLimitRepository()
    first_request = _build_request(
        "/api/v1/users/",
        ["Users"],
        account_id="account-a")
    second_request = _build_request(
        "/api/v1/users/",
        ["Users"],
        account_id="account-b")

    for _ in range(3):
        import asyncio

        asyncio.run(enforce_request_rate_limit(first_request, repository))

    with pytest.raises(RateLimitExceededException):
        import asyncio

        asyncio.run(enforce_request_rate_limit(first_request, repository))

    import asyncio

    asyncio.run(enforce_request_rate_limit(second_request, repository))


def test_auth_routes_include_rate_limit_dependency():
    route = _find_route("/api/v1/auth/login", "POST")

    dependency_calls = [dependency.call for dependency in route.dependant.dependencies]

    assert enforce_request_rate_limit in dependency_calls


def test_crud_routes_include_rate_limit_dependency():
    route = _find_route("/api/v1/users/", "GET")

    dependency_calls = [dependency.call for dependency in route.dependant.dependencies]

    assert enforce_request_rate_limit in dependency_calls