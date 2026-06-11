"""Shared fixtures for session tests."""

import pytest
import fakeredis

from app.shared.session.repository import SessionRepository
from app.shared.session.service import SessionService

TEST_ENCRYPTION_KEY = "MDEyMzQ1Njc4OWFiY2RlZjAxMjM0NTY3ODlhYmNkZWY="


@pytest.fixture
async def valkey_client():
    """Fakeredis-backed Valkey client for tests (no real Valkey needed)."""
    client = fakeredis.FakeAsyncValkey(decode_responses=True)
    yield client
    await client.flushall()
    await client.aclose()


@pytest.fixture
async def repository(valkey_client):
    """Session repository with injected fakeredis client."""
    repo = SessionRepository("valkey://localhost:6379/1")
    repo.client = valkey_client
    yield repo


@pytest.fixture
async def session_service(repository):
    """Session service with injected fake repository."""
    svc = SessionService(encryption_key=TEST_ENCRYPTION_KEY)
    svc._repository = repository
    return svc
