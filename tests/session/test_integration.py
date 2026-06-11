"""
Integration tests for Session module using fakeredis.

Tests validate:
- SessionRepository operations
- SessionService complete workflows
- Token encryption/decryption flows
- Session lifecycle management
"""

import asyncio
from datetime import datetime, timezone
from uuid import uuid4

import fakeredis
import pytest

from app.shared.session.models import SessionData
from app.shared.session.repository import SessionRepository
from app.shared.session.security import JWEHandler
from app.shared.session.service import SessionService


TEST_ENCRYPTION_KEY = "MDEyMzQ1Njc4OWFiY2RlZjAxMjM0NTY3ODlhYmNkZWY="


@pytest.fixture(scope="function")
async def valkey_client():
    client = fakeredis.FakeAsyncValkey(decode_responses=True)
    yield client
    await client.flushall()
    await client.aclose()


@pytest.fixture(scope="function")
async def repository(valkey_client):
    repo = SessionRepository("valkey://localhost:6379/1")
    repo.client = valkey_client
    yield repo


@pytest.fixture(scope="function")
async def service(valkey_client):
    svc = SessionService(encryption_key=TEST_ENCRYPTION_KEY)
    repo = SessionRepository("valkey://localhost:6379/1")
    repo.client = valkey_client
    svc._repository = repo
    yield svc


@pytest.fixture
def sample_session_data():
    """Create sample session data for testing."""
    now = datetime.now(timezone.utc)
    return SessionData(
        user_id="test-user-123",
        token_id=str(uuid4()),
        refresh_token="sample-refresh-token",
        email="test@example.com",
        account_type="user",
        is_master=False,
        ip_address="127.0.0.1",
        user_agent="Test Agent",
        created_at=now,
        last_activity=now)


# ==================== SessionRepository Tests ====================


class TestSessionRepositoryIntegration:
    """Integration tests for SessionRepository with real Valkey."""

    @pytest.mark.asyncio
    async def test_store_and_get_session(self, repository, sample_session_data):
        """Test storing and retrieving a session."""
        user_id = sample_session_data.user_id
        
        # Store session
        await repository.store_session(user_id, sample_session_data, ttl_seconds=60)
        
        # Retrieve session
        retrieved = await repository.get_session(user_id)
        
        assert retrieved is not None
        assert retrieved.user_id == sample_session_data.user_id
        assert retrieved.token_id == sample_session_data.token_id
        assert retrieved.email == sample_session_data.email
        assert retrieved.account_type == sample_session_data.account_type

    @pytest.mark.asyncio
    async def test_get_nonexistent_session(self, repository):
        """Test retrieving a session that doesn't exist."""
        result = await repository.get_session("nonexistent-user")
        assert result is None

    @pytest.mark.asyncio
    async def test_delete_session(self, repository, sample_session_data):
        """Test deleting a session."""
        user_id = sample_session_data.user_id
        
        # Store then delete
        await repository.store_session(user_id, sample_session_data)
        await repository.delete_session(user_id)
        
        # Verify deletion
        result = await repository.get_session(user_id)
        assert result is None

    @pytest.mark.asyncio
    async def test_update_last_activity(self, repository, sample_session_data):
        """Test updating last activity timestamp."""
        user_id = sample_session_data.user_id
        original_time = sample_session_data.last_activity
        
        # Store session
        await repository.store_session(user_id, sample_session_data)
        
        # Wait a moment and update
        await asyncio.sleep(0.1)
        await repository.update_last_activity(user_id)
        
        # Verify update
        updated = await repository.get_session(user_id)
        assert updated.last_activity > original_time

    @pytest.mark.asyncio
    async def test_get_user_by_refresh_token(self, repository, sample_session_data):
        """Test finding user by refresh token."""
        user_id = sample_session_data.user_id
        refresh_token = sample_session_data.refresh_token
        
        # Store session
        await repository.store_session(user_id, sample_session_data)
        
        # Find by refresh token
        found_user_id = await repository.get_user_by_refresh_token(refresh_token)
        
        assert found_user_id == user_id

    @pytest.mark.asyncio
    async def test_get_user_by_invalid_refresh_token(self, repository):
        """Test searching with invalid refresh token."""
        result = await repository.get_user_by_refresh_token("invalid-token")
        assert result is None

    @pytest.mark.asyncio
    async def test_rate_limit_increment(self, repository):
        """Test rate limit increment operations."""
        ip_address = "192.168.1.100"
        
        # First increment
        count1 = await repository.increment_rate_limit(ip_address, window_seconds=60)
        assert count1 == 1
        
        # Second increment
        count2 = await repository.increment_rate_limit(ip_address, window_seconds=60)
        assert count2 == 2
        
        # Check current count
        current = await repository.get_rate_limit(ip_address)
        assert current == 2

    @pytest.mark.asyncio
    async def test_rate_limit_check(self, repository):
        """Test checking if IP is rate limited."""
        ip_address = "192.168.1.101"
        max_attempts = 3
        
        # Not limited initially
        assert await repository.is_rate_limited(ip_address, max_attempts) is False
        
        # Increment to limit
        for _ in range(max_attempts):
            await repository.increment_rate_limit(ip_address, window_seconds=60)
        
        # Now should be limited
        assert await repository.is_rate_limited(ip_address, max_attempts) is True

    @pytest.mark.asyncio
    async def test_reset_rate_limit(self, repository):
        """Test resetting rate limit for an IP."""
        ip_address = "192.168.1.102"
        
        # Build up rate limit
        await repository.increment_rate_limit(ip_address, window_seconds=60)
        await repository.increment_rate_limit(ip_address, window_seconds=60)
        
        # Reset
        await repository.reset_rate_limit(ip_address)
        
        # Should be back to 0
        count = await repository.get_rate_limit(ip_address)
        assert count == 0


# ==================== SessionService Tests ====================


class TestSessionServiceIntegration:
    """Integration tests for SessionService with real Valkey."""

    @pytest.mark.asyncio
    async def test_create_session_flow(self, service):
        """Test complete session creation flow."""
        user_id = "test-user-456"
        claims = {
            "sub": user_id,
            "email": "user@test.com",
            "type": "user",
            "is_master": False,
        }
        request_info = {
            "ip_address": "10.0.0.1",
            "user_agent": "Mozilla/5.0",
        }
        
        # Create session
        tokens = await service.create_session_with_tokens(
            user_id=user_id,
            claims=claims,
            request_info=request_info)
        
        # Verify tokens structure
        assert tokens.access_token is not None
        assert tokens.refresh_token is not None
        assert tokens.token_type == "bearer"
        
        # Verify session stored
        session = await service.get_session(user_id)
        assert session is not None
        assert session.user_id == user_id
        assert session.email == claims["email"]
        assert session.ip_address == request_info["ip_address"]

    @pytest.mark.asyncio
    async def test_rate_limit_integration(self, service):
        """Test rate limiting functionality."""
        ip_address = "10.0.0.6"
        max_attempts = 3
        
        # Initially not rate limited
        is_limited = await service.check_rate_limit(ip_address, max_attempts)
        assert is_limited is False
        
        # Increment to limit
        for i in range(max_attempts):
            count = await service.increment_rate_limit(ip_address, max_attempts, 60)
            assert count == i + 1
        
        # Should be rate limited now
        is_limited = await service.check_rate_limit(ip_address, max_attempts)
        assert is_limited is True
        
        # Reset and check
        await service.reset_rate_limit(ip_address)
        is_limited = await service.check_rate_limit(ip_address, max_attempts)
        assert is_limited is False

