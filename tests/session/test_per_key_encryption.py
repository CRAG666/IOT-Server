"""
Tests for per-key encryption session management (entity sessions).

Tests the three main processes:
1. check_active_session - verify session existence by entity UUID
2. create_entity_session - create session with key_session + metadata
3. process_encrypted_request - verify HMAC and return key_session

Plus: invalidate_entity_session (logout) and validation helpers.
"""

import base64
import secrets
from uuid import UUID, uuid4

import fakeredis
import pytest

from app.shared.session.exceptions import (
    InvalidEntityIdException,
    InvalidIpAddressException,
    InvalidKeySessionException,
    InvalidMetadataException,
    InvalidTagException,
    SessionAlreadyExistsException,
    SessionNotFoundException)
from app.shared.session.repository import SessionRepository
from app.shared.session.security import SessionHMAC
from app.shared.session.service import SessionService


TEST_ENCRYPTION_KEY = "MDEyMzQ1Njc4OWFiY2RlZjAxMjM0NTY3ODlhYmNkZWY="


@pytest.fixture
async def valkey_client():
    client = fakeredis.FakeAsyncValkey(decode_responses=True)
    yield client
    await client.flushall()
    await client.aclose()


@pytest.fixture
async def repository(valkey_client):
    repo = SessionRepository("valkey://localhost:6379/1")
    repo.client = valkey_client
    yield repo


@pytest.fixture
async def service(valkey_client):
    svc = SessionService(encryption_key=TEST_ENCRYPTION_KEY)
    repo = SessionRepository("valkey://localhost:6379/1")
    repo.client = valkey_client
    svc._repository = repo
    yield svc


@pytest.fixture
def key_session() -> str:
    return base64.urlsafe_b64encode(secrets.token_bytes(32)).decode()


@pytest.fixture
def entity_id() -> UUID:
    return uuid4()


# ==============================================================
# Function 1: check_active_session
# ==============================================================


class TestCheckActiveSession:
    @pytest.mark.asyncio
    async def test_returns_false_when_no_session(self, service, entity_id):
        assert await service.check_active_session(entity_id) is False

    @pytest.mark.asyncio
    async def test_returns_true_after_create(self, service, entity_id, key_session):
        await service.create_entity_session(
            entity_id=entity_id,
            key_session=key_session,
            ip_address="192.168.1.1")
        assert await service.check_active_session(entity_id) is True

    @pytest.mark.asyncio
    async def test_independent_entities(self, service, key_session):
        a, b = uuid4(), uuid4()
        await service.create_entity_session(
            entity_id=a,
            key_session=key_session,
            ip_address="192.168.1.1")
        assert await service.check_active_session(a) is True
        assert await service.check_active_session(b) is False

    @pytest.mark.asyncio
    async def test_invalid_entity_id_raises(self, service):
        with pytest.raises(InvalidEntityIdException):
            await service.check_active_session("not-a-uuid")


# ==============================================================
# Function 2: create_entity_session
# ==============================================================


class TestCreateEntitySession:
    @pytest.mark.asyncio
    async def test_returns_session_id(self, service, entity_id, key_session):
        result = await service.create_entity_session(
            entity_id=entity_id,
            key_session=key_session,
            ip_address="192.168.1.1")
        assert result.session_id
        assert len(result.session_id) >= 32
        assert not hasattr(result, "encrypted_token")

    @pytest.mark.asyncio
    async def test_stores_in_valkey(self, service, repository, entity_id, key_session):
        await service.create_entity_session(
            entity_id=entity_id,
            key_session=key_session,
            ip_address="10.0.0.1")
        stored = await repository.get_entity_session(str(entity_id))
        assert stored is not None
        assert stored.entity_id == str(entity_id)
        assert stored.key_session == key_session
        assert stored.ip_address == "10.0.0.1"
        assert stored.metadata == {}

    @pytest.mark.asyncio
    async def test_stores_metadata(self, service, repository, entity_id, key_session):
        metadata = {"firmware": "1.2.3", "model": "RPi4"}
        await service.create_entity_session(
            entity_id=entity_id,
            key_session=key_session,
            ip_address="10.0.0.1",
            metadata=metadata)
        stored = await repository.get_entity_session(str(entity_id))
        assert stored.metadata == metadata

    @pytest.mark.asyncio
    async def test_reverse_index_created(self, service, repository, entity_id, key_session):
        result = await service.create_entity_session(
            entity_id=entity_id,
            key_session=key_session,
            ip_address="10.0.0.1")
        found = await repository.get_entity_session_by_id(result.session_id)
        assert found is not None
        assert found.entity_id == str(entity_id)

    @pytest.mark.asyncio
    async def test_unique_session_ids(self, service, key_session):
        a, b = uuid4(), uuid4()
        r1 = await service.create_entity_session(a, key_session, "1.1.1.1")
        r2 = await service.create_entity_session(b, key_session, "1.1.1.2")
        assert r1.session_id != r2.session_id

    @pytest.mark.asyncio
    async def test_guard_prevents_duplicate_session(self, service, entity_id, key_session):
        await service.create_entity_session(entity_id, key_session, "1.1.1.1")
        with pytest.raises(SessionAlreadyExistsException):
            await service.create_entity_session(entity_id, key_session, "1.1.1.1")

    @pytest.mark.asyncio
    async def test_invalid_entity_id_raises(self, service, key_session):
        with pytest.raises(InvalidEntityIdException):
            await service.create_entity_session("not-a-uuid", key_session, "1.1.1.1")

    @pytest.mark.asyncio
    async def test_empty_key_session_raises(self, service, entity_id):
        with pytest.raises(InvalidKeySessionException):
            await service.create_entity_session(entity_id, "", "1.1.1.1")

    @pytest.mark.asyncio
    async def test_wrong_length_key_raises(self, service, entity_id):
        short_key = base64.urlsafe_b64encode(secrets.token_bytes(16)).decode()
        with pytest.raises(InvalidKeySessionException):
            await service.create_entity_session(entity_id, short_key, "1.1.1.1")

    @pytest.mark.asyncio
    async def test_invalid_base64_key_raises(self, service, entity_id):
        with pytest.raises(InvalidKeySessionException):
            await service.create_entity_session(entity_id, "not!!base64!!", "1.1.1.1")

    @pytest.mark.asyncio
    async def test_empty_ip_raises(self, service, entity_id, key_session):
        with pytest.raises(InvalidIpAddressException):
            await service.create_entity_session(entity_id, key_session, "")

    @pytest.mark.asyncio
    async def test_invalid_ip_format_raises(self, service, entity_id, key_session):
        with pytest.raises(InvalidIpAddressException):
            await service.create_entity_session(entity_id, key_session, "999.999.999.999")

    @pytest.mark.asyncio
    async def test_metadata_forbidden_key_raises(
        self, service, entity_id, key_session
    ):
        with pytest.raises(InvalidMetadataException):
            await service.create_entity_session(
                entity_id,
                key_session,
                "1.1.1.1",
                metadata={"password": "secret"})

    @pytest.mark.asyncio
    async def test_metadata_too_many_keys_raises(
        self, service, entity_id, key_session
    ):
        too_many = {f"k{i}": i for i in range(51)}
        with pytest.raises(InvalidMetadataException):
            await service.create_entity_session(
                entity_id, key_session, "1.1.1.1", metadata=too_many
            )

    @pytest.mark.asyncio
    async def test_metadata_too_large_raises(self, service, entity_id, key_session):
        huge = {"blob": "x" * 5000}
        with pytest.raises(InvalidMetadataException):
            await service.create_entity_session(
                entity_id, key_session, "1.1.1.1", metadata=huge
            )


# ==============================================================
# Function 3: process_encrypted_request
# ==============================================================


class TestProcessEncryptedRequest:
    @pytest.mark.asyncio
    async def test_valid_request_returns_key(self, service, entity_id, key_session):
        result = await service.create_entity_session(
            entity_id, key_session, "1.1.1.1"
        )
        payload = "encrypted_body"
        tag = SessionHMAC.compute_hmac(result.session_id, payload, key_session)

        returned_key = await service.process_encrypted_request(
            session_id=result.session_id,
            tag=tag,
            payload=payload)
        assert returned_key == key_session

    @pytest.mark.asyncio
    async def test_invalid_tag_raises(self, service, entity_id, key_session):
        result = await service.create_entity_session(
            entity_id, key_session, "1.1.1.1"
        )
        with pytest.raises(InvalidTagException):
            await service.process_encrypted_request(
                session_id=result.session_id,
                tag="invalid_tag",
                payload="whatever")

    @pytest.mark.asyncio
    async def test_nonexistent_session_raises(self, service, key_session):
        tag = SessionHMAC.compute_hmac("fake_sid", "payload", key_session)
        with pytest.raises(SessionNotFoundException):
            await service.process_encrypted_request(
                session_id="fake_sid",
                tag=tag,
                payload="payload")

    @pytest.mark.asyncio
    async def test_modified_payload_rejected(self, service, entity_id, key_session):
        result = await service.create_entity_session(
            entity_id, key_session, "1.1.1.1"
        )
        tag = SessionHMAC.compute_hmac(result.session_id, "original", key_session)
        with pytest.raises(InvalidTagException):
            await service.process_encrypted_request(
                session_id=result.session_id,
                tag=tag,
                payload="modified")

    @pytest.mark.asyncio
    async def test_tag_cross_session_rejected(self, service, key_session):
        a, b = uuid4(), uuid4()
        key_b = base64.urlsafe_b64encode(secrets.token_bytes(32)).decode()
        r1 = await service.create_entity_session(a, key_session, "1.1.1.1")
        r2 = await service.create_entity_session(b, key_b, "1.1.1.2")

        tag_for_r1 = SessionHMAC.compute_hmac(r1.session_id, "payload", key_session)
        with pytest.raises(InvalidTagException):
            await service.process_encrypted_request(
                session_id=r2.session_id,
                tag=tag_for_r1,
                payload="payload")

    @pytest.mark.asyncio
    async def test_empty_params_raise(self, service):
        with pytest.raises(InvalidTagException):
            await service.process_encrypted_request("", "tag", "payload")
        with pytest.raises(InvalidTagException):
            await service.process_encrypted_request("sid", "", "payload")
        with pytest.raises(InvalidTagException):
            await service.process_encrypted_request("sid", "tag", "")

    @pytest.mark.asyncio
    async def test_updates_last_activity(
        self, service, repository, entity_id, key_session
    ):
        result = await service.create_entity_session(
            entity_id, key_session, "1.1.1.1"
        )
        before = await repository.get_entity_session(str(entity_id))

        payload = "x"
        tag = SessionHMAC.compute_hmac(result.session_id, payload, key_session)
        await service.process_encrypted_request(result.session_id, tag, payload)

        after = await repository.get_entity_session(str(entity_id))
        assert after.last_activity >= before.last_activity


# ==============================================================
# Invalidate (logout)
# ==============================================================


class TestInvalidateEntitySession:
    @pytest.mark.asyncio
    async def test_invalidate_removes_session(
        self, service, repository, entity_id, key_session
    ):
        result = await service.create_entity_session(
            entity_id, key_session, "1.1.1.1"
        )
        assert await service.check_active_session(entity_id) is True

        await service.invalidate_entity_session(entity_id)

        assert await service.check_active_session(entity_id) is False
        assert await repository.get_entity_session(str(entity_id)) is None
        assert await repository.get_entity_session_by_id(result.session_id) is None

    @pytest.mark.asyncio
    async def test_invalidate_missing_is_idempotent(self, service, entity_id):
        await service.invalidate_entity_session(entity_id)
        await service.invalidate_entity_session(entity_id)

    @pytest.mark.asyncio
    async def test_after_invalidate_can_create_again(
        self, service, entity_id, key_session
    ):
        await service.create_entity_session(entity_id, key_session, "1.1.1.1")
        await service.invalidate_entity_session(entity_id)
        await service.create_entity_session(entity_id, key_session, "1.1.1.1")
        assert await service.check_active_session(entity_id) is True


# ==============================================================
# HMAC static helpers (security.py)
# ==============================================================


class TestSessionHMAC:
    def test_compute_hmac_deterministic(self, key_session):
        a = SessionHMAC.compute_hmac("sid", "payload", key_session)
        b = SessionHMAC.compute_hmac("sid", "payload", key_session)
        assert a == b

    def test_compute_hmac_differs_by_payload(self, key_session):
        a = SessionHMAC.compute_hmac("sid", "p1", key_session)
        b = SessionHMAC.compute_hmac("sid", "p2", key_session)
        assert a != b

    def test_compute_hmac_differs_by_session_id(self, key_session):
        a = SessionHMAC.compute_hmac("sid1", "p", key_session)
        b = SessionHMAC.compute_hmac("sid2", "p", key_session)
        assert a != b

    def test_verify_hmac_accepts_valid(self, key_session):
        tag = SessionHMAC.compute_hmac("sid", "p", key_session)
        assert SessionHMAC.verify_hmac("sid", "p", tag, key_session) is True

    def test_verify_hmac_rejects_invalid(self, key_session):
        assert SessionHMAC.verify_hmac("sid", "p", "bad", key_session) is False

    def test_verify_hmac_rejects_modified_payload(self, key_session):
        tag = SessionHMAC.compute_hmac("sid", "original", key_session)
        assert SessionHMAC.verify_hmac("sid", "modified", tag, key_session) is False
