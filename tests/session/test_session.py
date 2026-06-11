import base64
import secrets
from datetime import datetime, timedelta, timezone

import pytest
from jose.exceptions import JWEError

from app.shared.session.models import SessionData, SessionTokens, UserData
from app.shared.session.security import JWEHandler


@pytest.fixture
def encryption_key():
    return base64.b64encode(secrets.token_bytes(32)).decode()


@pytest.fixture
def jwe_handler(encryption_key):
    return JWEHandler(encryption_key)


@pytest.fixture
def sample_claims():
    return {
        "sub": "user-123",
        "email": "test@example.com",
        "type": "user",
        "is_master": False,
    }


class TestJWEHandler:
    def test_encrypt_creates_jwe_token(self, jwe_handler, sample_claims):
        token = jwe_handler.encrypt(sample_claims, ttl_minutes=30)
        
        assert isinstance(token, str)
        assert token.count(".") == 4

    def test_encrypt_adds_expiration(self, jwe_handler, sample_claims):
        token = jwe_handler.encrypt(sample_claims, ttl_minutes=30)
        claims = jwe_handler.decrypt(token)
        
        assert "exp" in claims
        assert "iat" in claims
        assert isinstance(claims["exp"], int)
        assert isinstance(claims["iat"], int)

    def test_decrypt_valid_token(self, jwe_handler, sample_claims):
        token = jwe_handler.encrypt(sample_claims, ttl_minutes=30)
        decrypted = jwe_handler.decrypt(token)
        
        assert decrypted["sub"] == sample_claims["sub"]
        assert decrypted["email"] == sample_claims["email"]
        assert decrypted["type"] == sample_claims["type"]

    def test_decrypt_invalid_token_raises_exception(self, jwe_handler):
        with pytest.raises(JWEError):
            jwe_handler.decrypt("invalid.token.here")
    
    def test_decrypt_expired_token_raises_exception(self, jwe_handler, sample_claims):
        # Create token that expires immediately
        token = jwe_handler.encrypt(sample_claims, ttl_minutes=-1)
        
        with pytest.raises(JWEError, match="Token has expired"):
            jwe_handler.decrypt(token)

    def test_verify_expiration_valid_token(self, jwe_handler):
        now = datetime.now(timezone.utc)
        future_exp = int((now + timedelta(minutes=30)).timestamp())
        claims = {"exp": future_exp}
        
        assert jwe_handler.verify_expiration(claims) is True

    def test_verify_expiration_expired_token(self, jwe_handler):
        now = datetime.now(timezone.utc)
        past_exp = int((now - timedelta(minutes=5)).timestamp())
        claims = {"exp": past_exp}
        
        assert jwe_handler.verify_expiration(claims) is False

    def test_verify_expiration_missing_exp(self, jwe_handler):
        claims = {}
        assert jwe_handler.verify_expiration(claims) is False

    def test_encrypt_decrypt_preserves_all_claims(self, jwe_handler):
        claims = {
            "sub": "user-123",
            "email": "test@example.com",
            "type": "administrator",
            "is_master": True,
            "custom_field": "custom_value",
        }
        
        token = jwe_handler.encrypt(claims, ttl_minutes=30)
        decrypted = jwe_handler.decrypt(token)
        
        for key in claims:
            assert decrypted[key] == claims[key]

    def test_encryption_key_validation(self):
        invalid_key = base64.b64encode(b"short").decode()
        
        with pytest.raises(ValueError, match="exactly 32 bytes"):
            JWEHandler(invalid_key)


class TestModels:
    def test_session_data_model(self):
        now = datetime.now(timezone.utc)
        data = SessionData(
            user_id="user-123",
            token_id="token-456",
            refresh_token="refresh-789",
            email="test@example.com",
            account_type="user",
            is_master=False,
            ip_address="127.0.0.1",
            user_agent="Mozilla/5.0",
            created_at=now,
            last_activity=now)
        
        assert data.user_id == "user-123"
        assert data.token_id == "token-456"
        assert data.email == "test@example.com"
        
        json_str = data.model_dump_json()
        assert isinstance(json_str, str)
        assert "user-123" in json_str

    def test_session_tokens_model(self):
        tokens = SessionTokens(
            access_token="eyJ...",
            refresh_token="abc123",
            token_type="bearer")
        
        assert tokens.access_token == "eyJ..."
        assert tokens.refresh_token == "abc123"
        assert tokens.token_type == "bearer"

    def test_user_data_model(self):
        user = UserData(
            user_id="user-123",
            email="test@example.com",
            account_type="administrator",
            is_master=True,
            token_id="token-456")
        
        assert user.user_id == "user-123"
        assert user.email == "test@example.com"
        assert user.account_type == "administrator"
        assert user.is_master is True
