"""Cryptographic primitives for the E2E session protocol.

SEC-003: AES-256-GCM replaces AES-256-CBC — adds authentication tag, eliminates
         bit-flip malleability.  IV is 12 bytes (GCM standard).
SEC-004: HKDF-SHA256 replaces ad-hoc sha256(r2+r3) for session-key derivation —
         proper key separation via domain-separated info string.
SEC-001: Per-user password salt stored alongside the hash — prevents rainbow-table
         attacks on the password_hash column.
"""

import hashlib
import hmac as _hmac
import os
import secrets

from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives import hashes

_GCM_NONCE_BYTES = 12  # 96-bit nonce required by AES-GCM
_HKDF_HASH = hashes.SHA256()
_HKDF_LENGTH = 32  # 256-bit session key


# ── SHA-256 helpers (still used for password hashing) ─────────────────────────

def sha256_hex(data: str | bytes) -> str:
    """Return the SHA-256 hex digest of *data*."""
    if isinstance(data, str):
        data = data.encode("utf-8")
    return hashlib.sha256(data).hexdigest()


def sha256_bytes(data: str | bytes) -> bytes:
    """Return the raw 32-byte SHA-256 digest of *data*."""
    if isinstance(data, str):
        data = data.encode("utf-8")
    return hashlib.sha256(data).digest()


# ── Password salting (SEC-001) ─────────────────────────────────────────────────

def generate_salt() -> str:
    """Return a 32-hex-character random salt."""
    return secrets.token_hex(16)


def hash_password(plain_password: str, salt: str) -> str:
    """Return sha256(salt + sha256(password)) as a hex string.

    The outer hash binds the salt; the inner hash is what the E2E client
    computes locally (so the wire protocol only sends sha256(password), and
    the server applies the salt internally).
    """
    inner = sha256_hex(plain_password)
    return sha256_hex(salt + inner)


def verify_password(plain_password: str, salt: str, stored_hash: str) -> bool:
    """Constant-time password verification."""
    expected = hash_password(plain_password, salt)
    return _hmac.compare_digest(expected, stored_hash)


# ── Key derivation (SEC-004: HKDF) ────────────────────────────────────────────

def derive_temp_key(password_sha256_hex: str, random_hex: str, salt: str) -> bytes:
    """Derive the ephemeral AES-256 key used during the login handshake.

    Uses HKDF-SHA256 with the salt stored per user so the derived key is
    fully domain-separated from the session key.

    Args:
        password_sha256_hex: sha256(plain_password) — sent by the client.
        random_hex: server nonce from the /auth/challenge response.
        salt: per-user password salt retrieved from the DB.
    """
    ikm = (password_sha256_hex + random_hex).encode("utf-8")
    return HKDF(
        algorithm=_HKDF_HASH,
        length=_HKDF_LENGTH,
        salt=salt.encode("utf-8"),
        info=b"iotmx-temp-key-v2",
    ).derive(ikm)


def derive_session_key(random2: str, random3: str) -> bytes:
    """Derive the session AES-256 key via HKDF-SHA256 (SEC-004).

    Args:
        random2: server-side random hex from the login response.
        random3: client-side random hex from the login body.
    """
    ikm = (random2 + random3).encode("utf-8")
    return HKDF(
        algorithm=_HKDF_HASH,
        length=_HKDF_LENGTH,
        salt=None,
        info=b"iotmx-session-key-v2",
    ).derive(ikm)


# ── AES-256-GCM encryption (SEC-003) ──────────────────────────────────────────

def aes_encrypt(plaintext: bytes, key: bytes, iv: bytes | None = None) -> tuple[bytes, bytes]:
    """AES-256-GCM encrypt *plaintext* with *key*.

    Returns:
        (ciphertext_with_tag, nonce) — the 16-byte authentication tag is appended
        to the ciphertext by cryptography's AESGCM implementation.
    """
    if iv is None:
        iv = os.urandom(_GCM_NONCE_BYTES)
    aesgcm = AESGCM(key)
    ciphertext = aesgcm.encrypt(iv, plaintext, None)
    return ciphertext, iv


def aes_decrypt(ciphertext: bytes, key: bytes, iv: bytes) -> bytes:
    """AES-256-GCM decrypt and authenticate *ciphertext* with *key* and *nonce*.

    Raises:
        cryptography.exceptions.InvalidTag: if the authentication tag is wrong
            (tampered ciphertext, wrong key, or wrong nonce).
    """
    aesgcm = AESGCM(key)
    return aesgcm.decrypt(iv, ciphertext, None)
