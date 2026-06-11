"""Password hashing for the E2E session protocol.

SEC-001: Passwords are stored as hash_password(plain, salt) = sha256(salt + sha256(password)).
         Each user has an independent random salt so a DB compromise cannot
         use a precomputed rainbow table.
"""

from app.shared.crypto import generate_salt, hash_password, verify_password


def get_password_hash(password: str) -> tuple[str, str]:
    """Return (password_hash, salt) for a new credential.

    Callers that need only the hash (e.g. seed scripts) should unpack both
    values and persist the salt alongside the hash.
    """
    salt = generate_salt()
    return hash_password(password, salt), salt


def check_password(plain_password: str, salt: str, stored_hash: str) -> bool:
    """Constant-time password check (SEC-001 + SEC-002)."""
    return verify_password(plain_password, salt, stored_hash)
