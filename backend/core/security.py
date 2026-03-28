"""Fernet encryption utility for protecting SIEM credentials at rest.

Usage:
    from backend.core.security import encrypt_value, decrypt_value
    encrypted = encrypt_value("my-secret-api-key")
    original = decrypt_value(encrypted)
"""
from __future__ import annotations

from cryptography.fernet import Fernet

from backend.config import settings

_fernet: Fernet | None = None


def _get_fernet() -> Fernet:
    """Lazily initialise Fernet cipher from ENCRYPTION_KEY setting."""
    global _fernet
    if _fernet is None:
        key = settings.ENCRYPTION_KEY
        if not key:
            raise RuntimeError(
                "ENCRYPTION_KEY is not set. Generate one with: "
                "python -c 'from cryptography.fernet import Fernet; print(Fernet.generate_key().decode())'"
            )
        _fernet = Fernet(key.encode() if isinstance(key, str) else key)
    return _fernet


def encrypt_value(plaintext: str) -> str:
    """Encrypt a string value and return the base64-encoded ciphertext."""
    f = _get_fernet()
    return f.encrypt(plaintext.encode()).decode()


def decrypt_value(ciphertext: str) -> str:
    """Decrypt a base64-encoded ciphertext back to the original string."""
    f = _get_fernet()
    return f.decrypt(ciphertext.encode()).decode()


def generate_key() -> str:
    """Generate a new Fernet key (for bootstrapping)."""
    return Fernet.generate_key().decode()
