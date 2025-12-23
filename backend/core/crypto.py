from __future__ import annotations

import base64
import hashlib

from cryptography.fernet import Fernet

from core.settings import settings


def _fernet() -> Fernet:
    # Fernet requires a 32-byte urlsafe base64 key
    digest = hashlib.sha256(settings.api_secret_key.encode("utf-8")).digest()
    key = base64.urlsafe_b64encode(digest)
    return Fernet(key)


def encrypt_text(plaintext: str) -> str:
    return _fernet().encrypt(plaintext.encode("utf-8")).decode("utf-8")


def decrypt_text(ciphertext: str) -> str:
    return _fernet().decrypt(ciphertext.encode("utf-8")).decode("utf-8")
