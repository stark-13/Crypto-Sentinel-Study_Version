"""
Symmetric encryption and decryption using AES-256-GCM with PBKDF2 key derivation.

Format of the output (base64-encoded):
    [salt: 16 bytes][nonce: 12 bytes][ciphertext + tag: variable]

The salt is random per encryption. The nonce is random per encryption.
The ciphertext includes the 16-byte GCM authentication tag.
"""

import os
import base64
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives.ciphers.aead import AESGCM


# OWASP 2023 recommendation for PBKDF2-HMAC-SHA256
PBKDF2_ITERATIONS = 600_000
SALT_SIZE = 16      # bytes
NONCE_SIZE = 12     # bytes, 96-bit for GCM
KEY_SIZE = 32       # bytes, 256-bit for AES-256


def _derive_key(password: str, salt: bytes) -> bytes:
    """Derive a 256-bit key from a password and salt using PBKDF2-HMAC-SHA256."""
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=KEY_SIZE,
        salt=salt,
        iterations=PBKDF2_ITERATIONS,
    )
    return kdf.derive(password.encode("utf-8"))


def encrypt(plaintext: str, password: str) -> str:
    """
    Encrypt a plaintext string with a password.

    Returns a base64-encoded string containing salt + nonce + ciphertext+tag.
    """
    if not plaintext:
        raise ValueError("Plaintext cannot be empty.")
    if not password:
        raise ValueError("Password cannot be empty.")

    salt = os.urandom(SALT_SIZE)
    nonce = os.urandom(NONCE_SIZE)
    key = _derive_key(password, salt)

    aesgcm = AESGCM(key)
    ciphertext = aesgcm.encrypt(nonce, plaintext.encode("utf-8"), None)

    # Concatenate: salt || nonce || ciphertext+tag
    payload = salt + nonce + ciphertext
    return base64.b64encode(payload).decode("ascii")


def decrypt(encoded: str, password: str) -> str:
    """
    Decrypt a base64-encoded string with a password.

    Raises ValueError if the password is wrong or the data is corrupted.
    """
    if not encoded:
        raise ValueError("Encrypted input cannot be empty.")
    if not password:
        raise ValueError("Password cannot be empty.")

    try:
        payload = base64.b64decode(encoded)
    except Exception as exc:
        raise ValueError("Invalid base64 encoding.") from exc

    if len(payload) < SALT_SIZE + NONCE_SIZE + 16:  # 16 = GCM tag minimum
        raise ValueError("Encrypted data is too short or corrupted.")

    salt = payload[:SALT_SIZE]
    nonce = payload[SALT_SIZE:SALT_SIZE + NONCE_SIZE]
    ciphertext = payload[SALT_SIZE + NONCE_SIZE:]

    key = _derive_key(password, salt)
    aesgcm = AESGCM(key)

    try:
        plaintext = aesgcm.decrypt(nonce, ciphertext, None)
    except Exception as exc:
        raise ValueError(
            "Decryption failed. Wrong password or corrupted data."
        ) from exc

    return plaintext.decode("utf-8")