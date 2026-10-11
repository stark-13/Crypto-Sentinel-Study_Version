"""
Tests for core.crypto - AES-256-GCM + PBKDF2.
We monkeypatch PBKDF2_ITERATIONS down to 1000 so tests run fast.
"""

import base64

import pytest

from core import crypto


@pytest.fixture(autouse=True)
def fast_pbkdf2(monkeypatch):
    monkeypatch.setattr(crypto, "PBKDF2_ITERATIONS", 1000)


# --- Round trip ---

def test_encrypt_decrypt_roundtrip():
    plaintext = "Hello, world! Unicode: cafe \u2014 password \U0001f510"
    password = "test-password-123"
    ciphertext = crypto.encrypt(plaintext, password)
    assert ciphertext != plaintext
    assert crypto.decrypt(ciphertext, password) == plaintext


def test_encrypt_produces_unique_ciphertexts():
    # Same input, same password -> different output, because salt and nonce are random.
    c1 = crypto.encrypt("same message", "same password")
    c2 = crypto.encrypt("same message", "same password")
    assert c1 != c2


# --- Error handling ---

def test_decrypt_wrong_password_raises():
    ciphertext = crypto.encrypt("secret", "correct")
    with pytest.raises(ValueError, match="Decryption failed"):
        crypto.decrypt(ciphertext, "wrong")


def test_decrypt_tampered_ciphertext_raises():
    ciphertext = crypto.encrypt("secret", "pass")
    raw = bytearray(base64.b64decode(ciphertext))
    raw[-1] ^= 0xFF  # flip last byte of the tag
    tampered = base64.b64encode(bytes(raw)).decode("ascii")
    with pytest.raises(ValueError, match="Decryption failed"):
        crypto.decrypt(tampered, "pass")


def test_decrypt_invalid_base64_raises():
    with pytest.raises(ValueError, match="Invalid base64"):
        crypto.decrypt("not!valid@base64#", "password")


def test_decrypt_too_short_raises():
    # 5 bytes of valid base64 - shorter than the header
    payload = base64.b64encode(b"\x00\x01\x02\x03\x04").decode("ascii")
    with pytest.raises(ValueError, match="too short"):
        crypto.decrypt(payload, "password")


# --- Input validation ---

def test_encrypt_empty_plaintext_raises():
    with pytest.raises(ValueError):
        crypto.encrypt("", "password")


def test_encrypt_empty_password_raises():
    with pytest.raises(ValueError):
        crypto.encrypt("plaintext", "")


def test_decrypt_empty_inputs_raise():
    with pytest.raises(ValueError):
        crypto.decrypt("", "password")
    with pytest.raises(ValueError):
        crypto.decrypt("AAAA", "")