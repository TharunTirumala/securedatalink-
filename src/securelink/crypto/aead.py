"""Authenticated Encryption with Associated Data (AEAD) using AES-256-GCM."""

from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.exceptions import InvalidTag
from securelink.core.errors import AeadDecryptionError


_CIPHER_CACHE = {}


def _get_aesgcm(key: bytes) -> AESGCM:
    cipher = _CIPHER_CACHE.get(key)
    if cipher is None:
        if len(key) != 32:
            raise ValueError(f"AES-256 requires a 32-byte key, got {len(key)}")
        cipher = AESGCM(key)
        _CIPHER_CACHE[key] = cipher
    return cipher


def encrypt_gcm(key: bytes, nonce: bytes, plaintext: bytes, aad: bytes) -> bytes:
    """Encrypt plaintext using AES-256-GCM with associated data.

    Returns ciphertext concatenated with 16-byte authentication tag.
    """
    aesgcm = _get_aesgcm(key)
    return aesgcm.encrypt(nonce, plaintext, aad)


def decrypt_gcm(key: bytes, nonce: bytes, ciphertext_with_tag: bytes, aad: bytes) -> bytes:
    """Decrypt ciphertext and verify 16-byte authentication tag with associated data.

    Raises AeadDecryptionError if ciphertext is modified or tag check fails.
    """
    aesgcm = _get_aesgcm(key)
    try:
        return aesgcm.decrypt(nonce, ciphertext_with_tag, aad)
    except InvalidTag as e:
        raise AeadDecryptionError("AES-GCM authentication tag mismatch or corrupted ciphertext") from e

