"""Deterministic nonce generator for SecureLink AEAD."""

import struct
import secrets
from securelink.core.errors import SecureLinkError
from securelink.protocol.constants import SALT_SIZE, NONCE_SIZE


def generate_session_salt() -> bytes:
    """Generate a random 4-byte session salt for a run."""
    return secrets.token_bytes(SALT_SIZE)


def build_nonce(session_salt: bytes, seq: int) -> bytes:
    """Construct a 12-byte deterministic nonce.

    Nonce = 4 bytes session salt + 8 bytes uint64 sequence number.
    Strictly forbids random nonces to eliminate nonce collision risk.
    """
    if len(session_salt) != SALT_SIZE:
        raise SecureLinkError(
            f"Session salt must be exactly {SALT_SIZE} bytes, got {len(session_salt)}"
        )
    if seq < 0 or seq > 0xFFFFFFFFFFFFFFFF:
        raise SecureLinkError(f"Sequence number {seq} out of 64-bit uint range")

    seq_bytes = struct.pack(">Q", seq)
    nonce = session_salt + seq_bytes
    if len(nonce) != NONCE_SIZE:
        raise SecureLinkError(f"Built nonce size {len(nonce)} != {NONCE_SIZE}")
    return nonce
