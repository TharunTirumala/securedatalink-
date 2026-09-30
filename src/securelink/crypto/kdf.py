"""Key Derivation Functions using HKDF-SHA256 for dynamic per-sender, per-epoch keying."""

from typing import Tuple, Union
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF


def derive(
    master_secret: bytes,
    sender_id: Union[int, bytes],
    epoch: Union[int, bytes],
    session_id: int = 0,
) -> Tuple[bytes, bytes]:
    """Derive a 32-byte AES key and 4-byte session salt using HKDF-SHA256.

    info = b"securelink|" + sender_id + epoch [+ session_id if session_id != 0]
    session_id=0 gives byte-identical output to the original (V1 compatibility).
    Returns (aes_key: 32 bytes, session_salt: 4 bytes).
    """
    if not isinstance(master_secret, (bytes, bytearray)):
        raise TypeError("master_secret must be bytes")
    if len(master_secret) < 16:
        raise ValueError(f"master_secret must be at least 16 bytes, got {len(master_secret)}")

    sid_bytes = (
        sender_id.to_bytes(4, "big")
        if isinstance(sender_id, int)
        else bytes(sender_id)
    )
    epoch_bytes = (
        epoch.to_bytes(4, "big")
        if isinstance(epoch, int)
        else bytes(epoch)
    )
    info = b"securelink|" + sid_bytes + epoch_bytes
    if session_id != 0:
        info += session_id.to_bytes(4, "big")

    hkdf = HKDF(
        algorithm=hashes.SHA256(),
        length=36,
        salt=None,
        info=info,
    )
    okm = hkdf.derive(bytes(master_secret))
    aes_key = okm[:32]
    salt = okm[32:36]
    return aes_key, salt


derive_key_and_salt = derive


def key_id(
    master_secret: bytes,
    sender_id: Union[int, bytes],
    epoch: Union[int, bytes],
    session_id: int = 0,
) -> str:
    """Compute an 8-character hex identifier for a (sender_id, epoch[, session_id]) key.

    Uses an independent domain-separated HKDF info label (b"securelink|kid|")
    so it cannot be inverted or used to deduce the derived cryptographic key.
    """
    if not isinstance(master_secret, (bytes, bytearray)):
        raise TypeError("master_secret must be bytes")
    sid_bytes = (
        sender_id.to_bytes(4, "big")
        if isinstance(sender_id, int)
        else bytes(sender_id)
    )
    epoch_bytes = (
        epoch.to_bytes(4, "big")
        if isinstance(epoch, int)
        else bytes(epoch)
    )
    info = b"securelink|kid|" + sid_bytes + epoch_bytes
    if session_id != 0:
        info += session_id.to_bytes(4, "big")
    hkdf = HKDF(
        algorithm=hashes.SHA256(),
        length=4,
        salt=None,
        info=info,
    )
    return hkdf.derive(bytes(master_secret)).hex()
