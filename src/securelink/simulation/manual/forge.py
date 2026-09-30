"""Independent attacker frame forgery for File Lab.

This module intentionally uses its own ephemeral keys and random bytes.
It NEVER imports from crypto/keystore.py, crypto/kdf.py, crypto/aead.py, or pipeline/rx_pipeline.py.
"""

import os
import time
import struct
from typing import Tuple
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric.utils import decode_dss_signature
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from securelink.protocol.constants import PROTOCOL_VERSION, HEADER_FORMAT


def forge_frame(
    mode: str = "forged_valid_format",
    sender_id: int = 999,
    epoch: int = 1,
    seq: int = 1,
    timestamp: float = None,
) -> bytes:
    """Forge a frame using independent adversary cryptographic material."""
    if mode == "random_bytes":
        return os.urandom(128)

    # mode == "forged_valid_format"
    ts = timestamp if timestamp is not None else time.time()
    header_bytes = struct.pack(HEADER_FORMAT, PROTOCOL_VERSION, sender_id, epoch, seq, ts)

    payload = b'{"msg":"forged_payload","attacker":true}'
    random_salt = os.urandom(4)
    nonce = random_salt + struct.pack(">Q", seq)

    # Independent attacker AES key
    adversary_aes_key = os.urandom(32)
    aesgcm = AESGCM(adversary_aes_key)
    ciphertext_with_tag = aesgcm.encrypt(nonce, payload, header_bytes)

    # Independent attacker ECDSA keypair
    adversary_priv = ec.generate_private_key(ec.SECP256R1())
    data_to_sign = header_bytes + payload
    der_sig = adversary_priv.sign(data_to_sign, ec.ECDSA(hashes.SHA256()))
    r, s = decode_dss_signature(der_sig)
    sig_bytes = r.to_bytes(32, byteorder="big") + s.to_bytes(32, byteorder="big")

    return header_bytes + ciphertext_with_tag + sig_bytes
