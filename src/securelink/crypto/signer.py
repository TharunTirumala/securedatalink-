"""ECDSA P-256 digital signature creation and verification (IEEE P1363 64-byte format)."""

from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric.utils import (
    decode_dss_signature,
    encode_dss_signature,
)
from cryptography.hazmat.primitives import hashes
from cryptography.exceptions import InvalidSignature
from securelink.core.errors import SignatureVerificationError
from securelink.protocol.constants import SIGNATURE_SIZE


SECP256R1_ORDER = 0xFFFFFFFF00000000FFFFFFFFFFFFFFFFBCE6FAADA7179E84F3B9CAC2FC632551
SECP256R1_HALF_ORDER = SECP256R1_ORDER // 2


def sign_p256(private_key: ec.EllipticCurvePrivateKey, data: bytes) -> bytes:
    """Sign data using ECDSA P-256 / SHA-256 and return raw canonical 64-byte signature (r || s)."""
    der_signature = private_key.sign(data, ec.ECDSA(hashes.SHA256()))
    r, s = decode_dss_signature(der_signature)
    # Enforce canonical low-S (BIP-62 / RFC 6979)
    if s > SECP256R1_HALF_ORDER:
        s = SECP256R1_ORDER - s

    r_bytes = r.to_bytes(32, byteorder="big")
    s_bytes = s.to_bytes(32, byteorder="big")
    raw_sig = r_bytes + s_bytes
    if len(raw_sig) != SIGNATURE_SIZE:
        raise ValueError(f"Generated signature length {len(raw_sig)} != {SIGNATURE_SIZE}")
    return raw_sig


def verify_p256(public_key: ec.EllipticCurvePublicKey, signature: bytes, data: bytes) -> bool:
    """Verify raw 64-byte ECDSA P-256 signature over data with low-s canonical enforcement.

    Raises SignatureVerificationError if signature is invalid, malleable, or corrupted.
    """
    if len(signature) != SIGNATURE_SIZE:
        raise SignatureVerificationError(
            f"Signature must be exactly {SIGNATURE_SIZE} bytes, got {len(signature)}"
        )

    r = int.from_bytes(signature[:32], byteorder="big")
    s = int.from_bytes(signature[32:], byteorder="big")

    # Reject malleable high-S signatures
    if s > SECP256R1_HALF_ORDER:
        raise SignatureVerificationError("High-S signature rejected (ECDSA malleability mitigation)")

    try:
        der_signature = encode_dss_signature(r, s)
        public_key.verify(der_signature, data, ec.ECDSA(hashes.SHA256()))
        return True
    except (InvalidSignature, ValueError) as e:
        raise SignatureVerificationError("ECDSA signature verification failed") from e

