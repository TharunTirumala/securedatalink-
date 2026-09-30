"""Custom error definitions for SecureLink protocol and pipeline."""


class SecureLinkError(Exception):
    """Base exception for all SecureLink errors."""
    pass


class FrameMalformedError(SecureLinkError):
    """Raised when incoming frame cannot be unpacked or has invalid length."""
    pass


class UnknownSenderError(SecureLinkError):
    """Raised when frame sender_id does not exist in the Keystore."""
    pass


class AeadDecryptionError(SecureLinkError):
    """Raised when AES-GCM tag mismatch occurs or ciphertext is corrupt."""
    pass


class SignatureVerificationError(SecureLinkError):
    """Raised when ECDSA signature verification fails."""
    pass


class ReplayError(SecureLinkError):
    """Raised when sequence number is replayed, out-of-order, or timestamp is stale."""
    pass


class EpochExhausted(SecureLinkError):
    """Raised when the V1 key_epoch counter exceeds 255 (1-byte limit).

    Callers should either switch to V3 (session_id != 0) or terminate the session.
    """
    pass
