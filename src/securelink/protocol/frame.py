"""Frame representation and helpers."""

from securelink.core.types import Header, SecureFrame



def create_frame(header: Header, ciphertext_with_tag: bytes, signature: bytes) -> SecureFrame:
    """Helper to instantiate a SecureFrame."""
    return SecureFrame(
        header=header,
        ciphertext_with_tag=ciphertext_with_tag,
        signature=signature,
    )
