"""Binary serialization and deserialization for SecureLink frames."""

import struct
from securelink.core.types import Header, SecureFrame
from securelink.core.errors import FrameMalformedError
from securelink.protocol.constants import (
    HEADER_FORMAT_V1,
    HEADER_FORMAT_V2,
    HEADER_FORMAT_V3,
    HEADER_SIZE_V1,
    HEADER_SIZE_V2,
    HEADER_SIZE_V3,
    PROTOCOL_VERSION_V1,
    PROTOCOL_VERSION_V2,
    PROTOCOL_VERSION_V3,
    SIGNATURE_SIZE,
    TAG_SIZE,
    MIN_FRAME_SIZE,
)


def pack_header(header: Header) -> bytes:
    """Pack Header dataclass into big-endian bytes (20B V1, 24B V2, 25B V3)."""
    if header.version == PROTOCOL_VERSION_V3:
        return struct.pack(
            HEADER_FORMAT_V3,
            header.version,
            header.sender_id,
            header.key_epoch,
            header.session_id,
            header.seq,
            header.timestamp,
        )
    if header.version == PROTOCOL_VERSION_V2:
        return struct.pack(
            HEADER_FORMAT_V2,
            header.version,
            header.sender_id,
            header.key_epoch,
            header.session_id,
            header.seq,
            header.timestamp,
        )
    return struct.pack(
        HEADER_FORMAT_V1,
        header.version,
        header.sender_id,
        header.key_epoch,
        header.seq,
        header.timestamp,
    )


def unpack_header(data: bytes) -> Header:
    """Unpack big-endian bytes into Header dataclass (supports V1, V2, V3)."""
    if len(data) < 1:
        raise FrameMalformedError("Header data empty")
    ver = data[0]
    try:
        if ver == PROTOCOL_VERSION_V3:
            if len(data) < HEADER_SIZE_V3:
                raise FrameMalformedError(
                    f"V3 Header data too short: {len(data)} bytes (expected {HEADER_SIZE_V3})"
                )
            version, sender_id, key_epoch, session_id, seq, timestamp = struct.unpack(
                HEADER_FORMAT_V3, data[:HEADER_SIZE_V3]
            )
            return Header(
                version=version,
                sender_id=sender_id,
                key_epoch=key_epoch,
                seq=seq,
                timestamp=timestamp,
                session_id=session_id,
            )
        elif ver == PROTOCOL_VERSION_V2:
            if len(data) < HEADER_SIZE_V2:
                raise FrameMalformedError(
                    f"V2 Header data too short: {len(data)} bytes (expected {HEADER_SIZE_V2})"
                )
            version, sender_id, key_epoch, session_id, seq, timestamp = struct.unpack(
                HEADER_FORMAT_V2, data[:HEADER_SIZE_V2]
            )
            return Header(
                version=version,
                sender_id=sender_id,
                key_epoch=key_epoch,
                seq=seq,
                timestamp=timestamp,
                session_id=session_id,
            )
        elif ver == PROTOCOL_VERSION_V1:
            if len(data) < HEADER_SIZE_V1:
                raise FrameMalformedError(
                    f"V1 Header data too short: {len(data)} bytes (expected {HEADER_SIZE_V1})"
                )
            version, sender_id, key_epoch, seq, timestamp = struct.unpack(
                HEADER_FORMAT_V1, data[:HEADER_SIZE_V1]
            )
            return Header(
                version=version,
                sender_id=sender_id,
                key_epoch=key_epoch,
                seq=seq,
                timestamp=timestamp,
                session_id=0,
            )
        else:
            raise FrameMalformedError(f"Unsupported protocol version: {ver}")
    except struct.error as e:
        raise FrameMalformedError(f"Failed to unpack header: {e}") from e


def pack_frame(frame: SecureFrame) -> bytes:
    """Serialize SecureFrame into continuous byte sequence.

    Layout: Header (20/24/25B) || CiphertextWithTag (N+16B) || Signature (64B)
    """
    if len(frame.signature) != SIGNATURE_SIZE:
        raise FrameMalformedError(
            f"Signature must be exactly {SIGNATURE_SIZE} bytes, got {len(frame.signature)}"
        )
    if len(frame.ciphertext_with_tag) < TAG_SIZE:
        raise FrameMalformedError(
            f"Ciphertext with tag must be at least {TAG_SIZE} bytes, got {len(frame.ciphertext_with_tag)}"
        )

    header_bytes = pack_header(frame.header)
    return header_bytes + frame.ciphertext_with_tag + frame.signature


def unpack_frame(raw_bytes: bytes) -> SecureFrame:
    """Deserialize continuous byte sequence into SecureFrame."""
    if len(raw_bytes) < 1:
        raise FrameMalformedError("Frame empty")
    ver = raw_bytes[0]
    if ver == PROTOCOL_VERSION_V3:
        hdr_size = HEADER_SIZE_V3
    elif ver == PROTOCOL_VERSION_V2:
        hdr_size = HEADER_SIZE_V2
    else:
        hdr_size = HEADER_SIZE_V1
    min_size = hdr_size + TAG_SIZE + SIGNATURE_SIZE
    if len(raw_bytes) < min_size:
        raise FrameMalformedError(
            f"Frame too short: {len(raw_bytes)} bytes (minimum {min_size} bytes)"
        )

    header_bytes = raw_bytes[:hdr_size]
    signature_bytes = raw_bytes[-SIGNATURE_SIZE:]
    ciphertext_with_tag = raw_bytes[hdr_size:-SIGNATURE_SIZE]

    if len(ciphertext_with_tag) < TAG_SIZE:
        raise FrameMalformedError("Ciphertext payload missing GCM tag")

    header = unpack_header(header_bytes)

    return SecureFrame(
        header=header,
        ciphertext_with_tag=ciphertext_with_tag,
        signature=signature_bytes,
    )
