"""Unit tests for SecureLink protocol codec."""

import pytest
import os
from securelink.core.types import Header, SecureFrame
from securelink.core.errors import FrameMalformedError
from securelink.protocol.constants import (
    HEADER_SIZE,
    SIGNATURE_SIZE,
    TAG_SIZE,
    MIN_FRAME_SIZE,
)
from securelink.protocol.codec import (
    pack_header,
    unpack_header,
    pack_frame,
    unpack_frame,
)


def test_header_pack_unpack_roundtrip():
    header = Header(
        version=1,
        sender_id=42,
        key_epoch=2,
        seq=1024,
        timestamp=1790000000.125,
    )
    packed = pack_header(header)
    assert len(packed) == HEADER_SIZE

    unpacked = unpack_header(packed)
    assert unpacked.version == header.version
    assert unpacked.sender_id == header.sender_id
    assert unpacked.key_epoch == header.key_epoch
    assert unpacked.seq == header.seq
    assert pytest.approx(unpacked.timestamp) == header.timestamp


def test_frame_pack_unpack_roundtrip():
    header = Header(
        version=1,
        sender_id=1,
        key_epoch=1,
        seq=99999,
        timestamp=1700000000.0,
    )
    # Ciphertext + 16B tag
    payload = b"encrypted_telemetry_payload_sample"
    tag = os.urandom(TAG_SIZE)
    ciphertext_with_tag = payload + tag
    signature = os.urandom(SIGNATURE_SIZE)

    frame = SecureFrame(
        header=header,
        ciphertext_with_tag=ciphertext_with_tag,
        signature=signature,
    )

    wire_bytes = pack_frame(frame)
    expected_len = HEADER_SIZE + len(ciphertext_with_tag) + SIGNATURE_SIZE
    assert len(wire_bytes) == expected_len

    unpacked = unpack_frame(wire_bytes)
    assert unpacked.header == header
    assert unpacked.ciphertext_with_tag == ciphertext_with_tag
    assert unpacked.signature == signature

    # Byte-for-byte identity
    repacked = pack_frame(unpacked)
    assert repacked == wire_bytes


def test_minimum_frame_size():
    header = Header(version=1, sender_id=1, key_epoch=1, seq=0, timestamp=0.0)
    # Empty payload, only 16-byte tag
    ciphertext_with_tag = os.urandom(TAG_SIZE)
    signature = os.urandom(SIGNATURE_SIZE)

    frame = SecureFrame(
        header=header,
        ciphertext_with_tag=ciphertext_with_tag,
        signature=signature,
    )
    wire = pack_frame(frame)
    assert len(wire) == MIN_FRAME_SIZE  # 100 bytes

    unpacked = unpack_frame(wire)
    assert unpacked.header.seq == 0
    assert len(unpacked.ciphertext_with_tag) == TAG_SIZE


def test_malformed_frames():
    # Frame shorter than minimum
    short_frame = b"\x00" * 99
    with pytest.raises(FrameMalformedError):
        unpack_frame(short_frame)

    # Empty frame
    with pytest.raises(FrameMalformedError):
        unpack_frame(b"")

    # Header too short
    with pytest.raises(FrameMalformedError):
        unpack_header(b"\x00" * 15)
