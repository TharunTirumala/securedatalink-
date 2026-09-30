"""Frame layout calculation dynamically derived from protocol constants."""

from typing import List, Dict, Any
from securelink.protocol.constants import (
    HEADER_SIZE,
    TAG_SIZE,
    SIGNATURE_SIZE,
    MIN_FRAME_SIZE,
)


def field_ranges(frame_len: int) -> List[Dict[str, Any]]:
    """Compute exact byte ranges for each field in a frame of length `frame_len`.

    Returns a list of dicts: {'name': str, 'start': int, 'end': int, 'kind': str}.
    Raises ValueError if frame_len is below MIN_FRAME_SIZE.
    """
    if frame_len < MIN_FRAME_SIZE:
        raise ValueError(
            f"Frame length {frame_len} is less than minimum required {MIN_FRAME_SIZE} bytes"
        )

    ranges: List[Dict[str, Any]] = [
        {"name": "version", "start": 0, "end": 1, "kind": "header"},
        {"name": "sender_id", "start": 1, "end": 3, "kind": "header"},
        {"name": "key_epoch", "start": 3, "end": 4, "kind": "header"},
        {"name": "seq", "start": 4, "end": 12, "kind": "header"},
        {"name": "timestamp", "start": 12, "end": 20, "kind": "header"},
    ]

    cipher_end = frame_len - TAG_SIZE - SIGNATURE_SIZE
    ranges.append({"name": "ciphertext", "start": HEADER_SIZE, "end": cipher_end, "kind": "cipher"})

    tag_end = cipher_end + TAG_SIZE
    ranges.append({"name": "tag", "start": cipher_end, "end": tag_end, "kind": "tag"})

    sig_end = tag_end + SIGNATURE_SIZE
    ranges.append({"name": "signature", "start": tag_end, "end": sig_end, "kind": "sig"})

    return ranges


def get_field_range(field_name: str, frame_len: int) -> Dict[str, Any]:
    """Retrieve range for a specific field name."""
    for f in field_ranges(frame_len):
        if f["name"] == field_name:
            return f
    raise KeyError(f"Field '{field_name}' not found in frame layout")
