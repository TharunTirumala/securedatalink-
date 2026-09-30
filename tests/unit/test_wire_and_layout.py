"""Unit tests for frame layout ranges and JSONL wire file serialization/parsing."""

import pytest
from securelink.protocol.constants import MIN_FRAME_SIZE, HEADER_SIZE, TAG_SIZE, SIGNATURE_SIZE
from securelink.protocol.layout import field_ranges, get_field_range
from securelink.protocol.wire_file import write_wire_file, read_wire_file, compute_key_fp
from securelink.pipeline.replay_guard import ReplayGuard
from securelink.core.types import Reason


def test_field_ranges_boundaries():
    frame_len = 150
    ranges = field_ranges(frame_len)
    assert len(ranges) == 8

    # Ensure contiguous coverage from 0 to frame_len
    expected_start = 0
    for r in ranges:
        assert r["start"] == expected_start
        assert r["end"] > r["start"]
        expected_start = r["end"]
    assert expected_start == frame_len

    # Specific field checks
    assert get_field_range("version", frame_len) == {"name": "version", "start": 0, "end": 1, "kind": "header"}
    assert get_field_range("timestamp", frame_len) == {"name": "timestamp", "start": 12, "end": 20, "kind": "header"}
    assert get_field_range("signature", frame_len)["start"] == frame_len - SIGNATURE_SIZE


def test_field_ranges_too_short():
    with pytest.raises(ValueError):
        field_ranges(MIN_FRAME_SIZE - 1)


def test_wire_file_roundtrip():
    meta = {
        "file_id": "test-1234",
        "created": 1000.0,
        "sender_id": 1,
        "key_fp": "a1b2c3d4",
        "seed": 42,
        "rekey_every_packets": 50,
    }
    sample_bytes1 = b"\x01\x02\x03\x04" * 30
    sample_bytes2 = b"\x05\x06\x07\x08" * 30
    frames = [
        {"n": 1, "t": 1000.1, "raw_bytes": sample_bytes1},
        {"n": 2, "t": 1000.2, "raw_bytes": sample_bytes2},
    ]

    wire_text = write_wire_file(meta, frames)
    read_meta, read_entries, errors = read_wire_file(wire_text)

    assert not errors
    assert read_meta["file_id"] == "test-1234"
    assert read_meta["key_fp"] == "a1b2c3d4"
    assert len(read_entries) == 2
    assert read_entries[0]["raw_bytes"] == sample_bytes1
    assert read_entries[1]["raw_bytes"] == sample_bytes2
    assert read_entries[0]["t"] == 1000.1


def test_wire_file_tolerant_parsing():
    corrupted_content = (
        '{"type":"meta","format":1,"file_id":"bad-test","key_fp":"beef1234"}\n'
        '{"type":"frame","n":1,"t":1.0,"hex":"deadbeef"}\n'
        'not valid json at all\n'
        '{"type":"frame","n":3,"t":3.0,"hex":"NOT_HEX_CHARS!!!"}\n'
        '{"type":"frame","n":4,"t":4.0,"hex":"01020304"}\n'
    )
    meta, entries, errors = read_wire_file(corrupted_content)
    assert meta["file_id"] == "bad-test"
    assert len(entries) == 4
    assert entries[0]["is_malformed"] is False
    assert entries[0]["raw_bytes"] == bytes.fromhex("deadbeef")
    assert entries[1]["is_malformed"] is True
    assert entries[2]["is_malformed"] is True
    assert entries[3]["is_malformed"] is False
    assert entries[3]["raw_bytes"] == bytes.fromhex("01020304")
    assert len(errors) == 2


def test_wire_file_size_limits():
    # Test line count limit
    huge_lines = "\n".join(["{}"] * 50005)
    with pytest.raises(ValueError, match="exceeds maximum line limit"):
        read_wire_file(huge_lines)


def test_replay_guard_simulated_clock():
    simulated_time = 5000.0
    guard = ReplayGuard(max_clock_skew=10.0, clock=lambda: simulated_time)

    # Frame with timestamp 5002 is fresh
    ok, reason = guard.check_and_update(sender_id=1, seq=1, timestamp=5002.0)
    assert ok is True
    assert reason == Reason.OK

    # Frame with timestamp 4000 is stale relative to simulated clock
    ok, reason = guard.check_and_update(sender_id=1, seq=2, timestamp=4000.0)
    assert ok is False
    assert reason == Reason.STALE_TIMESTAMP
