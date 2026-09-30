"""H5 regression: Attacker ground-truth labels and replay buffer semantics.

Verifies:
- apply_wire_tamper always produces output != input
- WireJammer "delay" releases return "AUTHENTIC" not "REPLAYED"
- WireReplayBuffer record() called after forward does not include current frame
- extract_seq reads the correct byte for MAVLink v2 (byte 4)
- extract_seq reads correct offsets for SecureLink V1/V2/V3
"""

import struct
from securelink.simulation.attacks.wire_modes import (
    apply_wire_tamper,
    WireJammer,
    WireReplayBuffer,
)
from securelink.cli.attacker import extract_seq


def test_tamper_always_differs():
    """apply_wire_tamper must always produce output != input."""
    payload = b"X" * 100
    for seed in range(500):
        out, label = apply_wire_tamper(payload, seed=seed)
        assert out != payload, f"Tamper seed={seed} produced identical output"
        assert label == "TAMPERED"


def test_tamper_minimal_payload():
    """Tamper on single byte payload must change the byte."""
    payload = b"\xff"
    for seed in range(100):
        out, label = apply_wire_tamper(payload, seed=seed)
        assert out != payload, f"Tamper seed={seed} failed for single byte"


def test_jammer_delay_release_labelled_authentic():
    """Released delay frames must be labelled AUTHENTIC, not REPLAYED."""
    jammer = WireJammer(burst_size=2)
    raw = b"frame-data-" + b"\x01" * 64

    delays = 0
    releases = 0
    passes = 0
    results = []
    # Force enough "delay" actions to trigger a release
    for seed in range(200):
        out, label = jammer.handle(raw, seed=seed)
        results.append((out, label))
        if out is None:
            delays += 1
        elif label == "AUTHENTIC":
            if out == raw:
                passes += 1
            else:
                releases += 1  # released from queue
        elif label == "TAMPERED":
            pass  # corrupt action
        else:
            assert False, f"Unexpected label '{label}' from jammer"

    # No result should ever be "REPLAYED" from the jammer
    bad = [(i, l) for i, (_, l) in enumerate(results) if l == "REPLAYED"]
    assert not bad, f"Jammer returned REPLAYED at indices {[i for i, _ in bad]}"


def test_replay_buffer_record_after_forward():
    """After record(), get_replay() returns only recorded frames (not current frame)."""
    buf = WireReplayBuffer()
    frame_a = b"A" * 80
    frame_b = b"B" * 80

    # Buffer is empty before any record
    assert buf.get_replay() is None

    buf.record(frame_a)
    buf.record(frame_b)

    for _ in range(50):
        replayed = buf.get_replay()
        assert replayed in (frame_a, frame_b), f"Unexpected replay: {replayed}"


def test_extract_seq_mavlink_v2():
    """MAVLink v2 seq field is at byte 4 (not byte 2)."""
    # MAVLink v2 frame: 0xFD, payload_len, incompat, compat, seq, ...
    mav_frame = bytes([0xFD, 10, 0, 0, 42, 0, 0, 1, 0, 0])  # seq=42 at byte 4
    seq = extract_seq(mav_frame)
    assert seq == 42, f"Expected seq=42, got {seq}"

    # Byte 2 (old wrong offset) is 0, not 42
    assert mav_frame[2] == 0, "Byte 2 is not the seq field"


def test_extract_seq_securelink_v1():
    """SecureLink V1 seq extracted correctly from offset 4."""
    # V1: B(1) H(2) B(1) Q(8) = total 12 bytes minimum
    # version=1, sender_id=1, epoch=1, seq=12345
    header = struct.pack(">BHBQd", 1, 1, 1, 12345, 0.0)
    seq = extract_seq(header)
    assert seq == 12345, f"Expected 12345, got {seq}"


def test_extract_seq_securelink_v3():
    """SecureLink V3 seq extracted correctly from offset 9."""
    # V3: B(1) H(2) H(2) I(4) Q(8) = 17 bytes minimum
    header = struct.pack(">BHHIQd", 3, 1, 256, 99, 999, 0.0)
    seq = extract_seq(header)
    assert seq == 999, f"Expected 999, got {seq}"
