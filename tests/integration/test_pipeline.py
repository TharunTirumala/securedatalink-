"""Integration test for full TX -> RX pipeline under clean and hostile conditions."""

import pytest
import time
from securelink.crypto.keystore import KeyStore
from securelink.pipeline.tx_pipeline import TxPipeline
from securelink.pipeline.rx_pipeline import RxPipeline
from securelink.pipeline.replay_guard import ReplayGuard
from securelink.core.types import Verdict, Reason, TelemetryData


def create_sample_telemetry(seq: int, sender_id: int = 1) -> TelemetryData:
    return TelemetryData(
        seq=seq,
        sender_id=sender_id,
        timestamp=time.time(),
        lat=17.3850 + seq * 0.0001,
        lon=78.4867 + seq * 0.0001,
        alt=500.0,
        speed=25.5,
        heading=180.0,
        battery=98.5,
    )


def test_clean_stream_is_100_percent_authentic():
    keystore = KeyStore.generate_ephemeral(sender_ids=[1])
    tx = TxPipeline(keystore=keystore, sender_id=1)
    rx = RxPipeline(keystore=keystore, replay_guard=ReplayGuard(enforce_timestamp=False))

    count = 50
    verdicts = []
    for i in range(1, count + 1):
        telemetry = create_sample_telemetry(seq=i, sender_id=1)
        wire_bytes, _ = tx.transmit(telemetry)
        verdict, reason, plaintext, header = rx.process_frame(wire_bytes)
        verdicts.append(verdict)
        assert verdict == Verdict.AUTHENTIC
        assert reason == Reason.OK
        assert plaintext is not None
        assert header.seq == i

    assert verdicts.count(Verdict.AUTHENTIC) == count


def test_tampered_frame_classified_as_tampered():
    keystore = KeyStore.generate_ephemeral(sender_ids=[1])
    tx = TxPipeline(keystore=keystore, sender_id=1)
    rx = RxPipeline(keystore=keystore, replay_guard=ReplayGuard(enforce_timestamp=False))

    telemetry = create_sample_telemetry(seq=1, sender_id=1)
    wire_bytes, _ = tx.transmit(telemetry)

    # Tamper with byte at index 25 (inside ciphertext body)
    tampered_bytes = bytearray(wire_bytes)
    tampered_bytes[25] ^= 0xFF
    tampered_bytes = bytes(tampered_bytes)

    verdict, reason, plaintext, _ = rx.process_frame(tampered_bytes)
    assert verdict == Verdict.TAMPERED
    assert reason == Reason.GCM_TAG_MISMATCH
    assert plaintext is None


def test_replayed_frame_classified_as_replayed():
    keystore = KeyStore.generate_ephemeral(sender_ids=[1])
    tx = TxPipeline(keystore=keystore, sender_id=1)
    rx = RxPipeline(keystore=keystore, replay_guard=ReplayGuard(enforce_timestamp=False))

    telemetry = create_sample_telemetry(seq=10, sender_id=1)
    wire_bytes, _ = tx.transmit(telemetry)

    # First delivery: AUTHENTIC
    v1, r1, _, _ = rx.process_frame(wire_bytes)
    assert v1 == Verdict.AUTHENTIC

    # Second delivery (replay attack): REPLAYED
    v2, r2, _, _ = rx.process_frame(wire_bytes)
    assert v2 == Verdict.REPLAYED
    assert r2 == Reason.DUPLICATE_SEQ


def test_spoofed_unknown_sender_classified_as_spoofed():
    keystore = KeyStore.generate_ephemeral(sender_ids=[1])
    # Transmitter uses unknown sender ID 999
    # We create an ephemeral key for sender 999 that is NOT in receiver's keystore
    keystore_attacker = KeyStore.generate_ephemeral(sender_ids=[999])
    tx_attacker = TxPipeline(keystore=keystore_attacker, sender_id=999)
    rx = RxPipeline(keystore=keystore, replay_guard=ReplayGuard(enforce_timestamp=False))

    telemetry = create_sample_telemetry(seq=1, sender_id=999)
    wire_bytes, _ = tx_attacker.transmit(telemetry)

    verdict, reason, _, header = rx.process_frame(wire_bytes)
    assert verdict == Verdict.SPOOFED
    assert reason == Reason.UNKNOWN_SENDER
    assert header.sender_id == 999



def test_unsupported_version_classified_as_tampered():
    keystore = KeyStore.generate_ephemeral(sender_ids=[1])
    tx = TxPipeline(keystore=keystore, sender_id=1)
    rx = RxPipeline(keystore=keystore)

    telemetry = create_sample_telemetry(seq=1, sender_id=1)
    wire_bytes, _ = tx.transmit(telemetry)

    # Byte 0 is protocol version: corrupt to 99
    corrupted_version = bytearray(wire_bytes)
    corrupted_version[0] = 99
    verdict, reason, plaintext, _ = rx.process_frame(bytes(corrupted_version))
    assert verdict == Verdict.TAMPERED
    assert reason == Reason.FRAME_MALFORMED
    assert plaintext is None


def test_stale_timestamp_classified_as_replayed():
    keystore = KeyStore.generate_ephemeral(sender_ids=[1])
    tx = TxPipeline(keystore=keystore, sender_id=1)
    guard = ReplayGuard(max_clock_skew=10.0, enforce_timestamp=True)
    rx = RxPipeline(keystore=keystore, replay_guard=guard)

    now = 1000000.0
    # Create telemetry with timestamp 40 seconds in the past
    telemetry = create_sample_telemetry(seq=1, sender_id=1)
    telemetry.timestamp = now - 40.0
    wire_bytes, _ = tx.transmit(telemetry, timestamp=now - 40.0)

    verdict, reason, plaintext, _ = rx.process_frame(wire_bytes, current_time=now)
    assert verdict == Verdict.REPLAYED
    assert reason == Reason.STALE_TIMESTAMP
    assert plaintext is None


def test_unknown_epoch_classified_as_tampered():
    keystore = KeyStore.generate_ephemeral(sender_ids=[1], default_epoch=1)
    # Transmitter starts at epoch 1, then we test a far-future epoch jump
    tx_e1 = TxPipeline(keystore=keystore, sender_id=1, key_epoch=1)
    rx = RxPipeline(keystore=keystore)

    # Prime RX with a valid epoch-1 frame so it has prior state
    telemetry = create_sample_telemetry(seq=1, sender_id=1)
    wire_e1, _ = tx_e1.transmit(telemetry)
    v_prime, _, _, _ = rx.process_frame(wire_e1)
    assert v_prime == Verdict.AUTHENTIC, f"Priming frame failed: {v_prime}"

    # Now attempt epoch 99 (beyond highest+max_jump=9); must be rejected
    # Use a fresh TX at epoch 99 — keystore can derive the key but RX lookahead blocks it
    tx_e99 = TxPipeline(keystore=keystore, sender_id=1, key_epoch=99)
    wire_e99, _ = tx_e99.transmit(telemetry)

    verdict, reason, plaintext, _ = rx.process_frame(wire_e99)
    assert verdict == Verdict.TAMPERED
    assert reason == Reason.UNKNOWN_EPOCH
    assert plaintext is None


def test_tx_sequence_reuse_raises_error():
    keystore = KeyStore.generate_ephemeral(sender_ids=[1])
    tx = TxPipeline(keystore=keystore, sender_id=1)
    telemetry = create_sample_telemetry(seq=10, sender_id=1)
    tx.transmit(telemetry, seq=10)

    # Reusing seq 10 or sending seq 9 must raise ValueError
    with pytest.raises(ValueError):
        tx.transmit(telemetry, seq=10)
    with pytest.raises(ValueError):
        tx.transmit(telemetry, seq=9)

    # Sending strictly higher seq 11 succeeds
    _, frame = tx.transmit(telemetry, seq=11)
    assert frame.header.seq == 11


def test_stream_across_5_epochs_is_100_percent_authentic():
    """Verify that a stream rotating across 5 epochs verifies 100% AUTHENTIC."""
    keystore = KeyStore.generate_ephemeral(sender_ids=[1])
    tx = TxPipeline(keystore=keystore, sender_id=1, rekey_every_packets=20)
    rx = RxPipeline(keystore=keystore.to_public_keystore(), rekey_grace_epochs=1)

    for i in range(1, 101):
        telemetry = create_sample_telemetry(seq=i, sender_id=1)
        wire_bytes, _ = tx.transmit(telemetry)
        verdict, reason, pt, hdr = rx.process_frame(wire_bytes)
        assert verdict == Verdict.AUTHENTIC
        assert reason == Reason.OK
        assert pt is not None

    # TX should have rotated to epoch 5
    assert tx.key_epoch == 5
    assert rx.highest_auth_epoch[1] == 5


def test_replaying_frame_from_expired_epoch_classified_as_replayed():
    """Verify that a valid frame from epoch N-2 replayed in epoch N is REPLAYED / EPOCH_EXPIRED."""
    keystore = KeyStore.generate_ephemeral(sender_ids=[1])
    tx = TxPipeline(keystore=keystore, sender_id=1)
    rx = RxPipeline(keystore=keystore.to_public_keystore(), rekey_grace_epochs=1)

    # Frame in epoch 1
    telemetry_e1 = create_sample_telemetry(seq=1, sender_id=1)
    wire_e1, _ = tx.transmit(telemetry_e1)
    v1, r1, _, _ = rx.process_frame(wire_e1)
    assert v1 == Verdict.AUTHENTIC

    # Advance to epoch 2
    tx.rotate()
    wire_e2, _ = tx.transmit(create_sample_telemetry(seq=1, sender_id=1))
    rx.process_frame(wire_e2)

    # Advance to epoch 3 (now highest is 3; grace=1 means allowed epochs are 3 and 2; epoch 1 is expired)
    tx.rotate()
    wire_e3, _ = tx.transmit(create_sample_telemetry(seq=1, sender_id=1))
    rx.process_frame(wire_e3)
    assert rx.highest_auth_epoch[1] == 3

    # Replay wire_e1 from epoch 1
    v_replay, r_replay, _, _ = rx.process_frame(wire_e1)
    assert v_replay == Verdict.REPLAYED
    assert r_replay == Reason.EPOCH_EXPIRED




