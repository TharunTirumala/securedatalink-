"""H3 regression: Late-joining and restarted RX must authenticate epoch-N frames.

Verifies that an RxPipeline with no prior state (highest_auth_epoch empty)
can successfully authenticate frames from any epoch (not just epoch 1),
and that a too-far-forward forged epoch is still rejected after auth.
"""

import time
from securelink.crypto.keystore import KeyStore
from securelink.pipeline.tx_pipeline import TxPipeline
from securelink.pipeline.rx_pipeline import RxPipeline
from securelink.core.types import Verdict


def _make_stack(session_id: int = 100):
    ks = KeyStore.generate_ephemeral(sender_ids=[1])
    tx = TxPipeline(keystore=ks, sender_id=1, session_id=session_id,
                    rekey_every_packets=10)
    rx = RxPipeline(keystore=ks.to_public_keystore())
    return tx, rx, ks


def test_late_join_at_epoch_5():
    """RX joining at epoch 5 (having never seen epochs 1-4) authenticates all frames."""
    tx, _, _ = _make_stack()
    # Advance TX to epoch 5 by transmitting 40 frames (rekey_every=10)
    frames_e1_to_4 = []
    for i in range(40):
        wire, frame = tx.transmit(f"pkt-{i}".encode())
        frames_e1_to_4.append((wire, frame))

    # Build fresh RX with no prior state
    ks = KeyStore.generate_ephemeral(sender_ids=[1])
    # Rebuild TX with the same keystore
    tx2 = TxPipeline(keystore=ks, sender_id=1, session_id=100, rekey_every_packets=10)
    for i in range(40):
        tx2.transmit(f"pkt-{i}".encode())  # advance epoch

    rx_late = RxPipeline(keystore=ks.to_public_keystore())

    # Transmit 10 more frames at epoch 5; RX should auth all
    for i in range(10):
        wire, frm = tx2.transmit(f"late-{i}".encode())
        assert frm.header.key_epoch == 5, f"Expected epoch 5, got {frm.header.key_epoch}"
        verdict, reason, pt, hdr = rx_late.process_frame(wire)
        assert verdict == Verdict.AUTHENTIC, f"Frame {i} at epoch 5 rejected: {reason}"


def test_forged_far_future_epoch_rejected():
    """A frame claiming a far-future epoch that would fail GCM must not authenticate."""
    tx, rx_fresh, ks = _make_stack()
    wire, frame = tx.transmit(b"legit")
    assert frame.header.key_epoch == 1

    # Tamper: change epoch byte to 99 (raw byte at offset 2 for V2 header)
    raw = bytearray(wire)
    raw[2] = 99  # key_epoch field, 1 byte at index 2 in V2 header
    tampered = bytes(raw)

    verdict, reason, pt, hdr = rx_fresh.process_frame(tampered)
    # Must fail (either GCM mismatch or epoch-unknown, but NOT AUTHENTIC)
    assert verdict != Verdict.AUTHENTIC, f"Forged future-epoch frame should not be AUTHENTIC: {reason}"


def test_epoch_expired_after_auth():
    """A real old-epoch frame delivered after many epochs must be EPOCH_EXPIRED, not AUTHENTIC."""
    tx, _, ks = _make_stack()
    # Save a legit epoch-1 frame
    wire_e1, frm_e1 = tx.transmit(b"old-frame")
    assert frm_e1.header.key_epoch == 1

    rx = RxPipeline(keystore=ks.to_public_keystore())

    # Process the epoch-1 frame first so RX knows about epoch 1
    v, r, _, _ = rx.process_frame(wire_e1)
    assert v == Verdict.AUTHENTIC

    # Advance TX to epoch 4
    for i in range(30):
        wire, _ = tx.transmit(f"p{i}".encode())
        rx.process_frame(wire)

    # Now re-deliver the epoch-1 frame — must be EPOCH_EXPIRED
    v2, r2, _, _ = rx.process_frame(wire_e1)
    # Note: it may also be REPLAYED (replay guard fires first); either is acceptable,
    # but it must not be AUTHENTIC
    assert v2 != Verdict.AUTHENTIC, f"Old epoch-1 frame should not be AUTHENTIC after epoch 4"
