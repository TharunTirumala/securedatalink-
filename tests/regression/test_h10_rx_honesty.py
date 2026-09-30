"""H10 regression: RX honesty, malformed frame handling, and clock skew enforcement.

Verifies:
- Malformed/truncated frames yield header is None and Verdict.TAMPERED without fabricated values.
- Clock skew larger than max_clock_skew triggers Reason.STALE_TIMESTAMP.
- ReplayGuard respects configured max_clock_skew parameter.
"""

from securelink.crypto.keystore import KeyStore
from securelink.pipeline.tx_pipeline import TxPipeline
from securelink.pipeline.rx_pipeline import RxPipeline
from securelink.pipeline.replay_guard import ReplayGuard
from securelink.core.types import Verdict, Reason


def test_malformed_frame_header_is_none():
    """Malformed or garbage frame must produce header=None and TAMPERED verdict."""
    ks = KeyStore.generate_ephemeral(sender_ids=[1])
    rx = RxPipeline(keystore=ks.to_public_keystore())

    # Garbage bytes
    garbage = b"\x00" * 30
    verdict, reason, pt, header = rx.process_frame(garbage)
    assert verdict == Verdict.TAMPERED
    assert reason in (Reason.FRAME_TOO_SHORT, Reason.FRAME_MALFORMED)
    assert header is None
    assert pt is None


def test_clock_skew_enforcement_with_custom_skew():
    """ReplayGuard respects max_clock_skew and flags frames exceeding the threshold."""
    ks = KeyStore.generate_ephemeral(sender_ids=[1])
    # Configure tight 5.0-second clock skew limit
    guard = ReplayGuard(max_clock_skew=5.0, enforce_timestamp=True)
    rx = RxPipeline(keystore=ks.to_public_keystore(), replay_guard=guard)
    tx = TxPipeline(keystore=ks, sender_id=1)

    t_now = 1_000_000.0

    # Frame within 5s window (4s old) succeeds
    wire_ok, _ = tx.transmit(b"recent", timestamp=t_now - 4.0)
    v_ok, r_ok, pt_ok, _ = rx.process_frame(wire_ok, current_time=t_now)
    assert v_ok == Verdict.AUTHENTIC
    assert r_ok == Reason.OK
    assert pt_ok == b"recent"

    # Frame exceeding 5s window (6s old) triggers STALE_TIMESTAMP
    wire_stale, _ = tx.transmit(b"stale", timestamp=t_now - 6.0)
    v_stale, r_stale, pt_stale, _ = rx.process_frame(wire_stale, current_time=t_now)
    assert v_stale == Verdict.REPLAYED
    assert r_stale == Reason.STALE_TIMESTAMP
    assert pt_stale is None
