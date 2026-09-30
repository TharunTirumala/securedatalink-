"""H9 regression: Operator block runtime enforcement and false reject prevention.

Verifies:
- Blocked sender frames are classified as Verdict.SPOOFED with Reason.SENDER_BLOCKED.
- Unblocking allows valid frames to be accepted as AUTHENTIC.
- Operator-blocked frames are not counted as false rejects in transport_state.
"""

from securelink.crypto.keystore import KeyStore
from securelink.pipeline.tx_pipeline import TxPipeline
from securelink.pipeline.rx_pipeline import RxPipeline
from securelink.pipeline.operator_state import OperatorState
from securelink.core.types import Verdict, Reason
from dashboard.backend import transport_state


def test_operator_block_and_unblock_runtime():
    """Blocked sender returns SPOOFED/SENDER_BLOCKED, unblocking restores AUTHENTIC."""
    ks = KeyStore.generate_ephemeral(sender_ids=[1])
    op_state = OperatorState()
    tx = TxPipeline(keystore=ks, sender_id=1)
    rx = RxPipeline(keystore=ks.to_public_keystore(), operator_state=op_state)

    wire1, _ = tx.transmit(b"packet 1")
    v1, r1, pt1, _ = rx.process_frame(wire1)
    assert v1 == Verdict.AUTHENTIC
    assert r1 == Reason.OK

    # Block sender 1
    op_state.block_sender(1)
    wire2, _ = tx.transmit(b"packet 2")
    v2, r2, pt2, _ = rx.process_frame(wire2)
    assert v2 == Verdict.SPOOFED
    assert r2 == Reason.SENDER_BLOCKED
    assert pt2 is None

    # Unblock sender 1
    op_state.unblock_sender(1)
    wire3, _ = tx.transmit(b"packet 3")
    v3, r3, pt3, _ = rx.process_frame(wire3)
    assert v3 == Verdict.AUTHENTIC
    assert r3 == Reason.OK
    assert pt3 == b"packet 3"


def test_operator_blocked_not_counted_as_false_reject():
    """Events with Reason.SENDER_BLOCKED do not increment false_rejects."""
    sid = "test-h9-no-false-reject"
    transport_state.reset_session_counters(sid)

    # Attacker truth says AUTHENTIC, but RX verdict is SPOOFED due to sender_blocked
    atk_action = [{"seq": 1, "epoch": 1, "intended_label": "AUTHENTIC", "action": "pass"}]
    rx_event = [{"seq": 1, "epoch": 1, "verdict": "SPOOFED", "reason": "sender_blocked"}]

    transport_state.record_attacker_actions(sid, atk_action)
    transport_state.record_rx_events(sid, rx_event)

    c = transport_state.get_session_counters(sid)
    assert c["spoofed"] == 1
    assert c["false_rejects"] == 0, f"Expected 0 false_rejects for blocked sender, got {c['false_rejects']}"
