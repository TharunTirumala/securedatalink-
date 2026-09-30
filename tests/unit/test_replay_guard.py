"""Unit tests for the ReplayGuard sliding window and timestamp validation."""

import time
import pytest
from securelink.pipeline.replay_guard import ReplayGuard
from securelink.core.types import Reason


def test_in_order_sequences():
    guard = ReplayGuard(window_size=64, enforce_timestamp=False)
    for seq in range(1, 100):
        ok, reason = guard.check_and_update(sender_id=1, seq=seq, timestamp=0.0)
        assert ok is True
        assert reason == Reason.OK


def test_duplicate_sequence_rejection():
    guard = ReplayGuard(window_size=64, enforce_timestamp=False)
    ok, _ = guard.check_and_update(sender_id=1, seq=10, timestamp=0.0)
    assert ok is True

    # Immediate duplicate
    ok, reason = guard.check_and_update(sender_id=1, seq=10, timestamp=0.0)
    assert ok is False
    assert reason == Reason.DUPLICATE_SEQ


def test_out_of_order_within_window():
    guard = ReplayGuard(window_size=64, enforce_timestamp=False)
    guard.check_and_update(sender_id=1, seq=20, timestamp=0.0)
    guard.check_and_update(sender_id=1, seq=18, timestamp=0.0)

    # seq 19 arrives out of order within window
    ok, reason = guard.check_and_update(sender_id=1, seq=19, timestamp=0.0)
    assert ok is True
    assert reason == Reason.OK

    # Re-delivering 19 fails
    ok, reason = guard.check_and_update(sender_id=1, seq=19, timestamp=0.0)
    assert ok is False
    assert reason == Reason.DUPLICATE_SEQ


def test_sequence_out_of_window():
    guard = ReplayGuard(window_size=64, enforce_timestamp=False)
    guard.check_and_update(sender_id=1, seq=100, timestamp=0.0)

    # 100 - 37 = 63 < 64: seq 37 is the oldest valid sequence accepted within window
    ok, reason = guard.check_and_update(sender_id=1, seq=37, timestamp=0.0)
    assert ok is True
    assert reason == Reason.OK

    # 100 - 36 = 64 >= 64: seq 36 is on the exact boundary and rejected
    ok, reason = guard.check_and_update(sender_id=1, seq=36, timestamp=0.0)
    assert ok is False
    assert reason == Reason.SEQ_OUT_OF_WINDOW

    # 100 - 35 = 65 >= 64: seq 35 is strictly out of window
    ok, reason = guard.check_and_update(sender_id=1, seq=35, timestamp=0.0)
    assert ok is False
    assert reason == Reason.SEQ_OUT_OF_WINDOW



def test_timestamp_freshness():
    now = 1000.0
    guard = ReplayGuard(window_size=64, max_clock_skew=10.0, enforce_timestamp=True)

    # Fresh timestamp
    ok, reason = guard.check_and_update(sender_id=1, seq=1, timestamp=now - 2.0, current_time=now)
    assert ok is True

    # Stale timestamp (> 10s old)
    ok, reason = guard.check_and_update(sender_id=1, seq=2, timestamp=now - 15.0, current_time=now)
    assert ok is False
    assert reason == Reason.STALE_TIMESTAMP

    # NaN timestamp rejected
    ok, reason = guard.check_and_update(sender_id=1, seq=3, timestamp=float("nan"), current_time=now)
    assert ok is False
    assert reason == Reason.STALE_TIMESTAMP


def test_bitmap_bounded_size():
    guard = ReplayGuard(window_size=64, enforce_timestamp=False)
    # Stream 10,000 sequence numbers
    for seq in range(1, 10001):
        guard.check_and_update(sender_id=1, seq=seq, timestamp=0.0)

    # Bitmap length must strictly never exceed window_size bits
    state = guard.senders[1]
    assert state.bitmap.bit_length() <= 64

