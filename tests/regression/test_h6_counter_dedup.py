"""H6 regression: Counter double-count prevention and (epoch, seq) deduplication.

Verifies:
- Calling record_rx_stats does not double-count verdicts when record_rx_events is also called.
- Identical seq in different epochs (e.g. (1, 10) vs (2, 10)) are treated as distinct frames.
- Re-delivering the exact same (epoch, seq) does not increment verdict counters twice.
"""

from dashboard.backend import transport_state


def test_no_double_counting_from_rx_stats():
    """record_rx_stats should not increment verdict counters; events are authoritative."""
    sid = "test-h6-no-double"
    transport_state.reset_session_counters(sid)

    # Ingest 10 authentic events from RX
    events = [{"seq": i, "epoch": 1, "verdict": "AUTHENTIC"} for i in range(1, 11)]
    transport_state.record_rx_events(sid, events)

    c1 = transport_state.get_session_counters(sid)
    assert c1["authentic"] == 10
    assert c1["received"] == 10

    # RX now posts periodic /stats summary
    transport_state.record_rx_stats(
        sid,
        counts={"total": 10, "AUTHENTIC": 10, "TAMPERED": 0, "REPLAYED": 0, "SPOOFED": 0},
        total_received=10,
    )

    c2 = transport_state.get_session_counters(sid)
    # Authentic count must still be 10, NOT 20!
    assert c2["authentic"] == 10, f"Expected 10 authentic, got {c2['authentic']} (double-counted!)"
    assert c2["received"] == 10


def test_cross_epoch_seq_independence():
    """Same seq number in different epochs (epoch 1 seq 1 vs epoch 2 seq 1) are distinct frames."""
    sid = "test-h6-epochs"
    transport_state.reset_session_counters(sid)

    ev_epoch1 = [{"seq": 1, "epoch": 1, "verdict": "AUTHENTIC"}]
    ev_epoch2 = [{"seq": 1, "epoch": 2, "verdict": "TAMPERED"}]

    transport_state.record_rx_events(sid, ev_epoch1)
    transport_state.record_rx_events(sid, ev_epoch2)

    c = transport_state.get_session_counters(sid)
    assert c["received"] == 2
    assert c["authentic"] == 1
    assert c["tampered"] == 1


def test_duplicate_event_deduplication():
    """Identical (epoch, seq) delivered multiple times is deduplicated."""
    sid = "test-h6-dedup"
    transport_state.reset_session_counters(sid)

    ev = [{"seq": 5, "epoch": 1, "verdict": "AUTHENTIC"}]
    transport_state.record_rx_events(sid, ev)
    transport_state.record_rx_events(sid, ev)

    c = transport_state.get_session_counters(sid)
    assert c["received"] == 1
    assert c["authentic"] == 1
