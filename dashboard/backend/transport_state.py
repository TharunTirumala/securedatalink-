"""Shared singleton state for Transport sessions, authoritative counters, and live telemetry."""

import threading
import time
from typing import Any, Dict, List, Optional, Set
from dataclasses import dataclass, asdict

from securelink.sessions.manager import SessionManager
from securelink.sessions.store import SessionStore
from securelink.sessions.telemetry_reconcile import haversine_m

store = SessionStore()
manager = SessionManager(store=store)

ingest_lock = threading.Lock()
latest_drone_telemetry: Optional[Dict[str, Any]] = None
latest_c2_telemetry: Optional[Dict[str, Any]] = None
session_stats_cache: Dict[str, Dict[str, Any]] = {}
live_divergence_m: float = 0.0


def reset_live_telemetry():
    """Clear cached live telemetry between transport runs."""
    global latest_drone_telemetry, latest_c2_telemetry, live_divergence_m
    with ingest_lock:
        latest_drone_telemetry = None
        latest_c2_telemetry = None
        live_divergence_m = 0.0


@dataclass
class SessionCounters:
    sent: int = 0
    received: int = 0
    authentic: int = 0
    tampered: int = 0
    replayed: int = 0
    spoofed: int = 0
    dropped: int = 0
    operator_blocked: int = 0
    false_accepts: int = 0
    false_rejects: int = 0

    def to_dict(self) -> Dict[str, int]:
        return asdict(self)


# Counter storage — keyed by session_id
session_counters: Dict[str, SessionCounters] = {}
# (epoch, seq) -> verdict string; prevents cross-epoch seq collisions
session_rx_verdicts: Dict[str, Dict[tuple, str]] = {}
session_rx_reasons: Dict[str, Dict[tuple, str]] = {}
# (epoch, seq) -> intended_label string from attacker
session_attacker_truth: Dict[str, Dict[tuple, str]] = {}
# Set of (epoch, seq) tuples that have been evaluated for false_accepts/rejects
session_evaluated_seqs: Dict[str, Set[tuple]] = {}
session_dropped_seqs: Dict[str, Set[int]] = {}

_MAX_DICT_ENTRIES = 50_000  # cap to prevent unbounded memory growth


def _get_or_create_counters_locked(sid: str) -> SessionCounters:
    if sid not in session_counters:
        session_counters[sid] = SessionCounters()
        session_rx_verdicts[sid] = {}
        session_rx_reasons[sid] = {}
        session_attacker_truth[sid] = {}
        session_evaluated_seqs[sid] = set()
        session_dropped_seqs[sid] = set()
    return session_counters[sid]


def reset_session_counters(sid: str):
    with ingest_lock:
        session_counters[sid] = SessionCounters()
        session_rx_verdicts[sid] = {}
        session_rx_reasons[sid] = {}
        session_attacker_truth[sid] = {}
        session_evaluated_seqs[sid] = set()
        session_dropped_seqs[sid] = set()
        session_stats_cache[sid] = {}


def _check_and_clamp_invariants_locked(sid: str):
    if sid not in session_counters:
        return
    c = session_counters[sid]
    v_sum = c.authentic + c.tampered + c.replayed + c.spoofed
    if c.received > 0 and v_sum != c.received:
        import logging
        logging.getLogger("securelink.transport").warning(
            f"Invariant mismatch: verdict_sum={v_sum} != received={c.received} (session {sid})"
        )


def get_session_counters(sid: Optional[str]) -> Dict[str, int]:
    with ingest_lock:
        if not sid or sid not in session_counters:
            return SessionCounters().to_dict()
        _check_and_clamp_invariants_locked(sid)
        return session_counters[sid].to_dict()


def _evaluate_seq_locked(sid: str, key: tuple):
    """Check (epoch, seq) pair for false accepts/rejects. key must be (epoch, seq)."""
    if key in session_evaluated_seqs[sid]:
        return
    truth = session_attacker_truth[sid].get(key)
    verdict = session_rx_verdicts[sid].get(key)
    if truth is not None and verdict is not None:
        session_evaluated_seqs[sid].add(key)
        c = session_counters[sid]
        reason = session_rx_reasons[sid].get(key, "").lower()
        if verdict == "AUTHENTIC" and truth != "AUTHENTIC":
            c.false_accepts += 1
        elif verdict != "AUTHENTIC" and truth == "AUTHENTIC":
            if reason != "sender_blocked":
                c.false_rejects += 1


def record_tx_stats(sid: str, sent_count: int, epoch: int = 1, rate: float = 0.0):
    with ingest_lock:
        c = _get_or_create_counters_locked(sid)
        c.sent = max(c.sent, sent_count)


def record_rx_stats(sid: str, counts: Dict[str, int], total_received: Optional[int] = None):
    """Handle rx stats report.

    `received` is computed exclusively from record_rx_events() to ensure
    exact alignment with verdict counts and prevent double-counting.
    """
    pass


def record_attacker_stats(sid: str, stats: Dict[str, Any]):
    with ingest_lock:
        c = _get_or_create_counters_locked(sid)
        if "dropped" in stats:
            d_seqs = len(session_dropped_seqs.get(sid, set()))
            c.dropped = max(c.dropped, stats["dropped"], d_seqs)


def record_rx_events(sid: str, events: List[Dict[str, Any]]):
    with ingest_lock:
        c = _get_or_create_counters_locked(sid)
        for ev in events:
            seq = ev.get("seq")
            epoch = ev.get("epoch", 1) or 1
            v = str(ev.get("verdict", "")).upper()
            r_str = str(ev.get("reason", "")).lower()
            if seq is not None:
                key = (epoch, seq)
                if key not in session_rx_verdicts[sid]:
                    if len(session_rx_verdicts[sid]) < _MAX_DICT_ENTRIES:
                        session_rx_verdicts[sid][key] = v
                        session_rx_reasons[sid][key] = r_str
                    c.received += 1
                    if r_str == "sender_blocked":
                        c.operator_blocked += 1
                    if v == "AUTHENTIC":
                        c.authentic += 1
                    elif v == "TAMPERED":
                        c.tampered += 1
                    elif v == "REPLAYED":
                        c.replayed += 1
                    elif v == "SPOOFED":
                        c.spoofed += 1
                _evaluate_seq_locked(sid, key)
            else:
                c.received += 1
                if r_str == "sender_blocked":
                    c.operator_blocked += 1
                if v == "AUTHENTIC":
                    c.authentic += 1
                elif v == "TAMPERED":
                    c.tampered += 1
                elif v == "REPLAYED":
                    c.replayed += 1
                elif v == "SPOOFED":
                    c.spoofed += 1


def record_attacker_actions(sid: str, actions: List[Dict[str, Any]]):
    with ingest_lock:
        c = _get_or_create_counters_locked(sid)
        if sid not in session_dropped_seqs:
            session_dropped_seqs[sid] = set()
        for act in actions:
            seq = act.get("seq")
            epoch = act.get("epoch", 1) or 1
            if act.get("action") == "dropped":
                if seq is not None:
                    session_dropped_seqs[sid].add(seq)
                else:
                    c.dropped += 1
            label = str(act.get("intended_label", "")).upper()
            if seq is not None and label:
                key = (epoch, seq)
                if len(session_attacker_truth[sid]) < _MAX_DICT_ENTRIES:
                    session_attacker_truth[sid][key] = label
                _evaluate_seq_locked(sid, key)
        if session_dropped_seqs[sid]:
            c.dropped = max(c.dropped, len(session_dropped_seqs[sid]))


def update_drone_telemetry(data: Dict[str, Any]):
    global latest_drone_telemetry, live_divergence_m
    with ingest_lock:
        latest_drone_telemetry = data
        _recompute_divergence_locked()


def update_c2_telemetry(data: Dict[str, Any]):
    global latest_c2_telemetry, live_divergence_m
    with ingest_lock:
        latest_c2_telemetry = data
        _recompute_divergence_locked()


def _recompute_divergence_locked():
    global live_divergence_m
    if latest_drone_telemetry and latest_c2_telemetry:
        d_lat, d_lon = latest_drone_telemetry.get("lat"), latest_drone_telemetry.get("lon")
        c_lat, c_lon = latest_c2_telemetry.get("lat"), latest_c2_telemetry.get("lon")
        if d_lat is not None and d_lon is not None and c_lat is not None and c_lon is not None:
            live_divergence_m = round(haversine_m(d_lat, d_lon, c_lat, c_lon), 2)


def get_live_telemetry() -> Dict[str, Any]:
    with ingest_lock:
        return {
            "drone": latest_drone_telemetry,
            "c2": latest_c2_telemetry,
            "divergence_m": live_divergence_m,
        }


def get_live_state() -> Dict[str, Any]:
    with ingest_lock:
        return {
            "drone": latest_drone_telemetry,
            "c2": latest_c2_telemetry,
            "divergence_m": live_divergence_m,
            "stats": dict(session_stats_cache),
        }
