"""Pure deterministic verification runner for File Lab frames."""

import time
from typing import List, Dict, Any, Optional
from securelink.crypto.keystore import KeyStore
from securelink.pipeline.rx_pipeline import RxPipeline
from securelink.pipeline.replay_guard import ReplayGuard
from securelink.pipeline.operator_state import OperatorState
from securelink.core.types import Verdict, Reason


def verify_frames(
    entries: List[Dict[str, Any]],
    keystore: KeyStore,
    rekey_grace_epochs: int = 1,
) -> List[Dict[str, Any]]:
    """Execute fresh, deterministic RX verification across an ordered list of frame entries.

    NOTE: Signature contains NO ground-truth labels parameter to maintain strict separation.
    Uses recorded entry arrival timestamps 't' to drive simulated clocking.
    """
    replay_guard = ReplayGuard(
        window_size=64,
        max_clock_skew=30.0,
        enforce_timestamp=True,
    )
    rx = RxPipeline(
        keystore=keystore.to_public_keystore(),
        replay_guard=replay_guard,
        rekey_grace_epochs=rekey_grace_epochs,
        operator_state=OperatorState(),
    )

    results: List[Dict[str, Any]] = []

    for idx, entry in enumerate(entries, start=1):
        eid = str(entry.get("eid") or entry.get("n", idx))
        arrival_t = float(entry.get("t", 0.0))
        is_dropped = bool(entry.get("dropped", False))

        if is_dropped:
            drop_epoch, drop_seq, drop_sender = None, None, entry.get("sender_id", 1)
            raw = bytes(entry.get("raw_bytes", b""))
            if len(raw) >= 20:
                try:
                    from securelink.protocol.codec import unpack_header
                    hdr = unpack_header(raw)
                    drop_epoch, drop_seq, drop_sender = hdr.key_epoch, hdr.seq, hdr.sender_id
                except Exception:
                    pass
            results.append({
                "eid": eid, "n": entry.get("n", 0), "t": arrival_t,
                "verdict": Verdict.DROPPED.value, "reason": Reason.PACKET_DROPPED.value,
                "epoch": drop_epoch, "seq": drop_seq, "sender_id": drop_sender,
                "latency_us": 0.0, "dropped": True,
            })
            continue

        raw_bytes = bytes(entry.get("raw_bytes", b""))
        t0 = time.perf_counter_ns()
        verdict, reason, plaintext, header = rx.process_frame(raw_bytes, current_time=arrival_t)
        latency_us = round((time.perf_counter_ns() - t0) / 1000.0, 1)

        results.append({
            "eid": eid, "n": entry.get("n", 0), "t": arrival_t,
            "verdict": verdict.value, "reason": reason.value,
            "epoch": header.key_epoch if header else None,
            "seq": header.seq if header else None,
            "sender_id": header.sender_id if header else entry.get("sender_id", 1),
            "latency_us": latency_us, "dropped": False,
            "payload": plaintext if verdict == Verdict.AUTHENTIC else None,
        })

    return results
