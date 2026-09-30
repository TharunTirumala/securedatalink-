"""Multi-hop frame-level multiset reconciliation between TX, Attacker, and RX logs."""

import json
from pathlib import Path
from typing import Any, Dict, List, Optional


def load_jsonl(path: Path) -> List[Dict[str, Any]]:
    """Safely load JSONL file, ignoring corrupt/partial lines."""
    if not path.exists():
        return []
    records = []
    try:
        with open(path, "r", encoding="utf-8") as f:
            for line in f:
                line = line.strip()
                if not line:
                    continue
                try:
                    records.append(json.loads(line))
                except json.JSONDecodeError:
                    continue
    except Exception:
        return []
    return records


def reconcile_session(session_dir: Path) -> Dict[str, Any]:
    """Perform deterministic multiset reconciliation across all node logs."""
    all_tx = load_jsonl(session_dir / "tx_manifest.jsonl")
    tx_records = [r for r in all_tx if r.get("frame_sha256")]
    atk_records = load_jsonl(session_dir / "attacker_log.jsonl")
    rx_events = load_jsonl(session_dir / "rx_events.jsonl")
    rx_outputs = load_jsonl(session_dir / "rx_output.jsonl")

    total_sent = len(tx_records)
    total_rx_events = len(rx_events)
    total_delivered = len(rx_outputs)

    # Map TX frames: sha -> list of tx records
    tx_by_sha: Dict[str, List[Dict[str, Any]]] = {}
    for r in tx_records:
        sha = r.get("frame_sha256")
        if sha:
            tx_by_sha.setdefault(sha, []).append(r)

    # Map Attacker: in_sha -> list of records, out_sha -> list of records
    atk_by_in: Dict[str, List[Dict[str, Any]]] = {}
    atk_by_out: Dict[str, List[Dict[str, Any]]] = {}
    for r in atk_records:
        i_sha = r.get("in_sha256")
        o_sha = r.get("out_sha256")
        if i_sha:
            atk_by_in.setdefault(i_sha, []).append(r)
        if o_sha:
            atk_by_out.setdefault(o_sha, []).append(r)

    # Categorize RX events
    verdict_counts = {
        "AUTHENTIC": 0, "TAMPERED": 0, "REPLAYED": 0,
        "OUT_OF_WINDOW": 0, "RATE_LIMITED": 0, "DROPPED": 0, "UNPROTECTED": 0
    }
    false_accepts = 0
    false_rejects = 0

    for ev in rx_events:
        v = ev.get("verdict", "UNKNOWN")
        verdict_counts[v] = verdict_counts.get(v, 0) + 1
        ev_sha = ev.get("frame_sha256")

        # Determine authenticity
        was_in_tx = ev_sha in tx_by_sha
        atk_mutated = False
        if ev_sha in atk_by_out:
            # Check if attacker records for this out_sha performed mutation
            for ar in atk_by_out[ev_sha]:
                if ar.get("action") in ("tampered", "spoofed", "mutated"):
                    atk_mutated = True
                    break

        if v in ("AUTHENTIC", "UNPROTECTED"):
            if not was_in_tx or atk_mutated:
                false_accepts += 1
        elif v in ("TAMPERED", "REPLAYED", "DROPPED"):
            # Check if this frame was actually untouched by attacker
            if was_in_tx and not atk_mutated and ev.get("verdict") == "TAMPERED":
                false_rejects += 1

    # Attacker drops
    dropped_by_attacker = sum(1 for r in atk_records if r.get("action") == "dropped")
    tampered_by_attacker = sum(1 for r in atk_records if r.get("action") in ("tampered", "mutated"))

    # Missing attribution
    missing_count = max(0, total_sent - total_delivered)
    tampered_and_rejected = verdict_counts.get("TAMPERED", 0)
    unexplained = max(0, missing_count - dropped_by_attacker - tampered_and_rejected)

    # Timeline generation (sample first 200 events for UI)
    timeline = []
    combined_timeline = []
    for r in atk_records:
        if r.get("action") != "pass":
            combined_timeline.append({
                "ts": r.get("ts", 0),
                "type": "attacker",
                "label": f"Attacker {r.get('action')}",
                "detail": f"mode={r.get('mode_at_time')} field={r.get('field_changed')}"
            })
    for r in rx_events:
        combined_timeline.append({
            "ts": r.get("ts", 0),
            "type": "verdict",
            "label": f"RX {r.get('verdict')}",
            "detail": f"seq={r.get('seq')} reason={r.get('reason')}"
        })
    combined_timeline.sort(key=lambda x: x.get("ts", 0))
    timeline = combined_timeline[:200]

    return {
        "summary": {
            "total_sent": total_sent,
            "total_rx_events": total_rx_events,
            "total_delivered": total_delivered,
            "authentic": verdict_counts.get("AUTHENTIC", 0),
            "tampered": verdict_counts.get("TAMPERED", 0),
            "replayed": verdict_counts.get("REPLAYED", 0),
            "dropped_by_attacker": dropped_by_attacker,
            "tampered_by_attacker": tampered_by_attacker,
            "false_accepts": false_accepts,
            "false_rejects": false_rejects,
            "missing_frames": missing_count,
            "missing_attribution": {
                "dropped_by_attacker": dropped_by_attacker,
                "tampered_and_rejected": tampered_and_rejected,
                "unexplained": unexplained,
            }
        },
        "verdict_counts": verdict_counts,
        "timeline": timeline,
    }
