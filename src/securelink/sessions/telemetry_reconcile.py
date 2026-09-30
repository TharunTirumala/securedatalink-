"""Telemetry-level reconciliation comparing Drone Truth with C2 Received messages."""

import json
import math
from pathlib import Path
from typing import Any, Dict, List, Optional


def load_jsonl(path: Path) -> List[Dict[str, Any]]:
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


def haversine_m(lat1: float, lon1: float, lat2: float, lon2: float) -> float:
    """Compute distance in meters between two lat/lon points."""
    r = 6371000.0
    phi1, phi2 = math.radians(lat1), math.radians(lat2)
    dphi = math.radians(lat2 - lat1)
    dlambda = math.radians(lon2 - lon1)
    a = (math.sin(dphi / 2.0) ** 2 +
         math.cos(phi1) * math.cos(phi2) * math.sin(dlambda / 2.0) ** 2)
    c = 2.0 * math.atan2(math.sqrt(a), math.sqrt(1.0 - a))
    return r * c


def reconcile_telemetry(session_dir: Path) -> Dict[str, Any]:
    """Compare drone truth telemetry vs C2 received telemetry for divergence."""
    truth_records = load_jsonl(session_dir / "drone_truth.jsonl")
    c2_records = load_jsonl(session_dir / "c2_received.jsonl")

    # Index c2 records by time_boot_ms when available, else msg_type FIFO
    c2_by_time: Dict[str, Dict[int, Dict[str, Any]]] = {}
    c2_by_type: Dict[str, List[Dict[str, Any]]] = {}
    for r in c2_records:
        mtype = r.get("msg_type")
        tb = r.get("time_boot_ms")
        if mtype:
            c2_by_type.setdefault(mtype, []).append(r)
            if tb is not None:
                c2_by_time.setdefault(mtype, {})[tb] = r

    matched = 0
    identical = 0
    altered = 0
    pos_errors: List[float] = []
    path_comparison: List[Dict[str, Any]] = []

    for tr in truth_records:
        mtype = tr.get("msg_type")
        tb = tr.get("time_boot_ms")
        c2r = None
        if mtype and tb is not None:
            if mtype in c2_by_time and tb in c2_by_time[mtype]:
                c2r = c2_by_time[mtype].pop(tb)
        elif mtype and mtype in c2_by_type and c2_by_type[mtype]:
            c2r = c2_by_type[mtype].pop(0)

        if not c2r:
            continue

        matched += 1

        t_lat, t_lon = tr.get("lat"), tr.get("lon")
        c_lat, c_lon = c2r.get("lat"), c2r.get("lon")

        is_altered = False
        err_m = 0.0

        if t_lat is not None and c_lat is not None and t_lon is not None and c_lon is not None:
            err_m = haversine_m(t_lat, t_lon, c_lat, c_lon)
            pos_errors.append(err_m)
            if err_m > 1.0:  # More than 1 meter divergence
                is_altered = True

        t_alt, c_alt = tr.get("alt"), c2r.get("alt")
        if t_alt is not None and c_alt is not None and abs(t_alt - c_alt) > 1.0:
            is_altered = True

        t_bat, c_bat = tr.get("bat"), c2r.get("bat")
        if t_bat is not None and c_bat is not None and abs(t_bat - c_bat) > 0:
            is_altered = True

        if is_altered:
            altered += 1
        else:
            identical += 1

        if len(path_comparison) < 100 and t_lat is not None:
            path_comparison.append({
                "msg_seq": tr.get("msg_seq"),
                "msg_type": tr.get("msg_type"),
                "truth": {"lat": t_lat, "lon": t_lon, "alt": t_alt},
                "c2": {"lat": c_lat, "lon": c_lon, "alt": c_alt},
                "error_m": round(err_m, 2),
                "altered": is_altered,
            })

    max_err = max(pos_errors) if pos_errors else 0.0
    mean_err = (sum(pos_errors) / len(pos_errors)) if pos_errors else 0.0

    return {
        "truth_messages": len(truth_records),
        "c2_messages": len(c2_records),
        "matched_messages": matched,
        "delivered_identical": identical,
        "delivered_altered": altered,
        "max_position_error_m": round(max_err, 2),
        "mean_position_error_m": round(mean_err, 2),
        "path_comparison": path_comparison,
    }
