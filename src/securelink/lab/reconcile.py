"""Reconciliation engine for File Lab verification results against original dataset."""

import json
from typing import List, Dict, Any, Optional, Set, Tuple


def reconcile(
    results: List[Dict[str, Any]],
    labels: Dict[str, str],
    manifest: Dict[str, Any],
    source_rows: List[Dict[str, Any]],
) -> Dict[str, Any]:
    """Reconcile deterministic RX verification results against harness ground truth and original source dataset.

    Returns summary metrics, delivery audit, stream gap detection, and decoded clean C2 output.
    """
    counts_by_verdict: Dict[str, int] = {
        "authentic": 0,
        "tampered": 0,
        "replayed": 0,
        "spoofed": 0,
        "dropped": 0,
    }

    attacked_frames = 0
    correctly_rejected = 0
    false_accepts = 0
    false_rejects = 0
    exact_label_match = 0
    unlabeled = 0

    clean_output: List[Dict[str, Any]] = []
    delivered_row_indices: Set[int] = set()
    duplicates_delivered = 0
    content_mismatch = 0

    authentic_by_stream: Dict[Tuple[int, int], List[int]] = {}

    for row in results:
        eid = str(row.get("eid", ""))
        verdict = str(row.get("verdict", "")).upper()
        v_lower = verdict.lower()
        if v_lower in counts_by_verdict:
            counts_by_verdict[v_lower] += 1
        else:
            counts_by_verdict[v_lower] = 1

        intended = labels.get(eid)
        row["intended"] = intended
        if intended is None or intended == "UNKNOWN":
            unlabeled += 1
            row["classification"] = "UNLABELED"
        elif intended == "AUTHENTIC":
            if verdict == "AUTHENTIC":
                exact_label_match += 1
                row["classification"] = "AUTHENTIC"
            else:
                false_rejects += 1
                row["classification"] = "FALSE_REJECT"
        else:
            # Intended is an attack: TAMPERED, REPLAYED, SPOOFED, DROPPED
            attacked_frames += 1
            if verdict != "AUTHENTIC":
                correctly_rejected += 1
                row["classification"] = "REJECTED"
            else:
                false_accepts += 1
                row["classification"] = "FALSE_ACCEPT"

            if verdict == intended:
                exact_label_match += 1

        # C2 Delivery and Content Integrity audit
        if verdict == "AUTHENTIC":
            payload_raw = row.get("payload")
            decoded_row = None
            if payload_raw:
                if isinstance(payload_raw, bytes):
                    payload_str = payload_raw.decode("utf-8", errors="replace")
                else:
                    payload_str = str(payload_raw)
                row["payload"] = payload_str
                try:
                    decoded_row = json.loads(payload_str)
                except Exception:
                    decoded_row = payload_str

            if decoded_row is not None:
                clean_output.append(decoded_row)

            # Reconcile against manifest
            m_info = manifest.get(eid) or manifest.get(str(row.get("n", "")))
            if m_info and "row_index" in m_info:
                row_idx = int(m_info["row_index"])
                if row_idx in delivered_row_indices:
                    duplicates_delivered += 1
                delivered_row_indices.add(row_idx)

                if 0 <= row_idx < len(source_rows):
                    expected_row = source_rows[row_idx]
                    if decoded_row != expected_row:
                        content_mismatch += 1

            # Sequence tracking for stream gap analysis
            seq = row.get("seq")
            ep = row.get("epoch", 1)
            sid = row.get("sender_id", 1)
            if seq is not None:
                authentic_by_stream.setdefault((sid, ep), []).append(seq)

    # Sequence gaps detection
    gaps: List[Dict[str, Any]] = []
    manifest_by_epoch: Dict[int, List[int]] = {}
    for m in manifest.values():
        ep_val = m.get("epoch")
        seq_val = m.get("seq")
        if ep_val is not None and seq_val is not None:
            manifest_by_epoch.setdefault(int(ep_val), []).append(int(seq_val))

    for ep_val in manifest_by_epoch:
        manifest_by_epoch[ep_val].sort()

    for (sid, ep), seqs in authentic_by_stream.items():
        s_sorted = sorted(seqs)
        m_seqs = manifest_by_epoch.get(ep, [])
        if m_seqs and s_sorted and s_sorted[0] > m_seqs[0]:
            gaps.append({
                "sender_id": sid,
                "epoch": ep,
                "expected_seq": m_seqs[0],
                "found_seq": s_sorted[0],
                "gap_size": s_sorted[0] - m_seqs[0],
            })
        for i in range(len(s_sorted) - 1):
            if s_sorted[i + 1] > s_sorted[i] + 1:
                gaps.append({
                    "sender_id": sid,
                    "epoch": ep,
                    "expected_seq": s_sorted[i] + 1,
                    "found_seq": s_sorted[i + 1],
                    "gap_size": s_sorted[i + 1] - s_sorted[i] - 1,
                })
        if m_seqs and s_sorted and s_sorted[-1] < m_seqs[-1]:
            gaps.append({
                "sender_id": sid,
                "epoch": ep,
                "expected_seq": s_sorted[-1] + 1,
                "found_seq": m_seqs[-1] + 1,
                "gap_size": m_seqs[-1] - s_sorted[-1],
            })

    total_source_rows = len(source_rows)
    delivered_count = len(delivered_row_indices)
    missing_rows = [i for i in range(total_source_rows) if i not in delivered_row_indices]
    suppressed = total_source_rows - delivered_count

    delivery = {
        "source_rows": total_source_rows,
        "delivered": delivered_count,
        "delivered_rows": delivered_count,
        "suppressed": suppressed,
        "suppressed_at_gate": suppressed,
        "missing_rows": missing_rows,
        "duplicates_delivered": duplicates_delivered,
        "content_mismatch": content_mismatch,
        "content_mismatches": content_mismatch,
    }

    return {
        "total": len(results),
        "authentic": counts_by_verdict.get("authentic", 0),
        "counts_by_verdict": counts_by_verdict,
        "attacked_frames": attacked_frames,
        "correctly_rejected": correctly_rejected,
        "false_accepts": false_accepts,
        "false_rejects": false_rejects,
        "exact_label_match": exact_label_match,
        "unlabeled": unlabeled,
        "delivery": delivery,
        "gaps": gaps,
        "clean_output": clean_output,
    }


def build_feed_rows(
    results: List[Dict[str, Any]],
    labels: Dict[str, str],
    manifest: Dict[str, Any],
    source_rows: List[Dict[str, Any]],
    original_entries: Optional[List[Dict[str, Any]]] = None,
) -> Dict[str, Any]:
    """Build unified wire-ordered feed rows with status badges, ghost rows, and incident stream."""
    counts: Dict[str, int] = {
        "AUTHENTIC": 0, "TAMPERED": 0, "REPLAYED": 0, "SPOOFED": 0, "DROPPED": 0, "OTHER": 0, "total": 0,
    }
    rows: List[Dict[str, Any]] = []
    incidents: List[Dict[str, Any]] = []
    results_by_eid: Dict[str, Dict[str, Any]] = {str(r.get("eid", "")): r for r in results}

    ghost_entries: List[Dict[str, Any]] = []
    if original_entries:
        for idx, orig in enumerate(original_entries, start=1):
            oeid = str(orig.get("eid") or orig.get("n", idx))
            if oeid not in results_by_eid:
                orig_ep, orig_seq, orig_sender = None, None, orig.get("sender_id", 1)
                raw = bytes(orig.get("raw_bytes", b""))
                if len(raw) >= 20:
                    try:
                        from securelink.protocol.codec import unpack_header
                        hdr = unpack_header(raw)
                        orig_ep, orig_seq, orig_sender = hdr.key_epoch, hdr.seq, hdr.sender_id
                    except Exception:
                        pass
                ghost_entries.append({
                    "line": idx, "eid": oeid, "n": orig.get("n", idx),
                    "epoch": orig_ep, "seq": orig_seq, "sender_id": orig_sender,
                    "verdict": "DROPPED", "reason": "FRAME_REMOVED", "latency_us": 0.0,
                    "t": orig.get("t", 0.0), "truth": "DROPPED", "caught": True,
                    "edit_kind": "drop", "dropped": True,
                })

    combined = list(results)
    if ghost_entries:
        combined.extend(ghost_entries)
        combined.sort(key=lambda x: (int(x.get("n", 0)) if x.get("n") is not None else 999999, float(x.get("t", 0.0))))

    for idx, r in enumerate(combined, start=1):
        eid = str(r.get("eid", ""))
        verdict = str(r.get("verdict", "")).upper()
        reason = str(r.get("reason", "")).upper()
        is_dropped = bool(r.get("dropped", False))
        truth = labels.get(eid) or r.get("intended") or ("DROPPED" if is_dropped else "AUTHENTIC")
        truth = str(truth).upper()

        if truth in ("TAMPERED", "REPLAYED", "SPOOFED", "DROPPED"):
            caught = (verdict != "AUTHENTIC")
        elif truth == "AUTHENTIC":
            caught = (verdict == "AUTHENTIC")
        else:
            caught = None

        edit_kind = None
        if truth == "TAMPERED":
            edit_kind = "tamper"
        elif truth == "REPLAYED":
            edit_kind = "replay"
        elif truth == "SPOOFED":
            edit_kind = "spoof"
        elif truth == "DROPPED":
            edit_kind = "drop"

        feed_row = {
            "line": r.get("line", idx), "eid": eid, "n": r.get("n", idx),
            "epoch": r.get("epoch"), "seq": r.get("seq"), "sender_id": r.get("sender_id", 1),
            "verdict": verdict, "reason": reason, "latency_us": r.get("latency_us"),
            "t": r.get("t"), "truth": truth, "caught": caught,
            "edit_kind": edit_kind, "dropped": is_dropped,
        }
        rows.append(feed_row)

        if verdict in counts:
            counts[verdict] += 1
        else:
            counts["OTHER"] += 1
        counts["total"] += 1

        if verdict != "AUTHENTIC":
            incidents.append({
                "incident_id": eid, "eid": eid, "line": feed_row["line"],
                "epoch": feed_row["epoch"], "seq": feed_row["seq"], "t": feed_row["t"],
                "verdict": verdict, "reason": reason, "truth": truth, "caught": caught,
            })

    epoch_changes: List[Dict[str, Any]] = []
    last_epoch = None
    for idx, r in enumerate(rows):
        ep = r.get("epoch")
        if ep is not None:
            if last_epoch is not None and ep != last_epoch:
                epoch_changes.append({"at_index": idx, "from_epoch": last_epoch, "to_epoch": ep})
            last_epoch = ep

    return {
        "rows": rows, "counts": counts, "epoch_changes": epoch_changes, "incidents": incidents,
    }
