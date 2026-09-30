"""Lab business logic: import datasets, generate multi-epoch wire captures, and verify."""

import time, secrets
from pathlib import Path
from typing import List, Dict, Any, Tuple, Optional
from securelink.crypto.keystore import KeyStore
from securelink.sources.synthetic import SyntheticTelemetrySource
from securelink.sources.tabular import (
    parse_dataset, row_to_payload, validate_payload_sizes, TabularSource,
)
from securelink.pipeline.tx_pipeline import TxPipeline
from securelink.protocol.wire_file import write_wire_file, read_wire_file, compute_key_fp
from securelink.protocol.layout import field_ranges
from securelink.simulation.manual.edits import apply_edits, create_edit_entry
from securelink.simulation.manual.diff import infer_labels
from securelink.lab.store import (
    generate_file_id, save_wire_file, load_wire_file, save_source_rows, load_source_rows,
    save_manifest, load_manifest, save_edits, load_edits, get_lab_keystore,
    delete_lab_file, validate_file_id, get_file_path, LAB_DATA_DIR, load_inferred_labels,
)
from securelink.lab.verify import verify_frames
from securelink.lab.reconcile import reconcile, build_feed_rows

_last_verify_cache: Dict[str, Dict[str, Any]] = {}


def preview_dataset_content(
    text: str, fmt: str = "auto", columns: Optional[List[str]] = None,
) -> Dict[str, Any]:
    """Parse and return a 5-row sample preview of the dataset."""
    parsed = parse_dataset(text, fmt=fmt, columns=columns)
    validate_payload_sizes(parsed.rows)
    return {
        "format": parsed.format, "columns": parsed.columns,
        "row_count": len(parsed.rows), "sample": parsed.rows[:5], "warnings": parsed.warnings,
    }


def import_dataset_file(
    text: str, name: Optional[str] = None, fmt: str = "auto",
    columns: Optional[List[str]] = None, rate_pps: int = 100, rekey_every_packets: int = 50,
) -> Tuple[str, Dict[str, Any]]:
    """Import a dataset, encrypt and sign each row into a multi-epoch wire capture."""
    parsed = parse_dataset(text, fmt=fmt, columns=columns)
    validate_payload_sizes(parsed.rows)
    file_id = generate_file_id()
    keystore = get_lab_keystore()
    key_fp = compute_key_fp(keystore.master_secret)
    rekey_every_packets = max(5, min(rekey_every_packets, 1000))
    rate_pps = max(1, min(rate_pps, 2000))

    tx = TxPipeline(keystore=keystore, sender_id=1, rekey_every_packets=rekey_every_packets)
    source = TabularSource(parsed.rows, rate_pps=rate_pps, t0=time.time())
    frames, manifest = [], {}

    for n, (ts, payload_bytes, row_idx) in enumerate(source.stream_payloads(), start=1):
        wire_bytes, frame = tx.transmit(payload_bytes, timestamp=ts, seq=None)
        frames.append({"n": n, "t": ts, "raw_bytes": wire_bytes})
        manifest[str(n)] = {
            "epoch": frame.header.key_epoch, "seq": frame.header.seq,
            "row_index": row_idx, "payload_len": len(payload_bytes),
        }

    meta = {
        "file_id": file_id, "name": name or f"Dataset-{file_id[:8]}", "created": time.time(),
        "sender_id": 1, "key_fp": key_fp, "frame_count": len(frames),
        "source_kind": "dataset", "source_name": name or "tabular",
        "rate_pps": rate_pps, "rekey_every_packets": rekey_every_packets,
    }
    save_wire_file(file_id, write_wire_file(meta, frames))
    save_source_rows(file_id, parsed.rows)
    save_manifest(file_id, manifest)
    return file_id, meta


def generate_wire_capture(
    count: int = 100, seed: Optional[int] = None, rekey_every_packets: int = 25, name: Optional[str] = None,
) -> Tuple[str, Dict[str, Any]]:
    """Generate a multi-epoch synthetic capture file."""
    count = max(10, min(count, 5000))
    rekey_every_packets = max(5, min(rekey_every_packets, 1000))
    resolved_seed = seed if seed is not None else secrets.randbits(32)
    keystore = get_lab_keystore()
    key_fp = compute_key_fp(keystore.master_secret)
    file_id = generate_file_id()

    source = SyntheticTelemetrySource(seed=resolved_seed, sender_id=1)
    tx = TxPipeline(keystore=keystore, sender_id=1, rekey_every_packets=rekey_every_packets)
    frames, source_rows, manifest = [], [], {}
    base_t = time.time() - (count * 0.05)

    for seq in range(1, count + 1):
        t = base_t + (seq * 0.05)
        telemetry = source.generate_packet(seq)
        wire_bytes, frame = tx.transmit(telemetry, timestamp=t, seq=seq)
        frames.append({"n": seq, "t": t, "raw_bytes": wire_bytes})
        source_rows.append({
            "lat": telemetry.lat, "lon": telemetry.lon, "alt": telemetry.alt,
            "speed": telemetry.speed, "heading": telemetry.heading, "battery": telemetry.battery,
        })
        manifest[str(seq)] = {"epoch": frame.header.key_epoch, "seq": frame.header.seq, "row_index": seq - 1}

    meta = {
        "file_id": file_id, "name": name or f"Capture-{file_id[:8]}", "created": time.time(),
        "sender_id": 1, "key_fp": key_fp, "frame_count": len(frames), "seed": resolved_seed,
        "source_kind": "synthetic", "source_name": name or "synthetic", "rate_pps": 20,
        "rekey_every_packets": rekey_every_packets,
    }
    save_wire_file(file_id, write_wire_file(meta, frames))
    save_source_rows(file_id, source_rows)
    save_manifest(file_id, manifest)
    return file_id, meta


def list_lab_files() -> List[Dict[str, Any]]:
    """List all stored wire files with metadata, frame count, and key match status."""
    LAB_DATA_DIR.mkdir(parents=True, exist_ok=True)
    keystore = get_lab_keystore()
    current_fp = compute_key_fp(keystore.master_secret)
    files, seen_fids = [], set()

    for p in sorted(LAB_DATA_DIR.glob("*")):
        name = p.name
        if (name.endswith(".source.jsonl") or name.endswith(".manifest.json") or
                name.endswith(".edits.json") or name.endswith(".inferred.json")):
            continue
        fid = name.split(".")[0]
        if fid in seen_fids or len(fid) != 32:
            continue
        seen_fids.add(fid)
        try:
            wire_path = get_file_path(fid)
            if not wire_path.is_file():
                continue
            meta, entries, _ = read_wire_file(wire_path.read_text(encoding="utf-8"))
            edits = load_edits(fid)
            inferred = load_inferred_labels(fid)
            fp = meta.get("key_fp", "")
            files.append({
                "file_id": fid, "name": meta.get("name", fid[:8]),
                "created": meta.get("created", wire_path.stat().st_mtime), "frame_count": len(entries),
                "edit_count": len(edits), "key_match": bool(fp and fp == current_fp),
                "key_fp": fp, "seed": meta.get("seed"),
                "source_kind": meta.get("source_kind", "synthetic"),
                "rekey_every_packets": meta.get("rekey_every_packets", 50),
                "parent_id": meta.get("parent_id"),
                "inferred_count": sum(1 for l in inferred.values() if l != "AUTHENTIC"),
            })
        except Exception:
            continue
    files.sort(key=lambda x: x.get("created", 0), reverse=True)
    return files


def get_lab_file_frames(
    file_id: str, view: str = "working", offset: int = 0, limit: int = 100,
) -> Tuple[Dict[str, Any], List[Dict[str, Any]], int]:
    """Retrieve paginated frame summaries for the requested view."""
    meta, entries, _ = read_wire_file(load_wire_file(file_id))
    if view == "working":
        target_list, _ = apply_edits(entries, load_edits(file_id))
    else:
        target_list = entries

    manifest = load_manifest(file_id)
    total_count = len(target_list)
    slice_entries = target_list[offset : offset + limit]

    rows = []
    for item in slice_entries:
        raw = item.get("raw_bytes", b"")
        epoch = raw[3] if len(raw) >= 12 else None
        seq = int.from_bytes(raw[4:12], byteorder="big") if len(raw) >= 12 else None
        eid = str(item.get("eid", item.get("n", "")))
        m_info = manifest.get(eid) or manifest.get(str(item.get("n")))
        rows.append({
            "eid": eid, "n": item.get("n", 0), "t": item.get("t", 0.0),
            "epoch": epoch, "seq": seq, "size": len(raw),
            "hex_preview": raw[:24].hex() if raw else "",
            "source_row_index": m_info.get("row_index") if m_info else None,
            "origin": item.get("origin", "original"), "marks": item.get("marks", []),
            "dropped": item.get("dropped", False),
        })
    return meta, rows, total_count


def get_frame_detail(file_id: str, eid: str) -> Dict[str, Any]:
    """Retrieve full frame hex and field ranges for byte inspection."""
    _, entries, _ = read_wire_file(load_wire_file(file_id))
    edits = load_edits(file_id)
    working_entries, _ = apply_edits(entries, edits) if edits else (entries, {})
    entry = next((it for it in working_entries if str(it.get("eid", it.get("n", ""))) == str(eid)), None)
    if not entry:
        raise KeyError(f"Frame with eid '{eid}' not found")
    raw = entry.get("raw_bytes", b"")
    return {
        "eid": str(eid), "n": entry.get("n", 0), "t": entry.get("t", 0.0),
        "size": len(raw), "hex": raw.hex(),
        "ranges": field_ranges(len(raw)) if len(raw) >= 100 else [],
        "origin": entry.get("origin", "original"),
        "marks": entry.get("marks", []), "dropped": entry.get("dropped", False),
    }


def verify_lab_file(file_id: str, mode: str = "working") -> Dict[str, Any]:
    """Verify lab file frames, calculate detection metrics, and reconcile with original dataset."""
    meta, original_entries, _ = read_wire_file(load_wire_file(file_id))
    keystore = get_lab_keystore()
    current_fp = compute_key_fp(keystore.master_secret)

    if meta.get("key_fp") != current_fp:
        return {
            "key_match": False,
            "message": "Key fingerprint mismatch: file was generated under a different master secret.",
            "rows": [], "summary": {}, "clean_output": [], "gaps": [],
        }

    if mode == "original":
        parent_id = meta.get("parent_id")
        if parent_id:
            try:
                _, working_entries, _ = read_wire_file(load_wire_file(parent_id))
                manifest = load_manifest(parent_id)
                source_rows = load_source_rows(parent_id)
            except Exception:
                working_entries = original_entries
                manifest = load_manifest(file_id)
                source_rows = load_source_rows(file_id)
        else:
            working_entries = original_entries
            manifest = load_manifest(file_id)
            source_rows = load_source_rows(file_id)
        intended_labels: Dict[str, str] = {}
    else:
        inferred = load_inferred_labels(file_id)
        edits = load_edits(file_id)
        if edits:
            working_entries, edit_labels = apply_edits(original_entries, edits)
            intended_labels = dict(inferred)
            intended_labels.update(edit_labels)
        else:
            working_entries = original_entries
            intended_labels = dict(inferred)
        manifest = load_manifest(file_id)
        source_rows = load_source_rows(file_id)

    grace_epochs = int(meta.get("rekey_grace_epochs", 1))
    verified_rows = verify_frames(working_entries, keystore, rekey_grace_epochs=grace_epochs)
    reconcile_data = reconcile(verified_rows, intended_labels, manifest, source_rows)
    feed_data = build_feed_rows(
        verified_rows, intended_labels, manifest, source_rows, original_entries=original_entries,
    )

    out = {
        "key_match": True, "mode": mode, "rows": verified_rows,
        "summary": reconcile_data, "clean_output": reconcile_data["clean_output"],
        "delivery": reconcile_data["delivery"], "gaps": reconcile_data["gaps"],
        "feed": feed_data,
    }
    _last_verify_cache[f"{file_id}_{mode}"] = out
    return out


def get_last_verification(file_id: str, mode: str = "working") -> Optional[Dict[str, Any]]:
    """Retrieve cached verification results from memory."""
    return _last_verify_cache.get(f"{file_id}_{mode}")
