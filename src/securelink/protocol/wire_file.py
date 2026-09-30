"""JSONL Wire-File Reader and Writer with tolerant parsing and strict size limits."""

import io
import json
import hashlib
from pathlib import Path
from typing import List, Dict, Any, Tuple, Union, Optional

MAX_FILE_BYTES: int = 10 * 1024 * 1024  # 10 MB
MAX_LINES: int = 50000


def compute_key_fp(master_secret: bytes) -> str:
    """Compute 8-character hex fingerprint of the master secret for mismatch detection."""
    return hashlib.sha256(b"securelink-fp|" + bytes(master_secret)).hexdigest()[:8]


def write_wire_file(
    meta: Dict[str, Any],
    frames: List[Dict[str, Any]],
    output_path: Optional[Union[str, Path]] = None,
) -> str:
    """Serialize metadata header and frames to JSONL format.

    Returns the formatted string. If output_path is given, writes to disk.
    """
    lines: List[str] = []
    meta_line = {
        "type": "meta",
        "format": meta.get("format", 1),
        "file_id": meta.get("file_id", ""),
        "created": meta.get("created", 0.0),
        "sender_id": meta.get("sender_id", 1),
        "key_fp": meta.get("key_fp", ""),
        "frame_count": len(frames),
        "source_kind": meta.get("source_kind", "dataset"),
        "source_name": meta.get("source_name", meta.get("name", "")),
        "rate_pps": meta.get("rate_pps", 100),
        "rekey_every_packets": meta.get("rekey_every_packets", 100),
    }
    if meta.get("seed") is not None:
        meta_line["seed"] = meta["seed"]
    if meta.get("parent_id") is not None:
        meta_line["parent_id"] = meta["parent_id"]
    if "name" in meta:
        meta_line["name"] = meta["name"]
    lines.append(json.dumps(meta_line))

    for idx, f in enumerate(frames, start=1):
        hex_data = f.get("hex")
        if hex_data is None and "raw_bytes" in f:
            hex_data = f["raw_bytes"].hex()
        entry = {
            "type": "frame",
            "n": f.get("n", idx),
            "t": round(float(f.get("t", 0.0)), 6),
            "hex": hex_data or "",
        }
        lines.append(json.dumps(entry))

    content = "\n".join(lines) + "\n"
    if output_path:
        p = Path(output_path)
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(content, encoding="utf-8")
    return content


def read_wire_file(
    source: Union[str, Path],
) -> Tuple[Dict[str, Any], List[Dict[str, Any]], List[str]]:
    """Parse JSONL wire file with tolerant error handling.

    Returns (metadata_dict, frame_entries, error_messages).
    Raises ValueError on files exceeding 10 MB or 50,000 lines.
    """
    if isinstance(source, Path) or (isinstance(source, str) and len(source) < 500 and "\n" not in source and Path(source).is_file()):
        p = Path(source)
        if p.stat().st_size > MAX_FILE_BYTES:
            raise ValueError(f"File exceeds 10 MB limit ({p.stat().st_size} bytes)")
        raw_text = p.read_text(encoding="utf-8")
    else:
        raw_text = str(source)
        if len(raw_text.encode("utf-8")) > MAX_FILE_BYTES:
            raise ValueError("Input text exceeds 10 MB limit")

    lines = raw_text.splitlines()
    if len(lines) > MAX_LINES:
        raise ValueError(f"File exceeds maximum line limit of {MAX_LINES} lines ({len(lines)} lines)")

    meta: Dict[str, Any] = {}
    entries: List[Dict[str, Any]] = []
    errors: List[str] = []

    if not lines:
        return meta, entries, ["Empty wire file"]

    # Line 1: Meta
    first_line = lines[0].strip()
    try:
        parsed_meta = json.loads(first_line)
        if parsed_meta.get("type") == "meta":
            meta = parsed_meta
        else:
            errors.append("First line is not a valid 'meta' object; using fallback")
            meta = {"type": "meta", "format": 1, "key_fp": ""}
    except Exception as exc:
        errors.append(f"Failed to parse metadata header: {exc}")
        meta = {"type": "meta", "format": 1, "key_fp": ""}

    # Lines 2..N: Frame entries (tolerant parsing)
    last_t = 0.0
    for idx, line in enumerate(lines[1:], start=1):
        s = line.strip()
        if not s:
            continue
        try:
            item = json.loads(s)
            hex_str = item.get("hex", "")
            raw_bytes = bytes.fromhex(hex_str)
            t_val = item.get("t")
            entry_t = float(t_val) if t_val is not None else last_t
            last_t = entry_t

            entries.append({
                "eid": str(idx),
                "n": item.get("n", idx),
                "t": entry_t,
                "hex": hex_str,
                "raw_bytes": raw_bytes,
                "is_malformed": False,
            })
        except Exception as exc:
            # Tolerant recovery: bad JSON or invalid hex becomes a malformed entry
            errors.append(f"Line {idx + 1} malformed: {exc}")
            entries.append({
                "eid": str(idx),
                "n": idx,
                "t": last_t,
                "hex": "",
                "raw_bytes": b"\x00" * 20,  # Treated as malformed frame during verification
                "is_malformed": True,
                "raw_line": s,
            })

    return meta, entries, errors
