"""Manual attack edit operations and pure edit log application for File Lab.

This module NEVER imports from crypto/keystore.py, crypto/kdf.py, crypto/aead.py, or pipeline/rx_pipeline.py.
"""

import copy
import time
import secrets
from typing import List, Dict, Any, Tuple, Optional
from securelink.protocol.layout import field_ranges, get_field_range
from securelink.simulation.manual.forge import forge_frame


def create_edit_entry(op: str, params: Dict[str, Any], ts: Optional[float] = None) -> Dict[str, Any]:
    """Create a standardized edit log entry with an intended ground-truth label."""
    intended_map = {
        "tamper": "TAMPERED",
        "replay": "REPLAYED",
        "spoof": "SPOOFED",
        "drop": "DROPPED",
    }
    if op not in intended_map:
        raise ValueError(f"Unknown edit operation '{op}'")
    if op == "tamper" and params.get("xor_mask") == 0:
        raise ValueError("xor_mask cannot be 0")

    return {
        "edit_id": f"edt_{secrets.token_hex(4)}",
        "op": op,
        "params": params,
        "intended_label": intended_map[op],
        "ts": ts if ts is not None else time.time(),
    }



def _resolve_tamper_offset(target: str, byte_offset: Optional[int], frame_len: int) -> int:
    """Resolve the absolute byte index to tamper based on target field and layout."""
    target_to_field = {
        "header_sender": "sender_id",
        "header_epoch": "key_epoch",
        "header_seq": "seq",
        "header_ts": "timestamp",
        "ciphertext": "ciphertext",
        "tag": "tag",
        "signature": "signature",
    }
    if target == "any_byte":
        offset = byte_offset if byte_offset is not None else 0
        return max(0, min(offset, frame_len - 1))

    field_name = target_to_field.get(target, target)
    fr = get_field_range(field_name, frame_len)
    start, end = fr["start"], fr["end"]
    if byte_offset is not None:
        idx = start + byte_offset
        return max(start, min(idx, end - 1))
    return start  # default to first byte of field


def apply_edits(
    original_entries: List[Dict[str, Any]],
    edit_log: List[Dict[str, Any]],
) -> Tuple[List[Dict[str, Any]], Dict[str, str]]:
    """Pure function: applies sequential edit operations to original entries.

    Returns (working_entries, intended_labels_by_eid).
    Does NOT modify original_entries.
    """
    working: List[Dict[str, Any]] = []
    for item in original_entries:
        working.append({
            "eid": str(item.get("eid", item.get("n"))),
            "n": item.get("n", 0),
            "t": float(item.get("t", 0.0)),
            "hex": item.get("hex", ""),
            "raw_bytes": bytes(item.get("raw_bytes", b"")),
            "origin": "original",
            "marks": list(item.get("marks", [])),
            "dropped": False,
        })

    intended_labels: Dict[str, str] = {}
    # Original entries are baseline authentic
    for item in working:
        intended_labels[item["eid"]] = "AUTHENTIC"

    for edit in edit_log:
        op = edit.get("op")
        params = edit.get("params", {})
        edit_id = edit.get("edit_id", "e")

        if op == "tamper":
            target_eid = str(params.get("eid"))
            target_field = params.get("target", "ciphertext")
            offset_param = params.get("byte_offset")
            xor_mask = int(params.get("xor_mask") or 0x01)

            for item in working:
                if item["eid"] == target_eid:
                    raw = bytearray(item["raw_bytes"])
                    if len(raw) > 0:
                        abs_offset = _resolve_tamper_offset(target_field, offset_param, len(raw))
                        raw[abs_offset] ^= xor_mask
                        item["raw_bytes"] = bytes(raw)
                        item["hex"] = bytes(raw).hex()
                        if "TAMPERED" not in item["marks"]:
                            item["marks"].append("TAMPERED")
                        intended_labels[target_eid] = "TAMPERED"
                    break

        elif op == "replay":
            src_eid = str(params.get("source_eid"))
            insert_after = str(params.get("insert_after_eid")) if params.get("insert_after_eid") else None
            delay_s = float(params.get("delay_s", 1.0))

            source_item = next((it for it in working if it["eid"] == src_eid), None)
            if source_item:
                new_eid = f"rep_{edit_id}_{src_eid}"
                insert_idx = len(working)
                base_t = source_item["t"]
                if insert_after:
                    for i, it in enumerate(working):
                        if it["eid"] == insert_after:
                            insert_idx = i + 1
                            base_t = it["t"]
                            break

                replayed_entry = {
                    "eid": new_eid,
                    "n": source_item["n"],
                    "t": base_t + delay_s,
                    "hex": source_item["hex"],
                    "raw_bytes": source_item["raw_bytes"],
                    "origin": "replayed",
                    "marks": ["REPLAYED"],
                    "dropped": False,
                }
                working.insert(insert_idx, replayed_entry)
                intended_labels[new_eid] = "REPLAYED"

        elif op == "spoof":
            insert_after = str(params.get("insert_after_eid")) if params.get("insert_after_eid") else None
            count = max(1, min(int(params.get("count", 1)), 50))
            mode = params.get("mode", "forged_valid_format")

            insert_idx = len(working)
            base_t = time.time()
            if insert_after:
                for i, it in enumerate(working):
                    if it["eid"] == insert_after:
                        insert_idx = i + 1
                        base_t = it["t"]
                        break

            for c in range(count):
                new_eid = f"spf_{edit_id}_{c + 1}"
                forged_bytes = forge_frame(mode=mode, timestamp=base_t + (c * 0.1))
                spoofed_entry = {
                    "eid": new_eid,
                    "n": 0,
                    "t": base_t + (c * 0.1),
                    "hex": forged_bytes.hex(),
                    "raw_bytes": forged_bytes,
                    "origin": "spoofed",
                    "marks": ["SPOOFED"],
                    "dropped": False,
                }
                working.insert(insert_idx + c, spoofed_entry)
                intended_labels[new_eid] = "SPOOFED"

        elif op == "drop":
            eid_from = str(params.get("eid_from"))
            eid_to = str(params.get("eid_to", eid_from))

            in_range = False
            for it in working:
                if it["eid"] == eid_from:
                    in_range = True
                if in_range:
                    it["dropped"] = True
                    if "DROPPED" not in it["marks"]:
                        it["marks"].append("DROPPED")
                    intended_labels[it["eid"]] = "DROPPED"
                if it["eid"] == eid_to:
                    in_range = False

    orig_bytes_map = {
        str(item.get("eid", item.get("n"))): bytes(item.get("raw_bytes", b""))
        for item in original_entries
    }
    for item in working:
        eid = item["eid"]
        if eid in orig_bytes_map:
            if item["raw_bytes"] == orig_bytes_map[eid]:
                item["effective"] = False
                if "TAMPERED" in item["marks"]:
                    item["marks"].remove("TAMPERED")
                if intended_labels.get(eid) == "TAMPERED":
                    intended_labels[eid] = "AUTHENTIC"
            else:
                item["effective"] = True
        else:
            item["effective"] = True

    return working, intended_labels
