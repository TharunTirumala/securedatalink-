"""Content-based diff and label inference for uploaded hand-edited wire files.

This module NEVER imports from crypto/keystore.py, crypto/kdf.py, crypto/aead.py, or pipeline/rx_pipeline.py.
"""

from typing import List, Dict, Any, Tuple, Set


def _get_hex(entry: Dict[str, Any]) -> str:
    h = entry.get("hex")
    if h:
        return h
    rb = entry.get("raw_bytes")
    if rb is not None:
        return rb.hex() if isinstance(rb, (bytes, bytearray)) else ""
    return ""


def infer_labels(
    parent_entries: List[Dict[str, Any]],
    uploaded_entries: List[Dict[str, Any]],
) -> Tuple[Dict[str, str], List[int]]:
    """Infer ground-truth labels for uploaded wire frames by comparing against parent frames.

    Returns (labels_by_eid, dropped_ns).
    Matches frames by cryptographic hex content rather than positional index.
    """
    parent_by_n: Dict[int, Dict[str, Any]] = {}
    parent_first_occurrence: Dict[str, int] = {}

    for p in parent_entries:
        pn = p.get("n", 0)
        parent_by_n[pn] = p
        p_hex = _get_hex(p)
        if p_hex and p_hex not in parent_first_occurrence:
            parent_first_occurrence[p_hex] = pn

    labels_by_eid: Dict[str, str] = {}
    seen_uploaded_hexes: Set[str] = set()
    present_uploaded_ns: Set[int] = set()

    for idx, u in enumerate(uploaded_entries, start=1):
        u_eid = str(u.get("eid", u.get("n", idx)))
        u_n = u.get("n")
        u_hex = _get_hex(u)
        is_malformed = u.get("is_malformed", False)

        if is_malformed or not u_hex:
            labels_by_eid[u_eid] = "TAMPERED"
        elif u_hex in seen_uploaded_hexes:
            labels_by_eid[u_eid] = "REPLAYED"
        elif u_hex in parent_first_occurrence:
            orig_n = parent_first_occurrence[u_hex]
            if u_n == orig_n:
                labels_by_eid[u_eid] = "AUTHENTIC"
                present_uploaded_ns.add(u_n)
            else:
                labels_by_eid[u_eid] = "REPLAYED"
        else:
            if u_n is not None and u_n in parent_by_n:
                labels_by_eid[u_eid] = "TAMPERED"
                present_uploaded_ns.add(u_n)
            else:
                labels_by_eid[u_eid] = "SPOOFED"

        if u_hex:
            seen_uploaded_hexes.add(u_hex)

    dropped_ns = [
        p["n"] for p in parent_entries
        if p.get("n") is not None and p["n"] not in present_uploaded_ns
    ]

    return labels_by_eid, dropped_ns
