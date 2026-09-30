"""Unit tests for manual edit operations (tamper, replay, spoof, drop) in File Lab."""

import copy
from securelink.simulation.manual.edits import create_edit_entry, apply_edits
from securelink.protocol.constants import HEADER_SIZE, TAG_SIZE, SIGNATURE_SIZE


def _make_dummy_entries(count=5):
    entries = []
    for i in range(1, count + 1):
        # 20 bytes header + 20 bytes cipher + 16 bytes tag + 64 bytes sig = 120 bytes
        raw = bytes([i] * 120)
        entries.append({
            "eid": str(i),
            "n": i,
            "t": 100.0 + i,
            "hex": raw.hex(),
            "raw_bytes": raw,
        })
    return entries


def test_tamper_edit():
    entries = _make_dummy_entries(3)
    orig_copy = copy.deepcopy(entries)

    edit = create_edit_entry("tamper", {"eid": "2", "target": "ciphertext", "xor_mask": 0xFF})
    working, labels = apply_edits(entries, [edit])

    assert len(working) == 3
    # Frame 2 is tampered
    assert working[1]["raw_bytes"] != orig_copy[1]["raw_bytes"]
    assert "TAMPERED" in working[1]["marks"]
    assert labels["2"] == "TAMPERED"

    # Frame 1 and 3 are untouched
    assert working[0]["raw_bytes"] == orig_copy[0]["raw_bytes"]
    assert labels["1"] == "AUTHENTIC"
    assert labels["3"] == "AUTHENTIC"

    # Original entries list was not modified
    assert entries[1]["raw_bytes"] == orig_copy[1]["raw_bytes"]


def test_replay_edit():
    entries = _make_dummy_entries(3)
    edit = create_edit_entry("replay", {"source_eid": "1", "insert_after_eid": "2", "delay_s": 2.5})
    working, labels = apply_edits(entries, [edit])

    assert len(working) == 4
    # Inserted frame is at index 2 (after frame eid "2")
    replayed = working[2]
    assert replayed["eid"].startswith("rep_")
    assert replayed["raw_bytes"] == entries[0]["raw_bytes"]
    assert replayed["t"] == entries[1]["t"] + 2.5
    assert labels[replayed["eid"]] == "REPLAYED"


def test_spoof_edit():
    entries = _make_dummy_entries(2)
    edit = create_edit_entry("spoof", {"insert_after_eid": "1", "count": 2, "mode": "forged_valid_format"})
    working, labels = apply_edits(entries, [edit])

    assert len(working) == 4
    s1, s2 = working[1], working[2]
    assert s1["eid"].startswith("spf_")
    assert s2["eid"].startswith("spf_")
    assert labels[s1["eid"]] == "SPOOFED"
    assert labels[s2["eid"]] == "SPOOFED"


def test_drop_edit():
    entries = _make_dummy_entries(5)
    edit = create_edit_entry("drop", {"eid_from": "2", "eid_to": "4"})
    working, labels = apply_edits(entries, [edit])

    assert len(working) == 5
    assert working[0]["dropped"] is False
    assert working[1]["dropped"] is True
    assert working[2]["dropped"] is True
    assert working[3]["dropped"] is True
    assert working[4]["dropped"] is False
    assert labels["3"] == "DROPPED"


def test_reset_clears_edits():
    entries = _make_dummy_entries(3)
    edits = [
        create_edit_entry("tamper", {"eid": "1"}),
        create_edit_entry("spoof", {"count": 1}),
    ]
    working, labels = apply_edits(entries, edits)
    assert len(working) == 4

    # Reset with empty edit log
    reset_working, reset_labels = apply_edits(entries, [])
    assert len(reset_working) == 3
    assert all(it["dropped"] is False for it in reset_working)
    assert all(it["marks"] == [] for it in reset_working)
    assert all(lbl == "AUTHENTIC" for lbl in reset_labels.values())
