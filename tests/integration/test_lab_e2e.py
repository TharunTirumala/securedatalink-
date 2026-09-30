"""End-to-end integration tests for Phase 3B File Lab:
1. 500-row CSV with 10 epochs + 4 attacks + reconciliation audit
2. Hand-edited wire file upload flow with diff label inference
3. Formula injection resilience (CSV injection / DDE attacks)
4. Wire file immutability across edits
5. Keystore fingerprint mismatch rejection
"""

import hashlib
import json
import pytest
from securelink.crypto.keystore import KeyStore
from securelink.lab.store import (
    save_edits, load_wire_file, get_lab_keystore, save_wire_file,
    generate_file_id, save_source_rows, save_manifest,
)
from securelink.lab.service import (
    import_dataset_file, generate_wire_capture, verify_lab_file,
)
from securelink.simulation.manual.edits import create_edit_entry
from securelink.simulation.manual.diff import infer_labels
from securelink.protocol.wire_file import read_wire_file, write_wire_file, compute_key_fp
from securelink.lab.verify import verify_frames


def test_e2e_500_row_csv_baseline_and_attacks():
    """Test 500-row CSV across 10 epochs, verify baseline FA=0, FR=0, then apply 4 attacks."""
    csv_lines = ["id,sensor,val,status"]
    for i in range(1, 501):
        csv_lines.append(f"{i},sensor_{i % 5},{i * 1.5},OK")
    csv_text = "\n".join(csv_lines)

    file_id, meta = import_dataset_file(
        text=csv_text, name="e2e-500", fmt="csv", rate_pps=100, rekey_every_packets=50,
    )
    assert meta["frame_count"] == 500
    assert meta["rekey_every_packets"] == 50

    # 1. Baseline verification: original unedited file
    base_res = verify_lab_file(file_id, mode="original")
    assert base_res["key_match"] is True
    assert base_res["summary"]["false_accepts"] == 0
    assert base_res["summary"]["false_rejects"] == 0
    assert base_res["summary"]["authentic"] == 500
    assert base_res["summary"]["correctly_rejected"] == 0
    assert base_res["delivery"]["source_rows"] == 500
    assert base_res["delivery"]["delivered_rows"] == 500
    assert base_res["delivery"]["suppressed_at_gate"] == 0
    assert len(base_res["delivery"]["missing_rows"]) == 0
    assert base_res["delivery"]["content_mismatches"] == 0
    assert len(base_res["gaps"]) == 0

    # 2. Inject 4 attacks: tamper, replay, spoof, drop (2 frames)
    edits = [
        create_edit_entry("tamper", {"eid": "25", "target": "ciphertext", "byte_offset": 4, "xor_mask": 0xFF}),
        create_edit_entry("replay", {"source_eid": "100", "delay_s": 2.0}),
        create_edit_entry("spoof", {"insert_after_eid": "200", "count": 1}),
        create_edit_entry("drop", {"eid_from": "301"}),
        create_edit_entry("drop", {"eid_from": "302"}),
    ]
    save_edits(file_id, edits)

    work_res = verify_lab_file(file_id, mode="working")
    summary = work_res["summary"]
    delivery = work_res["delivery"]

    # Invariants: FA=0 and FR=0 always
    assert summary["false_accepts"] == 0
    assert summary["false_rejects"] == 0
    assert summary["correctly_rejected"] == 5  # tamper + replay + spoof + 2 drops rejected
    assert delivery["delivered_rows"] == 497   # 500 - 1 tampered - 2 dropped
    assert len(delivery["missing_rows"]) == 3  # row 24 tampered + rows 300, 301 dropped
    assert delivery["suppressed_at_gate"] == 3 # 3 rows never reached C2 clean output
    assert delivery["content_mismatches"] == 0 # Decrypted payloads match source rows exactly

    # Sequence gaps detected for dropped seqs 301, 302
    gaps = work_res["gaps"]
    assert len(gaps) >= 1
    dropped_gap = next((g for g in gaps if g["epoch"] == 7), None)
    assert dropped_gap is not None
    assert dropped_gap["expected_seq"] == 1
    assert dropped_gap["found_seq"] == 3
    assert dropped_gap["gap_size"] == 2


def test_e2e_hand_edited_wire_file_diff_flow():
    """Simulate user downloading wire file, hand-editing in text editor, uploading back."""
    file_id, _ = generate_wire_capture(count=20, seed=123, rekey_every_packets=10)
    raw_text = load_wire_file(file_id)
    meta, parent_entries, _ = read_wire_file(raw_text)

    # Hand-edit entries:
    edited_entries = []
    for entry in parent_entries:
        n = entry["n"]
        if n == 5:
            continue  # Drop frame 5
        if n == 8:
            # Tamper byte
            raw = bytearray(entry["raw_bytes"])
            raw[15] ^= 0x42
            edited_entries.append({"n": n, "t": entry["t"], "raw_bytes": bytes(raw)})
            continue
        edited_entries.append(entry)
        if n == 12:
            # Replay frame 12
            edited_entries.append({"n": 12, "t": entry["t"] + 1.0, "raw_bytes": entry["raw_bytes"]})

    # Append spoofed unauthed frame
    forged_bytes = b"\x53\x4c\x01\x01" + (b"\x00" * 96)
    edited_entries.append({"n": 999, "t": parent_entries[-1]["t"] + 0.1, "raw_bytes": forged_bytes})

    # Diff engine should identify all labels
    inferred_labels, dropped_ns = infer_labels(parent_entries, edited_entries)
    assert 5 in dropped_ns
    assert inferred_labels.get("8") == "TAMPERED"
    assert "REPLAYED" in inferred_labels.values()
    assert "SPOOFED" in inferred_labels.values()

    # Real RX pipeline verification
    keystore = get_lab_keystore()
    results = verify_frames(edited_entries, keystore)
    verdicts = {r["eid"]: r["verdict"] for r in results}
    assert verdicts.get("8") in ("TAMPERED", "BAD_TAG", "BAD_SIG")
    assert verdicts.get("999") in ("SPOOFED", "TAMPERED", "BAD_SIG", "BAD_EPOCH")


def test_e2e_formula_injection_safety():
    """Ensure spreadsheet formulas (=cmd, @SUM, +alert) in CSV cells are treated as raw text."""
    csv_text = "id,command,formula,notes\n1,=cmd|' /C calc'!A0,@SUM(1+1),+alert(1)\n2,-1+2,=10*5,normal_val"
    file_id, meta = import_dataset_file(text=csv_text, name="injection-test", fmt="csv")
    assert meta["frame_count"] == 2

    # Verification roundtrip
    res = verify_lab_file(file_id, mode="original")
    assert res["summary"]["false_accepts"] == 0
    assert res["summary"]["authentic"] == 2
    assert len(res["clean_output"]) == 2

    # Verify that clean_output contains the formula strings untouched and unexecuted
    row0 = res["clean_output"][0]
    assert row0["command"] == "=cmd|' /C calc'!A0"
    assert row0["formula"] == "@SUM(1+1)"
    assert row0["notes"] == "+alert(1)"


def test_e2e_wire_file_immutability():
    """Verify that editing working copy never modifies the original wire file on disk."""
    file_id, _ = generate_wire_capture(count=15, seed=42)
    original_text = load_wire_file(file_id)
    original_hash = hashlib.sha256(original_text.encode("utf-8")).hexdigest()

    # Add edits to working copy
    edits = [
        create_edit_entry("tamper", {"eid": "3", "target": "ciphertext"}),
        create_edit_entry("drop", {"eid_from": "7"}),
    ]
    save_edits(file_id, edits)

    # Verify working copy
    work_res = verify_lab_file(file_id, mode="working")
    assert work_res["mode"] == "working"

    # Reload original file from disk and assert hash matches exactly
    disk_text = load_wire_file(file_id)
    disk_hash = hashlib.sha256(disk_text.encode("utf-8")).hexdigest()
    assert disk_hash == original_hash


def test_e2e_keystore_mismatch_rejection():
    """Verify that a wire file generated under Master Key A is rejected under Master Key B."""
    file_id, _ = generate_wire_capture(count=20, seed=99)
    raw_text = load_wire_file(file_id)
    meta, entries, _ = read_wire_file(raw_text)

    # Different keystore with different master secret
    alt_keystore = KeyStore(master_secret=b"\x99" * 32, session_salt=b"\x88" * 4)
    alt_fp = compute_key_fp(alt_keystore.master_secret)
    assert alt_fp != meta["key_fp"]

    # When verified with alt_keystore, all frames fail authentication (FA=0)
    verified = verify_frames(entries, alt_keystore)
    for row in verified:
        assert row["verdict"] != "AUTHENTIC"


def test_e2e_clean_10_epoch_file_zero_gaps():
    """Verify that a clean multi-epoch capture (10 epochs) has zero sequence gaps."""
    file_id, meta = generate_wire_capture(count=200, seed=777, rekey_every_packets=20)
    assert meta["frame_count"] == 200
    res = verify_lab_file(file_id, mode="original")
    assert res["summary"]["false_accepts"] == 0
    assert res["summary"]["false_rejects"] == 0
    assert res["summary"]["authentic"] == 200
    assert len(res["gaps"]) == 0


def test_e2e_single_dropped_frame_reports_single_gap():
    """Verify that dropping a single frame in a multi-epoch capture reports exactly one gap."""
    file_id, _ = generate_wire_capture(count=100, seed=888, rekey_every_packets=20)
    # Drop frame 35 (in epoch 2, which has seqs 21..40)
    save_edits(file_id, [create_edit_entry("drop", {"eid_from": "35"})])
    res = verify_lab_file(file_id, mode="working")
    assert res["summary"]["false_accepts"] == 0
    assert res["summary"]["false_rejects"] == 0
    assert res["delivery"]["delivered_rows"] == 99
    assert len(res["gaps"]) == 1
    gap = res["gaps"][0]
    assert gap["epoch"] == 2
    assert gap["expected_seq"] == 35
    assert gap["found_seq"] == 36
    assert gap["gap_size"] == 1
