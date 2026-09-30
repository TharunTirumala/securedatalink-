"""Integration tests for Lab service: dataset import, baseline verification, attacks, and reconciliation."""

import hashlib
import json
from pathlib import Path
from securelink.lab.service import (
    generate_wire_capture,
    import_dataset_file,
    verify_lab_file,
    get_lab_keystore,
)
from securelink.lab.store import get_file_path, get_source_path
from securelink.simulation.manual.edits import create_edit_entry
from securelink.lab.store import save_edits


def test_lab_baseline_verification_500_row_csv():
    """Baseline verify of unedited 500-row, 10-epoch CSV import is 100% AUTHENTIC with 0 FR and 0 mismatch."""
    csv_rows = ["lat,lon,alt,speed"]
    for i in range(1, 501):
        csv_rows.append(f"{17.0 + i*0.001},{78.0 + i*0.001},{500 + i},{30.0}")
    csv_text = "\n".join(csv_rows) + "\n"

    file_id, meta = import_dataset_file(
        text=csv_text,
        name="flight-test-500",
        fmt="csv",
        rate_pps=100,
        rekey_every_packets=50,
    )
    wire_path = get_file_path(file_id)
    source_path = get_source_path(file_id)
    wire_hash_before = hashlib.sha256(wire_path.read_bytes()).hexdigest()
    source_hash_before = hashlib.sha256(source_path.read_bytes()).hexdigest()

    result = verify_lab_file(file_id, mode="original")
    assert result["key_match"] is True

    summary = result["summary"]
    counts = summary["counts_by_verdict"]
    assert counts["authentic"] == 500
    assert summary["false_rejects"] == 0
    assert summary["false_accepts"] == 0
    assert summary["correctly_rejected"] == 0

    delivery = result["delivery"]
    assert delivery["source_rows"] == 500
    assert delivery["delivered"] == 500
    assert delivery["suppressed"] == 0
    assert delivery["duplicates_delivered"] == 0
    assert delivery["content_mismatch"] == 0
    assert len(delivery["missing_rows"]) == 0
    assert len(result["clean_output"]) == 500
    assert len(result["gaps"]) == 0

    # Immutability check: original wire and source files never modified
    assert hashlib.sha256(wire_path.read_bytes()).hexdigest() == wire_hash_before
    assert hashlib.sha256(source_path.read_bytes()).hexdigest() == source_hash_before


def test_lab_attacks_and_reconciliation_metrics():
    """Tamper, replay, spoof, drop rejected with 0 false accepts, and drop reports gap and missing row."""
    csv_text = "id,name\n" + "\n".join(f"{i},UAV-{i}" for i in range(1, 51)) + "\n"
    file_id, _ = import_dataset_file(text=csv_text, fmt="csv", rekey_every_packets=10)

    edits = [
        create_edit_entry("tamper", {"eid": "10", "target": "ciphertext", "xor_mask": 0x01}),
        create_edit_entry("tamper", {"eid": "20", "target": "signature", "xor_mask": 0x02}),
        create_edit_entry("replay", {"source_eid": "5", "insert_after_eid": "15", "delay_s": 0.1}),
        create_edit_entry("replay", {"source_eid": "6", "insert_after_eid": "16", "delay_s": 60.0}),
        create_edit_entry("spoof", {"insert_after_eid": "30", "count": 2, "mode": "forged_valid_format"}),
        create_edit_entry("drop", {"eid_from": "40", "eid_to": "42"}),
    ]
    save_edits(file_id, edits)

    result = verify_lab_file(file_id, mode="working")
    assert result["key_match"] is True

    summary = result["summary"]
    assert summary["false_accepts"] == 0
    assert summary["attacked_frames"] > 0
    assert summary["correctly_rejected"] > 0

    delivery = result["delivery"]
    assert delivery["content_mismatch"] == 0
    assert delivery["duplicates_delivered"] == 0
    assert delivery["suppressed"] > 0
    # Dropped rows 40, 41, 42 correspond to source row indices 39, 40, 41
    assert 39 in delivery["missing_rows"]
    assert 40 in delivery["missing_rows"]
    assert 41 in delivery["missing_rows"]

    # Verify drop created a stream sequence gap
    gaps = result["gaps"]
    assert len(gaps) >= 1


def test_lab_json_nested_roundtrip():
    """JSON dataset with nested values and complex types round-trips exactly in C2 clean output."""
    raw_json = json.dumps([
        {"id": 1, "status": "active", "telemetry": {"alt": 100, "coords": [10.5, 20.5]}},
        {"id": 2, "status": "standby", "telemetry": {"alt": 200, "coords": [11.5, 21.5]}},
    ])
    file_id, _ = import_dataset_file(text=raw_json, fmt="json", rekey_every_packets=10)
    result = verify_lab_file(file_id, mode="original")

    assert result["key_match"] is True
    assert result["delivery"]["content_mismatch"] == 0
    assert len(result["clean_output"]) == 2
    assert result["clean_output"][0]["telemetry"]["coords"] == [10.5, 20.5]


def test_lab_key_mismatch_detection():
    """File generated under different key reports key_match: false without stats."""
    file_id, meta = generate_wire_capture(count=20, rekey_every_packets=10, seed=99)

    path = get_file_path(file_id)
    content = path.read_text(encoding="utf-8")
    lines = content.splitlines()
    lines[0] = lines[0].replace(meta["key_fp"], "ffffffff")
    path.write_text("\n".join(lines) + "\n", encoding="utf-8")

    result = verify_lab_file(file_id, mode="original")
    assert result["key_match"] is False
    assert "mismatch" in result["message"].lower()
    assert result["summary"] == {}
