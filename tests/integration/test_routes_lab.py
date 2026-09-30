"""Integration tests for File Lab REST API endpoints and security hardening."""

import os
import json
import pytest
from fastapi.testclient import TestClient
from dashboard.backend.server import app


@pytest.fixture
def client():
    return TestClient(app)


def test_lab_api_dataset_import_and_clean_output(client):
    csv_content = "lat,lon,alt\n17.1,78.1,100\n17.2,78.2,200\n17.3,78.3,300\n"

    # 1. Preview
    resp = client.post("/api/lab/datasets/preview?format=csv", content=csv_content.encode("utf-8"))
    assert resp.status_code == 200
    p_data = resp.json()
    assert p_data["row_count"] == 3
    assert p_data["columns"] == ["lat", "lon", "alt"]

    # 2. Import
    resp = client.post("/api/lab/datasets/import?name=test-import&format=csv", content=csv_content.encode("utf-8"))
    assert resp.status_code == 200
    imp_data = resp.json()
    file_id = imp_data["file_id"]

    # 3. Source rows endpoint
    resp = client.get(f"/api/lab/files/{file_id}/source?offset=0&limit=10")
    assert resp.status_code == 200
    s_data = resp.json()
    assert s_data["total"] == 3
    assert s_data["rows"][0]["lat"] == "17.1"

    # 4. Verify original and check last clean output
    resp = client.post(f"/api/lab/files/{file_id}/verify", json={"mode": "original"})
    assert resp.status_code == 200
    assert resp.json()["delivery"]["delivered"] == 3

    resp = client.get(f"/api/lab/files/{file_id}/verify/last?view=clean")
    assert resp.status_code == 200
    c_data = resp.json()
    assert c_data["view"] == "clean"
    assert len(c_data["rows"]) == 3
    assert c_data["rows"][0]["lat"] == "17.1"

    # Cleanup
    client.delete(f"/api/lab/files/{file_id}")


def test_lab_api_full_flow(client):
    # 1. Generate wire file
    resp = client.post("/api/lab/files/generate", json={"count": 50, "seed": 42, "rekey_every_packets": 20})
    assert resp.status_code == 200
    data = resp.json()
    assert "file_id" in data
    file_id = data["file_id"]
    assert len(file_id) == 32

    # 2. List files
    resp = client.get("/api/lab/files")
    assert resp.status_code == 200
    files = resp.json()
    assert any(f["file_id"] == file_id for f in files)

    # 3. Get file info
    resp = client.get(f"/api/lab/files/{file_id}")
    assert resp.status_code == 200
    info = resp.json()
    assert info["frame_count"] == 50

    # 4. Get paginated frames
    resp = client.get(f"/api/lab/files/{file_id}/frames?offset=0&limit=10")
    assert resp.status_code == 200
    frames_data = resp.json()
    assert len(frames_data["rows"]) == 10
    eid_1 = frames_data["rows"][0]["eid"]

    # 5. Inspect single frame layout
    resp = client.get(f"/api/lab/files/{file_id}/frames/{eid_1}")
    assert resp.status_code == 200
    inspect_data = resp.json()
    assert "ranges" in inspect_data
    assert len(inspect_data["ranges"]) == 8

    # 6. Add edit operation (tamper)
    resp = client.post(
        f"/api/lab/files/{file_id}/edits",
        json={"op": "tamper", "params": {"eid": eid_1, "target": "ciphertext", "xor_mask": 1}},
    )
    assert resp.status_code == 200
    edit_id = resp.json()["edit"]["edit_id"]

    # 7. Verify working copy (detects tampering)
    resp = client.post(f"/api/lab/files/{file_id}/verify", json={"mode": "working"})
    assert resp.status_code == 200
    v_data = resp.json()
    assert v_data["key_match"] is True
    assert v_data["summary"]["false_accepts"] == 0

    # 8. Reset edits
    resp = client.post(f"/api/lab/files/{file_id}/edits/reset")
    assert resp.status_code == 200
    assert resp.json()["total_edits"] == 0

    # 9. Verify baseline after reset
    resp = client.post(f"/api/lab/files/{file_id}/verify", json={"mode": "working"})
    assert resp.status_code == 200

    # 10. Download working .wire.txt
    resp = client.get(f"/api/lab/files/{file_id}/download?view=working")
    assert resp.status_code == 200
    assert '{"type": "meta"' in resp.text

    # 11. Path traversal security: invalid file ID
    resp = client.get("/api/lab/files/../../etc/passwd")
    assert resp.status_code in (404, 422)

    # 12. Delete file
    resp = client.delete(f"/api/lab/files/{file_id}")
    assert resp.status_code == 200
    assert resp.json()["status"] == "deleted"


def test_lab_api_token_hardening(client, monkeypatch):
    monkeypatch.setenv("SECURELINK_API_TOKEN", "secret-test-token")

    # Mutation without token rejected with 401
    resp = client.post("/api/lab/files/generate", json={"count": 20})
    assert resp.status_code == 401

    # Mutation with valid token accepted
    resp = client.post(
        "/api/lab/files/generate",
        json={"count": 20},
        headers={"X-SecureLink-Token": "secret-test-token"},
    )
    assert resp.status_code == 200
    file_id = resp.json()["file_id"]

    # Clean up
    client.delete(f"/api/lab/files/{file_id}", headers={"X-SecureLink-Token": "secret-test-token"})


def test_lab_api_upload_cases(client):
    csv_content = "lat,lon,alt\n10.0,20.0,100\n10.1,20.1,101\n10.2,20.2,102\n10.3,20.3,103\n10.4,20.4,104\n"
    imp_resp = client.post("/api/lab/datasets/import?name=test-parent&format=csv", content=csv_content.encode("utf-8"))
    assert imp_resp.status_code == 200
    p_id = imp_resp.json()["file_id"]

    # 1. Download parent wire file
    dl_resp = client.get(f"/api/lab/files/{p_id}/download?view=original")
    assert dl_resp.status_code == 200
    parent_text = dl_resp.text

    # Case A: Upload unchanged file with parent -> 0 changes detected, 100% authentic
    up_resp = client.post(f"/api/lab/files/upload?parent_id={p_id}", content=parent_text.encode("utf-8"))
    assert up_resp.status_code == 200
    c_id = up_resp.json()["file_id"]

    c_info = client.get(f"/api/lab/files/{c_id}").json()
    assert c_info["edits"] == []
    assert all(l == "AUTHENTIC" for l in c_info["inferred_labels"].values())
    assert [l for l in c_info["inferred_labels"].values() if l != "AUTHENTIC"] == []
    assert c_info["parent_id"] == p_id

    c_ver = client.post(f"/api/lab/files/{c_id}/verify", json={"mode": "working"}).json()
    assert c_ver["summary"]["authentic"] == 5
    assert len(c_ver["gaps"]) == 0
    assert c_ver["summary"]["false_accepts"] == 0

    # Baseline verify of child verifies parent untouched baseline
    c_base = client.post(f"/api/lab/files/{c_id}/verify", json={"mode": "original"}).json()
    assert c_base["summary"]["authentic"] == 5
    assert len(c_base["gaps"]) == 0

    # Case B: Upload 1 flipped hex char with parent -> TAMPERED caught, excluded from clean C2
    lines = parent_text.strip().split("\n")
    f2_data = json.loads(lines[2])
    raw_hex = f2_data["hex"]
    corrupted_char = "0" if raw_hex[45] != "0" else "1"
    f2_data["hex"] = raw_hex[:45] + corrupted_char + raw_hex[46:]
    lines_tampered = list(lines)
    lines_tampered[2] = json.dumps(f2_data)
    tampered_text = "\n".join(lines_tampered)

    t_resp = client.post(f"/api/lab/files/upload?parent_id={p_id}", content=tampered_text.encode("utf-8"))
    assert t_resp.status_code == 200
    t_id = t_resp.json()["file_id"]

    t_info = client.get(f"/api/lab/files/{t_id}").json()
    assert t_info["edits"] == []
    assert t_info["inferred_labels"].get("2") == "TAMPERED"

    t_ver = client.post(f"/api/lab/files/{t_id}/verify", json={"mode": "working"}).json()
    assert t_ver["summary"]["counts_by_verdict"]["tampered"] == 1
    assert t_ver["delivery"]["delivered"] == 4
    assert t_ver["delivery"]["suppressed"] == 1

    clean_resp = client.get(f"/api/lab/files/{t_id}/verify/last?view=clean").json()
    assert clean_resp["total"] == 4

    # Baseline on child still verifies pristine parent baseline
    t_base = client.post(f"/api/lab/files/{t_id}/verify", json={"mode": "original"}).json()
    assert t_base["summary"]["authentic"] == 5

    # Case C: Replay + Drop lines
    lines_edit = [lines[0], lines[1], lines[2], lines[4], lines[4], lines[5]]
    rep_drop_text = "\n".join(lines_edit)
    rd_resp = client.post(f"/api/lab/files/upload?parent_id={p_id}", content=rep_drop_text.encode("utf-8"))
    assert rd_resp.status_code == 200
    rd_id = rd_resp.json()["file_id"]

    rd_ver = client.post(f"/api/lab/files/{rd_id}/verify", json={"mode": "working"}).json()
    assert rd_ver["summary"]["false_accepts"] == 0
    assert len(rd_ver["delivery"]["missing_rows"]) >= 1

    # Case D: Upload with no parent -> verdicts only, no crash
    np_resp = client.post("/api/lab/files/upload", content=parent_text.encode("utf-8"))
    assert np_resp.status_code == 200
    np_id = np_resp.json()["file_id"]
    np_info = client.get(f"/api/lab/files/{np_id}").json()
    assert np_info["parent_id"] is None

    np_ver = client.post(f"/api/lab/files/{np_id}/verify", json={"mode": "working"}).json()
    assert np_ver["key_match"] is True
    assert np_ver["summary"]["authentic"] == 5

    # Case E: Malformed odd-length hex line
    bad_lines = list(lines)
    bad_f = json.loads(bad_lines[1])
    bad_f["hex"] = bad_f["hex"] + "a"
    bad_lines[1] = json.dumps(bad_f)
    bad_text = "\n".join(bad_lines)
    m_resp = client.post(f"/api/lab/files/upload?parent_id={p_id}", content=bad_text.encode("utf-8"))
    if m_resp.status_code == 200:
        m_id = m_resp.json()["file_id"]
        v_res = client.post(f"/api/lab/files/{m_id}/verify", json={"mode": "working"})
        assert v_res.status_code in (200, 422)
        assert isinstance(v_res.json(), dict)
        client.delete(f"/api/lab/files/{m_id}")
    else:
        assert m_resp.status_code == 422

    # Cleanup
    for fid in (p_id, c_id, t_id, rd_id, np_id):
        client.delete(f"/api/lab/files/{fid}")


def test_lab_api_view_feed(client):
    gen_res = client.post("/api/lab/files/generate", json={"count": 30, "rekey_every_packets": 10}).json()
    fid = gen_res["file_id"]

    # Tamper frame 5, replay frame 8 after frame 12, drop frame 15
    client.post(f"/api/lab/files/{fid}/edits", json={"op": "tamper", "params": {"eid": "5", "target": "ciphertext", "xor_mask": 1}})
    client.post(f"/api/lab/files/{fid}/edits", json={"op": "replay", "params": {"source_eid": "8", "insert_after_eid": "12", "delay_s": 0.5}})
    client.post(f"/api/lab/files/{fid}/edits", json={"op": "drop", "params": {"eid_from": "15", "eid_to": "15"}})

    resp = client.get(f"/api/lab/files/{fid}/verify/last?view=feed")
    assert resp.status_code == 200
    feed = resp.json()
    assert feed["view"] == "feed"
    assert feed["counts"]["TAMPERED"] == 1
    assert feed["counts"]["REPLAYED"] == 1
    assert feed["counts"]["DROPPED"] == 1
    assert feed["counts"]["AUTHENTIC"] >= 26
    assert len(feed["epoch_changes"]) >= 2
    assert len(feed["incidents"]) >= 3

    # Check row structure
    first_row = feed["rows"][0]
    for key in ("line", "eid", "epoch", "seq", "sender_id", "verdict", "reason", "truth", "caught"):
        assert key in first_row

    # Test filtering by verdict
    filt_resp = client.get(f"/api/lab/files/{fid}/verify/last?view=feed&verdict=TAMPERED")
    assert filt_resp.status_code == 200
    filt_feed = filt_resp.json()
    assert filt_feed["total"] == 1
    assert filt_feed["rows"][0]["verdict"] == "TAMPERED"
    assert filt_feed["counts"]["AUTHENTIC"] >= 26

    client.delete(f"/api/lab/files/{fid}")
