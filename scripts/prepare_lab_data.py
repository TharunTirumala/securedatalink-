"""Create clean and attacked files for File Lab verification screenshots."""

import json
import urllib.request

BASE_URL = "http://127.0.0.1:8000/api/lab"

def post_json(path, data):
    req = urllib.request.Request(
        f"{BASE_URL}{path}",
        data=json.dumps(data).encode("utf-8"),
        headers={"Content-Type": "application/json"},
    )
    with urllib.request.urlopen(req) as resp:
        return json.loads(resp.read().decode("utf-8"))

def main():
    print("Generating flight-clean-100...")
    clean_data = post_json("/files/generate", {
        "name": "flight-clean-100",
        "count": 100,
        "seed": 42,
        "rekey_every_packets": 25,
    })
    clean_fid = clean_data["file_id"]
    print(f"Clean file ID: {clean_fid}")

    # Verify clean baseline
    post_json(f"/files/{clean_fid}/verify", {"mode": "original"})

    print("Generating tactical-attacks-100...")
    att_data = post_json("/files/generate", {
        "name": "tactical-attacks-100",
        "count": 100,
        "seed": 42,
        "rekey_every_packets": 25,
    })
    att_fid = att_data["file_id"]
    print(f"Attacked file ID: {att_fid}")

    # 1. Tamper frame 15
    post_json(f"/files/{att_fid}/edits", {
        "op": "tamper",
        "params": {"eid": "15", "target": "ciphertext", "byte_offset": 2, "xor_mask": 1}
    })
    # 2. Replay frame 8 after frame 32
    post_json(f"/files/{att_fid}/edits", {
        "op": "replay",
        "params": {"source_eid": "8", "insert_after_eid": "32", "delay_s": 1.0}
    })
    # 3. Spoof 2 frames after frame 50
    post_json(f"/files/{att_fid}/edits", {
        "op": "spoof",
        "params": {"insert_after_eid": "50", "count": 2, "mode": "forged_valid_format"}
    })
    # 4. Drop frame 75
    post_json(f"/files/{att_fid}/edits", {
        "op": "drop",
        "params": {"eid_from": "75", "eid_to": "75"}
    })

    # Verify baseline and working copy
    post_json(f"/files/{att_fid}/verify", {"mode": "original"})
    post_json(f"/files/{att_fid}/verify", {"mode": "working"})
    print("Files created and verified successfully.")
    print(f"CLEAN_FILE_ID={clean_fid}")
    print(f"ATTACKED_FILE_ID={att_fid}")

if __name__ == "__main__":
    main()
