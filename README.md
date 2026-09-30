# SecureLink: Cyber-Secure Tactical Datalink System

SecureLink is a resilient, ultra-low latency tactical datalink communication and electronic warfare threat mitigation framework designed for autonomous unmanned aerial platforms and defense command-and-control (C2) operations.

---

## 1. System Architecture

```
[ Tabular Dataset / Synthetic Source ]
                  │
                  ▼
          [ TX Pipeline ] ────► AES-256-GCM + ECDSA P-256 (64B) + Dynamic HKDF Epochs
                  │
                  ▼
     [ Contested Channel / Lab ] ─► Jamming, Tampering, Replay, Spoofing, Dropping
                  │
                  ▼
          [ RX Pipeline ] ────► 8-Step Cryptographic Verification, Grace Windows & ReplayGuard
                  │
                  ▼
      [ Decoded C2 Output ] ──► Verified Plaintext Stream & Row-by-Row Reconciliation Audit
                  │
                  ▼
        [ Tactical C2 Shell ] ─► Live Monitor, Dynamic Re-keying, and File Lab Workbench
```

---

## 2. Capabilities & Interfaces

### 2.1 Left Sidebar Navigation & App Shell
- **Live Monitor (`#/monitor`)**: Real-time HUD with throughput metrics, latency p50/p95/p99, live packet timeline, adversarial incident stream with operator ACK controls, and sender blocking.
- **Dynamic Re-keying (`#/rekey`)**: Live epoch timeline chain, force re-key button, rekey interval adjustments (10..10,000 frames), grace window viewer, and expired-epoch replay attack injection testing.
- **File Lab (`#/lab`)**: 4-Step File Lab workflow:
  1. **Import Dataset**: Drag-and-drop or upload CSV, JSON, or JSONL; preview 5-row sample; select column subset; configure rate (pps) and rekey interval; click *[Encrypt & Sign Wire File]*.
  2. **Multi-Epoch Wire Capture**: Inspect key fingerprints and side-by-side comparison ("What you sent vs what the enemy sees"). Download wire file (`.wire.txt`) for external editing or upload hand-edited captures.
  3. **Attack Workbench**: Working copy vs original toggle, paginated frame list with dropped frame strikethrough, color-coded byte inspector, micro-tamper / replay / spoof / drop injectors, and active edit log with reset.
  4. **Verify & Reconcile**: Run deterministic verification on original baseline ($FA=0, FR=0$) or working copy. Inspect verdict chips, decoded clean C2 output stream, and complete reconciliation delivery audit.

---

## 3. Wire Protocol & Cryptography (`docs/PROTOCOL.md`)

```
+---------------------+-------------------------------+-----------------------+
|   Header (20 bytes) | Ciphertext + Tag (N+16 bytes) |  Signature (64 bytes) |
+---------------------+-------------------------------+-----------------------+
```

- **Header (20B)**: `>BHBQd` (version: uint8, sender_id: uint16, key_epoch: uint8, seq: uint64, timestamp: float64). Additional Authenticated Data (AAD).
- **Key & Salt Derivation**: Derived via HKDF-SHA256 per `(sender_id, epoch)` from master secret.
- **Nonce (12B)**: 4-byte session salt + 8-byte uint64 sequence number (strictly deterministic).
- **Body**: AES-256-GCM encrypted ciphertext + 16-byte authentication tag.
- **Signature (64B)**: ECDSA P-256 IEEE P1363 format `r (32B) || s (32B)`.
- **Receiver Pipeline**: 8-step verification pipeline enforcing bounds, sender whitelist, epoch lookahead, AEAD integrity, ECDSA signature, post-auth grace window, and partitioned ReplayGuard.

---

## 4. Quickstart

### 1-Click Launch (Windows):
Double-click or run:
```bat
run_demo.bat
```

### 1-Click Launch (Linux / macOS):
```bash
chmod +x run_demo.sh
./run_demo.sh
```

### Manual Launch:
```bash
# 1. Generate keys
python scripts/gen_keys.py keys

# 2. Start C2 Web Dashboard & Lab Backend
python -m uvicorn dashboard.backend.server:app --host 127.0.0.1 --port 8000
```
Open your browser to: [http://127.0.0.1:8000](http://127.0.0.1:8000)

---

## 5. Running the Test Suite

```bash
pytest -v
```

All 82 unit and integration tests verify:
- Binary frame packing and unpacking roundtrips
- AES-256-GCM and ECDSA P-256 cryptographic integrity and bit-flip rejection
- HKDF key epoch rotation and domain separation
- ReplayGuard sliding window integrity, bounded bitmap, and simulated clocking
- Strict architectural isolation of attack simulators (verified via AST analysis)
- 0% False Acceptance Rate ($FA=0$) and 0% False Rejection Rate ($FR=0$)
- Tabular dataset import, column projection, and payload size validation
- Content-based diff matching for hand-edited wire file uploads
- Spreadsheet formula / DDE injection safety
- Deterministic offline File Lab verification and stream sequence gap detection
- FastAPI REST APIs, WebSocket streaming, and token security
