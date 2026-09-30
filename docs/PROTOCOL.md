# SecureLink Datalink Protocol Specification (Version 3.5)

## 1. Scope & Objective
SecureLink is an authenticated, tamper-resistant, replay-immune tactical datalink protocol designed for low-latency transmission of telemetry frames over contested RF channels. Phase 3B introduces the File Lab: tabular dataset importation (CSV, JSON, JSONL), wire frame capture generation, content-based diff auditing, simulated arrival clocking, and deterministic row-by-row delivery reconciliation against source ground truth.

---

## 2. Wire Frame Architecture
Every SecureLink datagram consists of three contiguous byte sections:

```
+---------------------+-------------------------------+-----------------------+
|   Header (20 bytes) | Ciphertext + Tag (N+16 bytes) |  Signature (64 bytes) |
+---------------------+-------------------------------+-----------------------+
```

### 2.1 Header Format (20 bytes)
All multi-byte numeric fields are encoded in **Network Byte Order (Big-Endian)** using format `>BHBQd`.

| Offset | Size (bytes) | Field Name | Data Type | Description |
|---|---|---|---|---|
| `0x00` | 1 | `version` | uint8 | Protocol version (`0x01`). |
| `0x01` | 2 | `sender_id` | uint16 | Identifier of transmitting node (e.g. UAV-1 = 1). |
| `0x03` | 1 | `key_epoch` | uint8 | Active key epoch / key rotation generation (1..255). |
| `0x04` | 8 | `seq` | uint64 | Monotonic sequence number within the current epoch. |
| `0x0C` | 8 | `timestamp` | float64 | IEEE 754 double-precision UNIX timestamp in seconds. |

The raw 20-byte header serves as **Additional Authenticated Data (AAD)** for AES-GCM.

### 2.2 Dynamic Key & Salt Derivation (HKDF-SHA256)
Nodes store a 32-byte master secret (`keys/master.key`). Keys and session salts are derived per sender and epoch:

```
info = b"securelink|" + struct.pack(">I", sender_id) + struct.pack(">I", epoch)
OKM  = HKDF-SHA256(secret=master_secret, salt=None, info=info, length=36)

AES_KEY      = OKM[0:32]   # 32-byte AES-256 symmetric key
SESSION_SALT = OKM[32:36]  # 4-byte session salt for AES-GCM nonce
```

### 2.3 Nonce Construction (12 bytes / 96 bits)
Nonces are strictly deterministic. Random nonces are prohibited to prevent collision and IV exhaustion.

```
+------------------------+------------------------------------+
| Session Salt (4 bytes) | Sequence Number (8 bytes, uint64)  |
+------------------------+------------------------------------+
```
`nonce = session_salt (4B) + struct.pack('>Q', seq) (8B)`

### 2.4 Body: Authenticated Encryption
- **Cipher**: `AES-256-GCM` with derived `AES_KEY` and `SESSION_SALT`.
- **AAD**: The exact received 20-byte wire `Header`.
- **Payload**: Raw plaintext telemetry bytes ($N$ bytes, variable length up to 1024 bytes).
- **Output**: `Ciphertext (N bytes) + GCM Authentication Tag (16 bytes)`.

### 2.5 Digital Signature (64 bytes)
- **Algorithm**: `ECDSA` using curve `secp256r1` (`NIST P-256`) and `SHA-256`.
- **Signed Message**: `Header (20 bytes) || Plaintext (N bytes)`.
- **Format**: IEEE P1363 big-endian format `r (32B) || s (32B)` = 64 bytes total.

---

## 3. Receiver Verification Pipeline (8-Step Order)
Incoming frames are processed strictly in this sequence:

```
[ Ingest Frame ]
       │
       ▼
[ 1. Frame Parse & Bounds Check ]
       ├── If len(frame) < 100 or len > 65535 or unpack fails ──► TAMPERED (frame_malformed)
       │
       ▼
[ 2. Operator Block & Sender Known Check ]
       ├── If sender_id in blocked_senders ────────────────────► SPOOFED (sender_blocked)
       ├── If sender_id not in Keystore ───────────────────────► SPOOFED (unknown_sender)
       │
       ▼
[ 3. Epoch Lookahead Check ]
       ├── If key_epoch > highest_auth_epoch + 1 or no key ────► TAMPERED (unknown_epoch)
       │
       ▼
[ 4. AES-256-GCM Decryption ]
       ├── If tag mismatch / decryption fails ─────────────────► TAMPERED (gcm_tag_mismatch)
       │
       ▼
[ 5. ECDSA P-256 Signature Verification ]
       ├── If signature invalid for sender_id ─────────────────► SPOOFED (invalid_signature)
       │
       ▼
[ 6. Post-Authentication Epoch Grace Check ]
       ├── If key_epoch < highest_auth_epoch - grace_epochs ───► REPLAYED (epoch_expired)
       └── Advance highest_auth_epoch if newer
       │
       ▼
[ 7. ReplayGuard Check partitioned by (sender_id, epoch) ]
       ├── If seq duplicate / outside sliding window ──────────► REPLAYED (duplicate_seq / seq_out_of_window)
       ├── If timestamp outside latency window ────────────────► REPLAYED (stale_timestamp)
       │
       ▼
[ 8. Frame Accepted ] ─────────────────────────────────────────► AUTHENTIC (ok)
```

---

## 4. Operational Invariants
1. **Epoch Sequence Reset**: Sequence counters reset to 1 upon epoch rotation. Because ReplayGuard states are partitioned by `(sender_id, epoch)`, a sequence restart at 1 in a new epoch is recognized as fresh and authentic.
2. **Grace Epoch Window**: A configurable grace window (default 1 epoch) allows in-flight packets from epoch $N-1$ to be accepted, preventing false rejects during transitions. Packets from epoch $\le N-2$ are rejected as `REPLAYED / epoch_expired`.
3. **Target Metrics**: Clean transmissions maintain 0 False Accepts ($FA=0$) and 0 False Rejects ($FR=0$).

---

## 5. Phase 3B File Lab Specification

### 5.1 Tabular Source Ingestion
- Supports `.csv`, `.json` (array of objects), and `.jsonl`.
- Resilient parsing: UTF-8 BOM auto-stripping, delimiter sniffing (`,`, `;`, `\t`, `|`), ragged row padding/rejection, empty and duplicate header validation.
- Serialized to canonical compact JSON bytes per row, validated against maximum payload size (1024 bytes).

### 5.2 Simulated Arrival Clocking
Telemetry packets stream with simulated transmission timestamps:
$$t_i = t_0 + \frac{i}{\text{rate\_pps}}$$
When verifying wire captures, the RX pipeline advances a simulated clock matching entry timestamps, making replay and skew checks deterministic across test runs.

### 5.3 Wire File JSONL Specification
- Line 1: `{"type": "meta", "format": 1, "file_id": str, "created": float, "sender_id": int, "key_fp": str, "frame_count": int, "source_kind": str, "rate_pps": int, "rekey_every_packets": int}`
- Lines 2..N: `{"type": "frame", "n": int, "t": float, "hex": str}`
- Max size: 10 MB, max frames: 50,000. Tolerant parsing flags broken lines as malformed without aborting the file.

### 5.4 Content-Based Diff Engine (`diff.py`)
Matches uploaded hand-edited wire frames against parent captures by cryptographic hex content:
- Preserved identical hex with matching `n` $\rightarrow$ `AUTHENTIC`
- Duplicated hex within file or re-injected with modified `n` $\rightarrow$ `REPLAYED`
- Hex matching sequence in parent but with altered bytes $\rightarrow$ `TAMPERED`
- Hex completely unknown in parent $\rightarrow$ `SPOOFED`
- Missing parent sequence numbers $\rightarrow$ `DROPPED`

### 5.5 Reconciliation & Delivery Audit
Reconciliation compares decrypted payload bytes directly with canonical source rows:
- `source_rows`: Total rows in imported dataset.
- `delivered_rows`: Unique rows successfully authenticated and delivered to C2 stream.
- `suppressed_at_gate`: Attacked or corrupted frames withheld by RX security checks.
- `missing_rows`: Source rows that never arrived or were dropped in transit.
- `duplicates_delivered`: Repeated deliveries of the same row (must be 0).
- `content_mismatches`: Decrypted payload differing from source row truth (must be 0).
- `gaps`: Stream sequence discontinuities per `(sender_id, epoch)`.
