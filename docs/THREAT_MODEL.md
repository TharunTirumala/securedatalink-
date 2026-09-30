# SecureLink Threat Model & Security Architecture

## 1. System Overview & Trust Assumptions
SecureLink protects tactical datalink telemetry between remote transmitters (e.g., UAVs) and command receiving ground stations (RX) over hostile RF links.

### Trust Boundaries
- **Trusted Domain**: The cryptographic keystore and pipeline logic on legitimate nodes, along with the master secret `keys/master.key` and private keys.
- **Untrusted Domain**: The RF broadcast medium, physical channel, network transit buffers, and adversary-controlled software.
- **Operator Override**: Ground station human operators can selectively block compromised sender IDs via `/api/operator/block-sender`.
- **File Lab Boundary**: The adversary's boundary is strictly the encrypted wire file in transit. The adversary CANNOT alter data before encryption. Changing source data prior to encryption is not an attack on the datalink: the system protects integrity, authenticity, and freshness in transit.

---

## 2. Threat Vectors & Mitigations

| Threat | Attack Vector | Countermeasure | RX Pipeline Classification |
|---|---|---|---|
| **Payload Tampering** | Bit-flip or modification of encrypted telemetry bytes | AES-256-GCM authentication tag verification | `TAMPERED` (`gcm_tag_mismatch`) |
| **Header Tampering** | Modification of sender ID, sequence, epoch, or timestamp | Header is Additional Authenticated Data (AAD) and signed via ECDSA | `TAMPERED` (`gcm_tag_mismatch` / `invalid_signature`) |
| **Signature Forgery** | Attempt to sign forged frame with invalid/ephemeral key | ECDSA over `NIST P-256` (secp256r1) with SHA-256 verified against sender public key | `SPOOFED` (`invalid_signature` / `unknown_sender`) |
| **Within-Epoch Replay** | Re-transmission of captured authentic frame within same epoch | Sliding window bitmap replay guard partitioned by `(sender_id, epoch)` | `REPLAYED` (`duplicate_seq` / `seq_out_of_window`) |
| **Stale Delay Attack** | Buffering authentic frames and injecting them after delay | Maximum packet age timestamp validation (`max_latency_s = 5.0`) | `REPLAYED` (`stale_timestamp`) |
| **Expired-Epoch Replay** | Replaying frames from previous key generations | Post-authentication grace epoch window boundary check ($\le N - 2$ rejected) | `REPLAYED` (`epoch_expired`) |
| **Selective Packet Drop** | Dropping frames in transit to disrupt situational awareness | Receiver stream gap detection audits sequence continuity | Detected as sequence gap |
| **CSV / DDE Injection** | Malicious spreadsheet formulas in imported dataset (`=cmd`, `@SUM`, `+alert`) | Payloads treated as opaque binary data; rendered in UI strictly via `element.textContent` without script execution | Safe (no execution) |

---

## 3. Cryptographic Separation & Isolation

### 3.1 HKDF Domain Separation
- **Key & Salt Derivation**:
  `info = b"securelink|" || sender_id (4B) || epoch (4B)`
- **Key ID (Public Identifier)**:
  `info = b"securelink|kid|" || sender_id (4B) || epoch (4B)`
Ensures that key identifiers (8 hex chars) expose zero information about master secrets or derived symmetric keys.

### 3.2 Architectural Isolation
To ensure test and simulation validity without "insider cheats":
- All attacker and simulation modules (`simulation/attacks/`, `simulation/manual/`) are strictly forbidden from importing:
  - `securelink.crypto.keystore`
  - `securelink.crypto.kdf`
  - `securelink.crypto.aead`
  - `securelink.pipeline.rx_pipeline`
- Forged frames in the File Lab workbench are generated using strictly ephemeral EC P-256 keys and random AES keys (`simulation/manual/forge.py`).
- Compliance is continuously verified by AST static analysis in `tests/unit/test_attackers.py`.

### 3.3 Zero Key Material Exposure
- All REST APIs and client UIs only reference Key IDs and SHA-256 master key fingerprints (`key_fp`).
- Keystores are strictly isolated: wire files generated under Master Key A cannot be verified under Master Key B (immediate fingerprint mismatch rejection with 0 frames processed).

---

## 4. Evaluation Criteria
- **False Accept Rate**: Target = 0 ($FA = 0$). An attacker must never successfully inject a modified or forged packet as `AUTHENTIC`.
- **False Reject Rate**: Target = 0 ($FR = 0$). Under nominal or legitimate grace-period operations, authentic packets must never be rejected.
