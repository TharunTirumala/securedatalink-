"""Unit tests verifying attacker behaviors and strict architectural isolation rules."""

import ast
from pathlib import Path
import pytest
from securelink.simulation.attacks.tamper import TamperAttacker
from securelink.simulation.attacks.replay import ReplayAttacker
from securelink.simulation.attacks.spoof import SpoofAttacker
from securelink.simulation.attacks.drop import DropAttacker
from securelink.simulation.attacks.wire_modes import (
    apply_wire_pass,
    apply_wire_tamper,
    apply_wire_drop,
    apply_wire_spoof,
    WireReplayBuffer,
    WireJammer,
)
from securelink.simulation.attacks.mavlink_modes import MavlinkMutator


def test_attacker_architectural_isolation():
    """Verify attackers and transports never import from crypto, keystore, or pipelines."""
    repo_root = Path(__file__).resolve().parents[2]
    attacks_dir = repo_root / "src/securelink/simulation/attacks"
    manual_dir = repo_root / "src/securelink/simulation/manual"
    transport_dir = repo_root / "src/securelink/transport"
    
    py_files = list(attacks_dir.glob("*.py")) + list(manual_dir.glob("*.py")) + list(transport_dir.glob("*.py"))
    py_files.append(repo_root / "src/securelink/simulation/channel.py")
    py_files.append(repo_root / "src/securelink/cli/attacker.py")

    forbidden_modules = (
        "crypto.keystore",
        "crypto.kdf",
        "crypto.aead",
        "crypto.signing",
        "pipeline.rx_pipeline",
        "pipeline.tx_pipeline",
        "securelink.crypto",
    )
    forbidden_names = {"KeyStore", "RxPipeline", "TxPipeline", "decrypt_gcm", "encrypt_gcm", "derive", "key_id"}

    for py_file in py_files:
        tree = ast.parse(py_file.read_text(encoding="utf-8"))
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                for alias in node.names:
                    assert not any(alias.name.endswith(fm) or fm in alias.name for fm in forbidden_modules), (
                        f"{py_file} imports forbidden {alias.name}"
                    )
                    assert alias.name not in forbidden_names, f"{py_file} imports forbidden symbol {alias.name}"
            elif isinstance(node, ast.ImportFrom):
                mod = node.module or ""
                assert not any(mod.endswith(fm) or fm in mod for fm in forbidden_modules), (
                    f"{py_file} imports from {mod}"
                )
                for alias in node.names:
                    assert alias.name not in forbidden_names, f"{py_file} imports {alias.name} from {mod}"


def test_wire_modes():
    frame = b"SECURELINK_FRAME_TEST_PAYLOAD_12345"
    out_pass, lbl = apply_wire_pass(frame)
    assert out_pass == frame and lbl == "AUTHENTIC"

    out_tamper, lbl = apply_wire_tamper(frame, seed=42)
    assert out_tamper != frame and lbl == "TAMPERED"

    out_drop, lbl = apply_wire_drop(frame)
    assert out_drop is None and lbl == "DROPPED"

    out_spoof, lbl = apply_wire_spoof(frame, seed=42)
    assert out_spoof != frame and lbl == "SPOOFED"

    buf = WireReplayBuffer(max_size=5)
    buf.record(frame)
    assert buf.get_replay() == frame

    jammer = WireJammer()
    j_out, j_lbl = jammer.handle(frame, seed=10)
    assert j_lbl in ("TAMPERED", "DROPPED", "AUTHENTIC", "REPLAYED")


def test_mavlink_mutator_fallback_on_raw():
    mut = MavlinkMutator()
    ciphertext = b"\x02\x00\x01\x00" + b"\xff" * 60  # Not a valid MAVLink message
    out, lbl, meta = mut.mutate(ciphertext, "position_rewrite")
    assert meta["fallback"] is True
    assert lbl == "TAMPERED"
    assert out != ciphertext


def test_mavlink_mutator_on_mavlink():
    import pymavlink.dialects.v20.common as mavlink2
    mav = mavlink2.MAVLink(None)
    pos = mav.global_position_int_encode(1000, 377749000, -1224194000, 50000, 45000, 100, 200, 50, 18000)
    buf = pos.pack(mav)

    mut = MavlinkMutator()
    out, lbl, meta = mut.mutate(buf, "position_rewrite", {"lat_offset_deg": 0.01, "lon_offset_deg": 0.01})
    assert meta["fallback"] is False
    assert lbl == "MUTATED"
    assert out != buf

    # Verify that the mutated message parses with valid CRC
    parser = mavlink2.MAVLink(None)
    parsed = parser.parse_buffer(out)
    assert len(parsed) == 1
    assert parsed[0].lat == 377749000 + int(0.01 * 1e7)
