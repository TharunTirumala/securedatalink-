"""H1 regression: Windows encoding crash on non-ASCII output directed to a file.

Verifies that TX and RX run cleanly under cp1252 PYTHONIOENCODING
with rotation banners, and that RX receives all expected frames.
"""

import os
import subprocess
import sys
import tempfile
import time


def _run_proc(cmd, log_path: str, env: dict) -> subprocess.Popen:
    f = open(log_path, "w", encoding="utf-8")
    p = subprocess.Popen(cmd, stdout=f, stderr=subprocess.STDOUT, env=env)
    p._log_file = f
    return p


def test_no_unicode_crash_under_cp1252(tmp_path):
    """TX + RX run 20 frames with rekey_every=5 under cp1252 without crashing."""
    env = os.environ.copy()
    # Simulate a console that rejects non-ASCII (worst-case Windows log file)
    env["PYTHONIOENCODING"] = "cp1252"
    env["PYTHONUNBUFFERED"] = "1"  # Ensure output appears in log files immediately
    env.pop("PYTHONUTF8", None)

    keys_dir = str((tmp_path / "keys").resolve())
    # Generate ephemeral keys for this test
    gen_result = subprocess.run(
        [sys.executable, "-c",
         f"import os, pathlib; p=pathlib.Path(r'{keys_dir}'); p.mkdir(parents=True, exist_ok=True);"
         "from securelink.crypto.keystore import KeyStore;"
         "ks=KeyStore.generate_ephemeral(sender_ids=[1]);"
         "import json;"
         "(p/'session_salt.bin').write_bytes(ks.session_salt);"
         "(p/'master.key').write_bytes(ks.master_secret);"
         "from cryptography.hazmat.primitives import serialization;"
         "pk=ks.sender_priv_keys[1];"
         "(p/'uav_sender_1_priv.pem').write_bytes(pk.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.TraditionalOpenSSL, serialization.NoEncryption()));"
         "(p/'uav_sender_1_pub.pem').write_bytes(pk.public_key().public_bytes(serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo));"],
        capture_output=True, text=True
    )
    assert gen_result.returncode == 0, f"Key gen failed: {gen_result.stderr}"

    rx_port = 51420
    rx_log = str(tmp_path / "rx.log")
    tx_log = str(tmp_path / "tx.log")

    rx_cmd = [
        sys.executable, "-u", "-m", "securelink.cli.rx",
        "--listen", f"127.0.0.1:{rx_port}",
        "--keys-dir", keys_dir,
        "--protect", "on",
        "--dashboard", "none",
        "--session-id", "h1-test",
    ]
    tx_cmd = [
        sys.executable, "-u", "-m", "securelink.cli.tx",
        "--send", f"127.0.0.1:{rx_port}",
        "--source", "synthetic",
        "--protect", "on",
        "--count", "20",
        "--rate-pps", "50",
        "--rekey-every", "5",
        "--seed", "1",
        "--keys-dir", keys_dir,
        "--session-id", "h1-test",
        "--dashboard", "none",
    ]

    p_rx = _run_proc(rx_cmd, rx_log, env)
    time.sleep(0.3)
    p_tx = _run_proc(tx_cmd, tx_log, env)

    try:
        p_tx.wait(timeout=15)
        time.sleep(1.0)  # Let RX flush
    finally:
        p_rx.terminate()
        try:
            p_rx.wait(timeout=2)
        except Exception:
            p_rx.kill()
        p_rx._log_file.close()
        p_tx._log_file.close()

    rx_text = open(rx_log, encoding="utf-8", errors="replace").read()
    tx_text = open(tx_log, encoding="utf-8", errors="replace").read()

    # No Python Tracebacks should appear
    assert "Traceback" not in rx_text, f"Traceback in rx.log:\n{rx_text[-800:]}"
    assert "Traceback" not in tx_text, f"Traceback in tx.log:\n{tx_text[-800:]}"
    assert "UnicodeEncodeError" not in rx_text, f"UnicodeEncodeError in rx.log"
    assert "UnicodeEncodeError" not in tx_text, f"UnicodeEncodeError in tx.log"

    # RX should have seen all 20 frames (check for "RX #" lines)
    rx_frame_lines = [l for l in rx_text.splitlines() if l.startswith("RX #")]
    assert len(rx_frame_lines) == 20, f"Expected 20 RX frame lines, got {len(rx_frame_lines)}:\n{rx_text[-1200:]}"

    # Rotation banners must be ASCII (no box-drawing characters)
    assert "\u2500" not in rx_text, "Non-ASCII box-drawing character found in rx.log"
    assert "\u2500" not in tx_text, "Non-ASCII box-drawing character found in tx.log"
    # micro sign (µ) must not appear
    assert "\u00b5" not in rx_text, "Non-ASCII micro sign found in rx.log"


def test_session_id_to_uint32_never_zero():
    """session_id_to_uint32 must never return 0."""
    from securelink.cli.common import session_id_to_uint32
    # Test integers
    assert session_id_to_uint32(0) != 0
    assert session_id_to_uint32(0xFFFFFFFF + 1) != 0  # wraps to 0 -> should return 1
    # Test strings (1000 hashes)
    import hashlib
    for i in range(1000):
        result = session_id_to_uint32(f"session-{i}")
        assert result != 0, f"Got 0 for session-{i}"
    # Test None
    for _ in range(20):
        assert session_id_to_uint32(None) != 0
