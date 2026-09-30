"""Unit tests for process readiness helpers and command generation."""

import time
from pathlib import Path
from securelink.sessions.models import SessionConfig
from securelink.sessions.proc_cmds import build_process_commands
from securelink.sessions.readiness import ready_dir, mark_ready, wait_for_ready


def test_build_process_commands_drone_first_and_ready_args(tmp_path):
    s_dir = tmp_path / "test_session"
    cfg = SessionConfig(
        session_id="test_readiness_cmd",
        source_type="drone",
        rate_pps=20,
        count=50,
        protect=True,
    )
    cmds = build_process_commands(cfg, s_dir, token="tok123")

    # Order check: drone must be first
    keys = list(cmds.keys())
    assert keys[0] == "drone", f"Expected drone to be first command, got: {keys}"

    # Ready file args check
    assert "--wait-for" in cmds["drone"]
    tx_ready_path = str(ready_dir(s_dir) / "tx.ready")
    assert tx_ready_path in cmds["drone"]

    for proc_name in ("tx", "attacker", "rx", "c2"):
        assert proc_name in cmds
        assert "--ready-file" in cmds[proc_name]
        expected_path = str(ready_dir(s_dir) / f"{proc_name}.ready")
        assert expected_path in cmds[proc_name]


def test_readiness_helpers_success_and_timeout(tmp_path):
    r_dir = ready_dir(tmp_path)
    f1 = r_dir / "p1.ready"
    f2 = r_dir / "p2.ready"

    # Timeout case: files do not exist
    t0 = time.monotonic()
    assert not wait_for_ready([f1, f2], timeout=0.1)
    elapsed = time.monotonic() - t0
    assert elapsed >= 0.08

    # Success case: mark files ready
    mark_ready(f1)
    mark_ready(f2)
    assert f1.exists()
    assert f2.exists()
    assert wait_for_ready([f1, f2], timeout=0.5)
