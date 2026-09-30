"""Integration tests for session management and multi-node reconciliation."""

import shutil
import tempfile
import time
from pathlib import Path
import pytest

from securelink.sessions.models import SessionConfig, SessionState
from securelink.sessions.store import SessionStore
from securelink.sessions.manager import SessionManager
from securelink.sessions.reconcile import reconcile_session
from securelink.sessions.telemetry_reconcile import reconcile_telemetry


def test_session_store_crud():
    with tempfile.TemporaryDirectory() as tmpdir:
        store = SessionStore(base_dir=Path(tmpdir))
        cfg = SessionConfig(session_id="test-123", protect=True, rate_pps=10)
        store.save_config(cfg)

        loaded_cfg = store.load_config("test-123")
        assert loaded_cfg is not None
        assert loaded_cfg.protect is True
        assert loaded_cfg.rate_pps == 10

        st = SessionState(session_id="test-123", status="running", start_time=100.0)
        store.save_state(st)

        loaded_st = store.load_state("test-123")
        assert loaded_st is not None
        assert loaded_st.status == "running"

        report = {"summary": {"total_sent": 50, "authentic": 50}}
        store.save_reconcile_report("test-123", report)
        loaded_rep = store.load_reconcile_report("test-123")
        assert loaded_rep["summary"]["authentic"] == 50

        sessions = store.list_sessions()
        assert len(sessions) == 1
        assert sessions[0]["session_id"] == "test-123"


def test_reconcile_empty_and_graceful():
    with tempfile.TemporaryDirectory() as tmpdir:
        s_dir = Path(tmpdir)
        # Empty directory should never raise exception
        f_rep = reconcile_session(s_dir)
        assert f_rep["summary"]["total_sent"] == 0
        assert f_rep["summary"]["false_accepts"] == 0

        t_rep = reconcile_telemetry(s_dir)
        assert t_rep["truth_messages"] == 0
        assert t_rep["delivered_altered"] == 0


def test_session_lifecycle_protect_on():
    with tempfile.TemporaryDirectory() as tmpdir:
        store = SessionStore(base_dir=Path(tmpdir))
        mgr = SessionManager(store=store)

        # Run 10 synthetic frames with protect=on and attacker pass mode
        cfg = SessionConfig(
            session_id="test-lifecycle-on",
            source_type="synthetic",
            count=15,
            rate_pps=50,
            protect=True,
            attack_mode="pass",
            attack_rate=1.0,
            tx_port=15550,
            attacker_port=18888,
            attacker_control_port=18889,
            rx_port=19999,
            c2_port=15551,
            dashboard_url="http://127.0.0.1:9999",  # dummy, no dashboard needed
        )

        st = mgr.start_session(cfg)
        assert st.status == "running"

        # Wait for watchdog to complete the count of 15 frames
        deadline = time.time() + 5.0
        final_st = None
        while time.time() < deadline:
            time.sleep(0.3)
            final_st = store.load_state("test-lifecycle-on")
            if final_st and final_st.status in ("finished", "stopped"):
                break

        if final_st and final_st.status == "running":
            mgr.stop_session("test-lifecycle-on")

        rep = store.load_reconcile_report("test-lifecycle-on")
        assert rep is not None
        assert "frame_reconciliation" in rep
        # In clean pass mode with protect=on, false_accepts must be 0
        assert rep["frame_reconciliation"]["summary"]["false_accepts"] == 0
        assert rep["frame_reconciliation"]["summary"]["authentic"] > 0


def test_telemetry_reconciliation_protect_off_vs_on():
    with tempfile.TemporaryDirectory() as tmpdir:
        store = SessionStore(base_dir=Path(tmpdir))
        mgr = SessionManager(store=store)

        # 1. Protect OFF with position_rewrite attack
        cfg_off = SessionConfig(
            session_id="test-telem-off",
            source_type="drone",
            count=15,
            rate_pps=30,
            protect=False,
            attack_mode="position_rewrite",
            attack_rate=1.0,
            attack_params={"lat_offset_deg": 0.05, "lon_offset_deg": 0.05},
            tx_port=16550,
            attacker_port=18880,
            attacker_control_port=18881,
            rx_port=19990,
            c2_port=16551,
            dashboard_url="http://127.0.0.1:9999",
        )
        mgr.start_session(cfg_off)
        for _ in range(15):
            time.sleep(0.3)
            st = store.load_state("test-telem-off")
            if st and st.status in ("finished", "stopped"):
                break
        if store.load_state("test-telem-off").status == "running":
            mgr.stop_session("test-telem-off")

        rep_off = store.load_reconcile_report("test-telem-off")
        assert rep_off is not None
        # With protect=off, mutated frames pass right through to C2!
        telem_off = rep_off["telemetry_reconciliation"]
        assert telem_off["delivered_altered"] > 0
        assert telem_off["max_position_error_m"] > 100.0

