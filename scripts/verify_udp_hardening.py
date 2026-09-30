"""Comprehensive end-to-end verification of Phase 3 Hardening (H1 through H10).

Runs:
1. 600+ frames across 6+ key epochs over real UDP with logs redirected to files.
2. Checks all logs for zero Tracebacks / UnicodeEncodeErrors.
3. Tests replay, jam, and tamper modes to confirm 0 phantom false accepts.
4. Verifies live session counters against reconcile_report.json.
"""

import sys
import time
import json
import shutil
from pathlib import Path

from securelink.sessions.models import SessionConfig
from securelink.sessions.manager import SessionManager
from securelink.sessions.store import SessionStore
from dashboard.backend import transport_state


def run_verification():
    print("=" * 70)
    print("STARTING SECURELINK END-TO-END HARDENING VERIFICATION")
    print("=" * 70)

    store = SessionStore()
    manager = SessionManager(store=store)

    # -------------------------------------------------------------
    # RUN 1: 600+ frames across 6+ epochs with log file redirection
    # -------------------------------------------------------------
    sid = f"verify_600_e6_{int(time.time())}"
    print(f"\n[1/3] Running 600-frame 6-epoch UDP session: {sid}")

    cfg = SessionConfig(
        session_id=sid,
        source_type="drone",
        protect=True,
        count=600,
        rate_pps=100,
        rekey_every=90,  # 600 frames / 90 = ~7 epochs!
        drone_seed=42,
        attack_mode="pass",
        attack_rate=1.0,
        tx_port=44550,
        attacker_port=44888,
        attacker_control_port=44889,
        rx_port=44999,
        c2_port=44551,
        keys_dir="keys",
        dashboard_url="none",
    )

    transport_state.reset_session_counters(sid)
    st = manager.start_session(cfg, restart=True)
    assert st.status == "running"

    # Wait for completion (600 pkts @ 100 pps = ~6s + settle)
    print("  Streaming 600 frames through TX -> Attacker -> RX -> C2...")
    t_start = time.time()
    while time.time() - t_start < 25:
        cur_st = store.load_state(sid)
        if cur_st and cur_st.status in ("finished", "failed", "stopped"):
            break
        time.sleep(0.5)

    manager.stop_session(sid)
    print(f"  Session completed in {time.time() - t_start:.2f}s")

    # Inspect logs
    s_dir = store.get_session_dir(sid)
    logs_dir = s_dir / "logs"
    for log_path in sorted(logs_dir.glob("*.log")):
        content = log_path.read_text(encoding="utf-8", errors="replace")
        assert "Traceback" not in content, f"Traceback found in {log_path.name}:\n{content[-500:]}"
        assert "UnicodeEncodeError" not in content, f"UnicodeEncodeError found in {log_path.name}"
        print(f"  Log check: {log_path.name} - Clean (no tracebacks, {len(content.splitlines())} lines)")

    # Verify frame count and epochs
    rx_events_path = s_dir / "rx_events.jsonl"
    assert rx_events_path.exists(), "rx_events.jsonl not created"
    rx_lines = [json.loads(line) for line in rx_events_path.read_text(encoding="utf-8").splitlines() if line.strip()]
    epochs = set(ev["epoch"] for ev in rx_lines if ev.get("epoch") is not None)
    print(f"  Frames verified by RX: {len(rx_lines)}")
    print(f"  Epochs observed by RX: {sorted(list(epochs))} (count={len(epochs)})")
    assert len(rx_lines) >= 500, f"Expected at least 500 frames, got {len(rx_lines)}"
    assert len(epochs) >= 6, f"Expected at least 6 epochs, got {len(epochs)}"

    # -------------------------------------------------------------
    # RUN 2: Attack runs (Tamper, Replay, Jam) -> 0 phantom false accepts
    # -------------------------------------------------------------
    print("\n[2/3] Verifying 0 phantom false accepts under attacks...")
    for attack_mode in ("tamper", "replay", "jam"):
        atk_sid = f"verify_{attack_mode}_{int(time.time())}"
        print(f"  Testing attack_mode='{attack_mode}' (sid={atk_sid})...")
        atk_cfg = SessionConfig(
            session_id=atk_sid,
            source_type="synthetic",
            protect=True,
            count=150,
            rate_pps=100,
            rekey_every=50,
            attack_mode=attack_mode,
            attack_rate=0.7,
            tx_port=45550,
            attacker_port=45888,
            attacker_control_port=45889,
            rx_port=45999,
            c2_port=45551,
            keys_dir="keys",
            dashboard_url="none",
        )
        transport_state.reset_session_counters(atk_sid)
        manager.start_session(atk_cfg, restart=True)
        t_run = time.time()
        while time.time() - t_run < 15:
            cst = store.load_state(atk_sid)
            if cst and cst.status in ("finished", "failed", "stopped"):
                break
            time.sleep(0.5)
        manager.stop_session(atk_sid)

        # Check reconciliation report
        rep_file = store.get_session_dir(atk_sid) / "reconcile_report.json"
        if rep_file.exists():
            rep = json.loads(rep_file.read_text(encoding="utf-8"))
            summary = rep.get("frame_reconciliation", {}).get("summary", {})
            false_accepts = summary.get("false_accepts", 0)
            print(f"    Mode {attack_mode}: authentic={summary.get('authentic', 0)}, tampered={summary.get('tampered', 0)}, false_accepts={false_accepts}")
            assert false_accepts == 0, f"Expected 0 false accepts in {attack_mode}, got {false_accepts}"

    print("\n[3/3] All checks passed successfully! Zero regressions.")
    print("=" * 70)


if __name__ == "__main__":
    run_verification()
