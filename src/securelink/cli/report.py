"""Terminal verification summary and exit-code reporting for SecureLink sessions."""

import argparse
import json
import sys
from pathlib import Path
from securelink.sessions.reconcile import reconcile_session
from securelink.sessions.telemetry_reconcile import reconcile_telemetry


def print_banner(text: str):
    print("\n" + "=" * 60)
    print(f" {text}")
    print("=" * 60)


def run_report(session_dir: Path) -> int:
    if not session_dir.exists() or not session_dir.is_dir():
        print(f"Error: Session directory does not exist: {session_dir}", file=sys.stderr)
        return 2

    # Load configuration
    cfg_file = session_dir / "config.json"
    cfg = json.loads(cfg_file.read_text(encoding="utf-8")) if cfg_file.exists() else {}
    protect_on = cfg.get("protect", True)

    print_banner(f"SECURELINK VERIFICATION REPORT: {session_dir.name}")
    print(f"Protection Mode: {'PROTECTED (ON)' if protect_on else 'UNPROTECTED (OFF)'}")
    print(f"Source Type:     {cfg.get('source_type', 'unknown')}")
    print(f"Attack Mode:     {cfg.get('attack_mode', 'none')} (rate: {cfg.get('attack_rate', 1.0)})")

    # Run reconciliations
    frame_rep = reconcile_session(session_dir)
    f_sum = frame_rep.get("summary", {})
    telem_rep = reconcile_telemetry(session_dir)

    print("\n[1] MULTISET FRAME RECONCILIATION:")
    print(f"  Total Sent (TX):        {f_sum.get('total_sent', 0)}")
    print(f"  Total RX Events:        {f_sum.get('total_rx_events', 0)}")
    print(f"  Total Delivered Clean:  {f_sum.get('total_delivered', 0)}")
    print(f"  Authentic:              {f_sum.get('authentic', 0)}")
    print(f"  Tampered (Rejected):    {f_sum.get('tampered', 0)}")
    print(f"  Replayed (Rejected):    {f_sum.get('replayed', 0)}")
    print(f"  Dropped by Attacker:    {f_sum.get('dropped_by_attacker', 0)}")
    print(f"  False Accepts:          {f_sum.get('false_accepts', 0)}  (target: 0)")
    print(f"  False Rejects:          {f_sum.get('false_rejects', 0)}  (target: 0)")

    missing = f_sum.get("missing_frames", 0)
    if missing > 0:
        attr = f_sum.get("missing_attribution", {})
        print(f"\n  Missing Frames Breakdown ({missing} total):")
        print(f"    - Attacker Drops:     {attr.get('dropped_by_attacker', 0)}")
        print(f"    - Tampered & Cut:     {attr.get('tampered_and_rejected', 0)}")
        print(f"    - Unexplained Loss:   {attr.get('unexplained', 0)}")

    if telem_rep.get("truth_messages", 0) > 0:
        print("\n[2] TELEMETRY DIVERGENCE AUDIT (MAVLink):")
        print(f"  Drone Truth Messages:   {telem_rep.get('truth_messages', 0)}")
        print(f"  C2 Received Messages:   {telem_rep.get('c2_messages', 0)}")
        print(f"  Matched Messages:       {telem_rep.get('matched_messages', 0)}")
        print(f"  Delivered Identical:    {telem_rep.get('delivered_identical', 0)}")
        print(f"  Delivered Altered:      {telem_rep.get('delivered_altered', 0)}")
        print(f"  Max Position Error:     {telem_rep.get('max_position_error_m', 0.0):.2f} meters")
        print(f"  Mean Position Error:    {telem_rep.get('mean_position_error_m', 0.0):.2f} meters")

    # Evaluate verdict
    false_accepts = f_sum.get("false_accepts", 0)
    altered = telem_rep.get("delivered_altered", 0)

    print("\n" + "-" * 60)
    if protect_on:
        if false_accepts == 0 and altered == 0:
            print(" VERDICT: PASS [0 False Accepts, 0 Altered Telemetry Delivered]")
            print("-" * 60)
            return 0
        else:
            print(" VERDICT: FAIL [Security Invariant Violated]")
            print(f" False Accepts: {false_accepts}, Altered Delivered: {altered}")
            print("-" * 60)
            return 2
    else:
        # Protect OFF mode
        print(" VERDICT: UNPROTECTED RUN COMPLETE")
        print(f" Altered Telemetry Injected: {altered}")
        print("-" * 60)
        return 0


def main():
    parser = argparse.ArgumentParser(description="SecureLink Session Verification Report")
    parser.add_argument("--session-dir", required=True, help="Path to data/sessions/<session_id>")
    args = parser.parse_args()
    code = run_report(Path(args.session_dir))
    sys.exit(code)


if __name__ == "__main__":
    main()
