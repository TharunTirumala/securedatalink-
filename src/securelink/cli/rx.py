"""SecureLink Receiver (RX) Gateway CLI supporting real UDP input and C2 dispatch."""

import sys
import time
_t_start = time.perf_counter()
import json
import base64
import argparse
import hashlib
import threading
import urllib.request
from typing import Optional, List, Dict, Any

from securelink.crypto.keystore import KeyStore
from securelink.pipeline.rx_pipeline import RxPipeline
from securelink.pipeline.operator_state import OperatorState
from securelink.pipeline.replay_guard import ReplayGuard
from securelink.core.types import Verdict, Reason
from securelink.transport.udp import UdpReceiver, UdpSender
from securelink.cli.common import (
    parse_host_port,
    post_json_background,
    session_id_to_uint32,
    setup_stdio,
    GracefulExit,
)


def run_rx(args):
    setup_stdio()
    exit_handler = GracefulExit()
    listen_host, listen_port = parse_host_port(args.listen, default_host="127.0.0.1", default_port=9999)
    receiver = UdpReceiver(listen_host, listen_port)
    import_sec = time.perf_counter() - _t_start
    print(f"READY name=rx t={time.time()} import_sec={import_sec:.4f}", flush=True)
    if getattr(args, "ready_file", None):
        try:
            from securelink.sessions.readiness import mark_ready
            mark_ready(args.ready_file)
        except Exception:
            pass
    receiver.drain_buffer()
    expected_sess_uint = session_id_to_uint32(args.session_id) if args.session_id else None

    c2_sender = None
    if args.mavlink_out:
        c2_host, c2_port = parse_host_port(args.mavlink_out, default_host="127.0.0.1", default_port=14551)
        c2_sender = UdpSender(c2_host, c2_port)

    is_protected = (args.protect.lower() == "on")
    keystore, pipeline = None, None
    operator_state = OperatorState()
    if is_protected:
        keystore = KeyStore.load_from_dir(args.keys_dir).to_public_keystore()
        assert not keystore.sender_priv_keys, "RX must not hold private keys"
        guard = ReplayGuard(max_clock_skew=getattr(args, "max_clock_skew", 30.0))
        pipeline = RxPipeline(keystore=keystore, replay_guard=guard, operator_state=operator_state)
    else:
        print("[UNPROTECTED] Plain byte pass-through mode active - no crypto verification.")

    use_dashboard = bool(args.dashboard and args.dashboard.lower() != "none")

    # Poll dashboard for blocked senders
    if use_dashboard:
        def _poll_blocked_senders():
            url = f"{args.dashboard}/api/state"
            while not exit_handler.stop_requested:
                try:
                    req = urllib.request.Request(url)
                    if args.token:
                        req.add_header("X-SecureLink-Token", args.token)
                    with urllib.request.urlopen(req, timeout=1.0) as resp:
                        if resp.status == 200:
                            data = json.loads(resp.read().decode("utf-8"))
                            bs = data.get("blocked_senders", [])
                            with operator_state._lock:
                                operator_state.blocked_senders = set(int(x) for x in bs)
                except Exception:
                    pass
                time.sleep(1.0)

        t_poll = threading.Thread(target=_poll_blocked_senders, daemon=True)
        t_poll.start()
    events_f = open(args.events_log, "w", encoding="utf-8") if args.events_log else None
    output_f = open(args.output_log, "w", encoding="utf-8") if args.output_log else None

    counts: Dict[str, int] = {"AUTHENTIC": 0, "TAMPERED": 0, "REPLAYED": 0, "SPOOFED": 0, "DROPPED": 0, "OTHER": 0, "total": 0}
    latencies: List[float] = []
    epochs_seen = set()
    last_epoch_printed = None

    pending_events: List[Dict[str, Any]] = []
    last_event_post, last_stats_post = 0.0, 0.0
    start_time = time.time()

    print(f"RX listening on {listen_host}:{listen_port} (protect={args.protect})...")

    def flush_events():
        nonlocal pending_events, last_event_post
        if pending_events and use_dashboard:
            batch = list(pending_events[:500])
            pending_events = pending_events[len(batch):]
            post_json_background(
                f"{args.dashboard}/api/ingest/events",
                {"session_id": args.session_id or "default", "events": batch},
                token=args.token,
            )
            last_event_post = time.time()

    try:
        while not exit_handler.stop_requested:
            res = receiver.recv(timeout=0.1)
            now = time.time()

            if res is not None:
                raw_bytes, addr = res
                f_sha = hashlib.sha256(raw_bytes).hexdigest()

                if is_protected and pipeline:
                    t_start = time.perf_counter()
                    verdict, reason, plaintext, header = pipeline.process_frame(raw_bytes)
                    if header and expected_sess_uint is not None and header.session_id != 0 and header.session_id != expected_sess_uint:
                        continue
                    counts["total"] += 1
                    lat_us = (time.perf_counter() - t_start) * 1e6
                    latencies.append(lat_us)

                    v_str = verdict.value
                    if v_str in counts:
                        counts[v_str] += 1
                    else:
                        counts["OTHER"] += 1

                    # Only update epoch tracking for authenticated frames
                    if verdict == Verdict.AUTHENTIC and header is not None:
                        ep = header.key_epoch
                        epochs_seen.add(ep)
                        if last_epoch_printed is not None and ep != last_epoch_printed:
                            # ASCII-only epoch banner
                            print(f"--- KEY EPOCH {last_epoch_printed} -> {ep} ---")
                        last_epoch_printed = ep

                    # Extract fields for logging; None for malformed frames
                    if header is not None:
                        ep = header.key_epoch
                        seq = header.seq
                        sid = header.sender_id
                        # ASCII-only latency unit
                        print(f"RX #{seq} epoch {ep} {v_str} {reason.value} {lat_us:.1f}us")
                    else:
                        ep, seq, sid = None, None, None
                        print(f"RX [MALFORMED] {v_str} {reason.value} {lat_us:.1f}us")

                    event_entry = {
                        "ts": now, "verdict": v_str, "reason": reason.value,
                        "epoch": ep, "seq": seq, "sender_id": sid,
                        "latency_us": round(lat_us, 1), "src_addr": f"{addr[0]}:{addr[1]}",
                        "frame_sha256": f_sha,
                    }
                    if events_f:
                        events_f.write(json.dumps(event_entry) + "\n")
                        events_f.flush()
                    # Only buffer pending_events when dashboard is configured
                    if use_dashboard:
                        pending_events.append(event_entry)

                    if verdict == Verdict.AUTHENTIC and plaintext:
                        if c2_sender:
                            c2_sender.send(plaintext)
                        if output_f:
                            output_f.write(json.dumps({
                                "frame_sha256": f_sha, "epoch": ep, "seq": seq,
                                "payload_b64": base64.b64encode(plaintext).decode("ascii"),
                            }) + "\n")
                            output_f.flush()
                else:
                    # Protect OFF
                    counts["total"] += 1
                    counts["AUTHENTIC"] += 1
                    event_entry = {
                        "ts": now, "verdict": "AUTHENTIC", "reason": "unprotected_pass_through",
                        "epoch": 1, "seq": counts["total"], "sender_id": 1,
                        "latency_us": 0.0, "src_addr": f"{addr[0]}:{addr[1]}",
                        "frame_sha256": f_sha,
                    }
                    if events_f:
                        events_f.write(json.dumps(event_entry) + "\n")
                        events_f.flush()
                    if use_dashboard:
                        pending_events.append(event_entry)
                    if c2_sender:
                        c2_sender.send(raw_bytes)
                    if output_f:
                        output_f.write(json.dumps({
                            "frame_sha256": f_sha, "epoch": 1, "seq": counts["total"],
                            "payload_b64": base64.b64encode(raw_bytes).decode("ascii"),
                        }) + "\n")
                        output_f.flush()
                    if counts["total"] % 50 == 0 or counts["total"] == 1:
                        print(f"RX [UNPROTECTED]: forwarded {len(raw_bytes)}B (total {counts['total']})")

            # Periodic batch flush (every 100 ms)
            if now - last_event_post >= 0.1:
                flush_events()

            # Periodic stats report (every 500 ms) - latency/epoch only, no verdict counts
            if use_dashboard and (now - last_stats_post >= 0.5):
                last_stats_post = now
                p50, p99 = 0.0, 0.0
                if latencies:
                    s_lat = sorted(latencies)
                    p50 = s_lat[int(len(s_lat) * 0.50)]
                    p99 = s_lat[min(len(s_lat) - 1, int(len(s_lat) * 0.99))]
                post_json_background(
                    f"{args.dashboard}/api/ingest/stats",
                    {
                        "component": "rx", "role": "rx", "session_id": args.session_id or "default",
                        "received": counts["total"],
                        "stats": {"p50_us": round(p50, 1), "p99_us": round(p99, 1)},
                        "p50_us": round(p50, 1), "p99_us": round(p99, 1),
                        "protect": args.protect,
                    },
                    token=args.token,
                )

    finally:
        flush_events()
        if use_dashboard:
            p50, p99 = 0.0, 0.0
            if latencies:
                s_lat = sorted(latencies)
                p50 = s_lat[int(len(s_lat) * 0.50)]
                p99 = s_lat[min(len(s_lat) - 1, int(len(s_lat) * 0.99))]
            post_json_background(
                f"{args.dashboard}/api/ingest/stats",
                {
                    "component": "rx", "role": "rx", "session_id": args.session_id or "default",
                    "received": counts["total"],
                    "stats": {"p50_us": round(p50, 1), "p99_us": round(p99, 1)},
                    "p50_us": round(p50, 1), "p99_us": round(p99, 1),
                    "protect": args.protect,
                },
                token=args.token,
            )
        receiver.close()
        if c2_sender:
            c2_sender.close()
        if events_f:
            events_f.close()
        if output_f:
            output_f.close()

        # Print exit summary - ASCII only
        duration = time.time() - start_time
        p50, p95, p99 = 0.0, 0.0, 0.0
        if latencies:
            s_lat = sorted(latencies)
            p50 = s_lat[int(len(s_lat) * 0.50)]
            p95 = s_lat[min(len(s_lat) - 1, int(len(s_lat) * 0.95))]
            p99 = s_lat[min(len(s_lat) - 1, int(len(s_lat) * 0.99))]
        print("\n=== RX SUMMARY ===")
        print(f"Total Received : {counts['total']} frames in {duration:.2f}s")
        print(f"Verdicts       : AUTHENTIC={counts['AUTHENTIC']}, TAMPERED={counts['TAMPERED']}, REPLAYED={counts['REPLAYED']}, SPOOFED={counts['SPOOFED']}")
        print(f"Latency (us)   : p50={p50:.1f}, p95={p95:.1f}, p99={p99:.1f}")
        print(f"Epochs Seen    : {sorted(list(epochs_seen)) or [1]}")


def main():
    setup_stdio()
    parser = argparse.ArgumentParser(description="SecureLink RX Gateway")
    parser.add_argument("--listen", default="127.0.0.1:9999", help="Listen HOST:PORT")
    parser.add_argument("--keys-dir", default="keys", help="Directory containing keys")
    parser.add_argument("--protect", choices=["on", "off"], default="on", help="Protection mode")
    parser.add_argument("--dashboard", default="http://127.0.0.1:8000", help="Dashboard URL or 'none'")
    parser.add_argument("--token", default=None, help="API token if required")
    parser.add_argument("--session-id", default=None, help="Session UUID or identifier")
    parser.add_argument("--events-log", help="Path to write rx_events.jsonl")
    parser.add_argument("--output-log", help="Path to write rx_output.jsonl")
    parser.add_argument("--mavlink-out", default=None, help="Destination HOST:PORT for clean MAVLink")
    parser.add_argument("--print-payload", action="store_true", help="Print payload details")
    parser.add_argument("--max-clock-skew", type=float, default=30.0, help="Max clock skew in seconds for STALE_TIMESTAMP")
    parser.add_argument("--ready-file", default=None, help="Path to touch when socket is bound")
    args = parser.parse_args()
    run_rx(args)


if __name__ == "__main__":
    main()
