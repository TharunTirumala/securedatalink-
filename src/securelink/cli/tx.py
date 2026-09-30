"""SecureLink Transmitter (TX) Gateway CLI supporting real UDP output."""

import sys
import time
_t_start = time.perf_counter()
import json
import argparse
import hashlib
from pathlib import Path
from typing import Optional, Iterator, Tuple

from securelink.crypto.keystore import KeyStore
from securelink.pipeline.tx_pipeline import TxPipeline
from securelink.transport.udp import UdpSender, MAX_DATAGRAM_SIZE
from securelink.sources.synthetic import SyntheticTelemetrySource
from securelink.sources.tabular import parse_dataset, TabularSource, row_to_payload
from securelink.sources.mavlink_source import MavlinkSource
from securelink.cli.common import (
    parse_host_port,
    session_id_to_uint32,
    post_json_background,
    flush_posts,
    setup_stdio,
    GracefulExit,
)

# Overhead: header(24B) + GCM tag(16B) + ECDSA sig(64B) = 104 bytes
_FRAME_OVERHEAD = 104


def run_tx(args):
    setup_stdio()
    exit_handler = GracefulExit()
    send_host, send_port = parse_host_port(args.send, default_host="127.0.0.1", default_port=8888)
    sender = UdpSender(send_host, send_port)
    is_protected = (args.protect.lower() == "on")
    sess_uint = session_id_to_uint32(args.session_id)

    keystore, pipeline = None, None
    if is_protected:
        keystore = KeyStore.load_from_dir(args.keys_dir)
        pipeline = TxPipeline(
            keystore=keystore,
            sender_id=1,
            rekey_every_packets=args.rekey_every,
            session_id=sess_uint,
        )
    else:
        print("[UNPROTECTED] Plain byte pass-through mode active - no crypto applied.")

    # Manifest file setup
    manifest_f = open(args.manifest, "w", encoding="utf-8") if args.manifest else None

    # Source setup
    source_iter: Iterator[Tuple[float, bytes, int]]
    mav_source = None
    seed = args.seed if args.seed is not None else 42
    count = args.count  # None means unlimited

    if args.source == "mavlink":
        m_host, m_port = parse_host_port(args.mavlink_listen, default_host="127.0.0.1", default_port=14550)
        mav_source = MavlinkSource(m_host, m_port)
        source_iter = mav_source.stream_payloads()
    elif args.source in ("csv", "json", "jsonl"):
        path = Path(args.path)
        if not path.is_file():
            raise FileNotFoundError(f"Dataset file not found: {path}")
        parsed = parse_dataset(path.read_text(encoding="utf-8"))
        tab_src = TabularSource(parsed.rows, rate_pps=args.rate_pps)
        source_iter = tab_src.stream_payloads()
    else:
        # Synthetic source
        syn = SyntheticTelemetrySource(seed=seed, sender_id=1)
        n = count if count is not None else 200

        def _syn_gen():
            for seq in range(1, n + 1):
                pkt = syn.generate_packet(seq)
                yield pkt.timestamp, pkt.to_bytes(), seq
        source_iter = _syn_gen()

    import_sec = time.perf_counter() - _t_start
    print(f"READY name=tx t={time.time()} import_sec={import_sec:.4f}", flush=True)
    if getattr(args, "ready_file", None):
        try:
            from securelink.sessions.readiness import mark_ready
            mark_ready(args.ready_file)
        except Exception:
            pass

    sent_count, start_time = 0, time.time()
    last_stats_post, last_epoch_reported = 0.0, 1
    pace_internally = (args.source not in ("mavlink",))
    rate_interval = (1.0 / args.rate_pps) if (args.rate_pps > 0 and pace_internally) else 0.0

    try:
        for orig_ts, raw_payload, row_idx in source_iter:
            if exit_handler.stop_requested:
                break
            if count is not None and sent_count >= count:
                break

            # Size pre-check BEFORE transmit() so seq is not consumed on oversized frames
            if is_protected and len(raw_payload) + _FRAME_OVERHEAD > MAX_DATAGRAM_SIZE:
                print(f"[TX WARN] Skipping oversized payload: {len(raw_payload)}B payload would exceed {MAX_DATAGRAM_SIZE}B limit")
                continue

            step_start = time.monotonic()
            epoch_val, seq_val = 1, sent_count + 1
            if is_protected and pipeline:
                wire_bytes, frame = pipeline.transmit(raw_payload)
                epoch_val, seq_val = frame.header.key_epoch, frame.header.seq
            else:
                wire_bytes = raw_payload

            if len(wire_bytes) > MAX_DATAGRAM_SIZE:
                print(f"[TX WARN] Rejecting oversized wire frame: {len(wire_bytes)}B > {MAX_DATAGRAM_SIZE}B")
                continue

            sender.send(wire_bytes)
            sent_count += 1
            now = time.time()
            f_sha = hashlib.sha256(wire_bytes).hexdigest()

            if manifest_f:
                manifest_f.write(json.dumps({
                    "n": sent_count, "row_index": row_idx, "epoch": epoch_val,
                    "seq": seq_val, "frame_sha256": f_sha, "sent_ts": now,
                }) + "\n")
                manifest_f.flush()

            # Epoch rotation log - ASCII only
            if is_protected and epoch_val > last_epoch_reported:
                print(f"--- KEY EPOCH {last_epoch_reported} -> {epoch_val} ---")
                last_epoch_reported = epoch_val

            # Periodic line logging
            if sent_count % 50 == 0 or sent_count == 1:
                lbl = f"frame epoch {epoch_val} seq {seq_val}" if is_protected else "UNPROTECTED forward"
                print(f"TX: {lbl} -> {len(wire_bytes)}B (sha {f_sha[:8]}) total {sent_count}")

            # Background stats reporting
            if args.dashboard and (now - last_stats_post >= 0.1):
                last_stats_post = now
                elapsed = max(0.001, now - start_time)
                post_json_background(f"{args.dashboard}/api/ingest/stats", {
                    "component": "tx", "role": "tx", "session_id": args.session_id or "default",
                    "sent": sent_count, "epoch": epoch_val, "rate": round(sent_count / elapsed, 1),
                    "stats": {"sent": sent_count, "epoch": epoch_val, "rate": round(sent_count / elapsed, 1)},
                    "protect": args.protect,
                }, token=args.token)

            # Rate pacing
            if rate_interval > 0:
                elapsed_step = time.monotonic() - step_start
                sleep_sec = rate_interval - elapsed_step
                if sleep_sec > 0:
                    time.sleep(sleep_sec)

            if count is not None and sent_count >= count:
                break

    finally:
        sender.close()
        if mav_source:
            mav_source.close()
        duration = time.time() - start_time
        if args.dashboard:
            post_json_background(f"{args.dashboard}/api/ingest/stats", {
                "component": "tx", "role": "tx", "session_id": args.session_id or "default",
                "sent": sent_count, "epoch": last_epoch_reported, "rate": round(sent_count / max(0.001, duration), 1),
                "stats": {"sent": sent_count, "epoch": last_epoch_reported, "rate": round(sent_count / max(0.001, duration), 1)},
                "protect": args.protect,
            }, token=args.token)
            flush_posts(timeout=0.5)
        if manifest_f:
            manifest_f.write(json.dumps({
                "type": "summary", "sent": sent_count,
                "epochs": last_epoch_reported, "duration": round(duration, 3),
            }) + "\n")
            manifest_f.close()
        print(f"TX finished: {sent_count} datagrams sent in {duration:.2f}s")


def main():
    setup_stdio()
    parser = argparse.ArgumentParser(description="SecureLink TX Gateway")
    parser.add_argument("--send", default="127.0.0.1:8888", help="Target HOST:PORT (attacker or RX)")
    parser.add_argument("--source", choices=["synthetic", "csv", "json", "jsonl", "mavlink"], default="synthetic")
    parser.add_argument("--path", help="File path for dataset source")
    parser.add_argument("--mavlink-listen", default="127.0.0.1:14550", help="Listen HOST:PORT for raw MAVLink")
    parser.add_argument("--protect", choices=["on", "off"], default="on", help="Protection mode")
    parser.add_argument("--count", type=int, default=None, help="Packet count limit (None = unlimited)")
    parser.add_argument("--seed", type=int, default=None, help="RNG seed (0 is valid)")
    parser.add_argument("--rate-pps", type=int, default=25, help="Transmission rate in PPS")
    parser.add_argument("--rekey-every", type=int, default=50, help="Packets per key epoch")
    parser.add_argument("--keys-dir", default="keys", help="Directory containing keys")
    parser.add_argument("--session-id", default=None, help="Session UUID or identifier")
    parser.add_argument("--manifest", help="Path to write tx_manifest.jsonl")
    parser.add_argument("--dashboard", default="http://127.0.0.1:8000", help="Dashboard URL")
    parser.add_argument("--token", default=None, help="API token for dashboard ingest")
    parser.add_argument("--ready-file", default=None, help="Path to touch when socket is bound")
    args = parser.parse_args()
    run_tx(args)


if __name__ == "__main__":
    main()
