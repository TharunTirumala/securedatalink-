"""Adversarial attacker proxy bridging UDP sockets with dynamic runtime mutation.

Strict isolation: NEVER import crypto, rx_pipeline, tx_pipeline, or keystores.
"""

import time
_t_start = time.perf_counter()
import argparse
import hashlib
import http.server
import json
import os
import random
import struct
import sys
import threading
from typing import Any, Dict, List, Optional, Tuple

from securelink.cli.common import GracefulExit, parse_host_port, post_json_background, setup_stdio
from securelink.simulation.attacks.mavlink_modes import MavlinkMutator
from securelink.simulation.attacks.wire_modes import (
    WireJammer, WireReplayBuffer, apply_wire_drop, apply_wire_pass, apply_wire_spoof, apply_wire_tamper
)
from securelink.transport.udp import UdpReceiver, UdpSender


class AttackerState:
    """Thread-safe mutable state for attacker settings and counters."""

    def __init__(self, mode: str = "pass", rate: float = 1.0, params: Optional[Dict] = None):
        self.lock = threading.Lock()
        self.mode = mode
        self.rate = rate
        self.params = params or {}
        self.stats = {"received": 0, "forwarded": 0, "mutated": 0, "dropped": 0}


def extract_seq(raw_bytes: bytes) -> Optional[int]:
    """Extract packet sequence number without importing crypto or protocol internals."""
    if not raw_bytes:
        return None
    try:
        ver = raw_bytes[0]
        if ver == 1 and len(raw_bytes) >= 12:
            return struct.unpack(">Q", raw_bytes[4:12])[0]
        elif ver == 2 and len(raw_bytes) >= 16:
            return struct.unpack(">Q", raw_bytes[8:16])[0]
        elif ver == 3 and len(raw_bytes) >= 17:
            return struct.unpack(">Q", raw_bytes[9:17])[0]
        elif ver == 0xFD and len(raw_bytes) >= 5:
            return raw_bytes[4]
    except Exception:
        pass
    return None


def extract_epoch(raw_bytes: bytes) -> Optional[int]:
    """Extract packet epoch without importing crypto or protocol internals."""
    if not raw_bytes:
        return None
    try:
        ver = raw_bytes[0]
        if ver in (1, 2) and len(raw_bytes) >= 4:
            return raw_bytes[3]
        elif ver == 3 and len(raw_bytes) >= 5:
            return struct.unpack(">H", raw_bytes[3:5])[0]
    except Exception:
        pass
    return None


class ReusableHTTPServer(http.server.HTTPServer):
    allow_reuse_address = True


def create_control_handler(state: AttackerState, auth_token: Optional[str]):
    class ControlHandler(http.server.BaseHTTPRequestHandler):
        def log_message(self, format, *args):
            pass  # Quiet logging

        def _check_auth(self) -> bool:
            if not auth_token:
                return True
            auth_header = self.headers.get("Authorization", "")
            return auth_header == f"Bearer {auth_token}"

        def do_GET(self):
            if not self._check_auth():
                self.send_response(401); self.end_headers(); return
            if self.path == "/stats":
                with state.lock:
                    payload = json.dumps({"mode": state.mode, "rate": state.rate, **state.stats})
                self.send_response(200)
                self.send_header("Content-Type", "application/json")
                self.end_headers()
                self.wfile.write(payload.encode())
            else:
                self.send_response(404); self.end_headers()

        def do_POST(self):
            if not self._check_auth():
                self.send_response(401); self.end_headers(); return
            if self.path == "/control":
                content_len = int(self.headers.get("Content-Length", 0))
                body = self.rfile.read(content_len)
                try:
                    data = json.loads(body)
                    with state.lock:
                        if "mode" in data: state.mode = data["mode"]
                        if "rate" in data: state.rate = float(data["rate"])
                        if "params" in data: state.params.update(data["params"])
                    self.send_response(200)
                    self.send_header("Content-Type", "application/json")
                    self.end_headers()
                    self.wfile.write(b'{"status":"ok"}')
                except Exception as e:
                    self.send_response(400); self.end_headers()
                    self.wfile.write(str(e).encode())
            else:
                self.send_response(404); self.end_headers()

    return ControlHandler


def run_control_server(port: int, state: AttackerState, auth_token: Optional[str]):
    ReusableHTTPServer(("127.0.0.1", port), create_control_handler(state, auth_token)).serve_forever()


def main():
    setup_stdio()
    parser = argparse.ArgumentParser(description="SecureLink Adversarial Proxy")
    parser.add_argument("--listen", required=True, help="HOST:PORT to receive datagrams")
    parser.add_argument("--forward", required=True, help="HOST:PORT to send datagrams")
    parser.add_argument("--mode", default="pass", help="Attack mode")
    parser.add_argument("--rate", type=float, default=1.0, help="Probability [0.0..1.0]")
    parser.add_argument("--control-port", type=int, default=0, help="Local control HTTP port")
    parser.add_argument("--seed", type=int, default=None, help="RNG seed")
    parser.add_argument("--log", default=None, help="JSONL log path")
    parser.add_argument("--dashboard", default=None, help="Dashboard URL")
    parser.add_argument("--session-id", default=None, help="Session UUID")
    parser.add_argument("--token", default=None, help="API token for dashboard ingest")
    parser.add_argument("--ready-file", default=None, help="Path to touch when socket is bound")
    args = parser.parse_args()

    l_host, l_port = parse_host_port(args.listen)
    f_host, f_port = parse_host_port(args.forward)
    token = os.environ.get("SECURELINK_CONTROL_TOKEN")
    state = AttackerState(mode=args.mode, rate=args.rate)
    rng = random.Random(args.seed) if args.seed is not None else random

    if args.control_port > 0:
        t = threading.Thread(
            target=run_control_server,
            args=(args.control_port, state, token),
            daemon=True
        )
        t.start()

    receiver = UdpReceiver(l_host, l_port)
    sender = UdpSender(f_host, f_port)
    import_sec = time.perf_counter() - _t_start
    print(f"READY name=attacker t={time.time()} import_sec={import_sec:.4f}", flush=True)
    if args.ready_file:
        try:
            from securelink.sessions.readiness import mark_ready
            mark_ready(args.ready_file)
        except Exception:
            pass
    replay_buf = WireReplayBuffer()
    jammer = WireJammer()
    mav_mutator = MavlinkMutator()
    killer = GracefulExit()

    log_file = open(args.log, "a", encoding="utf-8") if args.log else None
    last_stats = time.time()
    last_action_flush = time.time()
    pending_actions: List[Dict[str, Any]] = []

    def flush_actions():
        nonlocal pending_actions, last_action_flush
        if pending_actions and args.dashboard:
            batch = list(pending_actions)
            pending_actions = []
            post_json_background(
                f"{args.dashboard}/api/ingest/attacker_actions",
                {"session_id": args.session_id or "default", "actions": batch},
                token=args.token,
            )
        last_action_flush = time.time()

    try:
        while not killer.stop:
            item = receiver.recv(timeout=0.1)
            now = time.time()
            if item is None:
                if args.dashboard and now - last_stats >= 0.5:
                    with state.lock:
                        st = dict(state.stats)
                    post_json_background(
                        f"{args.dashboard}/api/ingest/stats",
                        {"component": "attacker", "role": "attacker", "session_id": args.session_id, "stats": st},
                        token=args.token,
                    )
                    last_stats = now
                if now - last_action_flush >= 0.2:
                    flush_actions()
                continue

            raw, _ = item
            in_sha = hashlib.sha256(raw).hexdigest()
            with state.lock:
                cur_mode, cur_rate, cur_params = state.mode, state.rate, dict(state.params)
                state.stats["received"] += 1

            action = "pass"
            label = "AUTHENTIC"
            out_bytes = raw
            field_name = None

            if rng.random() < cur_rate:
                if cur_mode == "pass":
                    out_bytes, label = apply_wire_pass(raw)
                elif cur_mode == "tamper":
                    out_bytes, label = apply_wire_tamper(raw, seed=rng.randint(0, 100000))
                    action = "tampered"
                elif cur_mode == "drop":
                    out_bytes, label = apply_wire_drop(raw)
                    action = "dropped"
                elif cur_mode == "spoof":
                    out_bytes, label = apply_wire_spoof(raw, seed=rng.randint(0, 100000))
                    action = "spoofed"
                elif cur_mode == "replay":
                    rep = replay_buf.get_replay(seed=rng.randint(0, 100000))
                    if rep:
                        out_bytes = rep
                        action = "replayed"
                        label = "REPLAYED"
                elif cur_mode == "jam":
                    jammed_out, jammed_label = jammer.handle(raw, seed=rng.randint(0, 100000))
                    out_bytes = jammed_out
                    # A delayed+released frame arrives late but is NOT a replay (no prior send)
                    label = jammed_label if jammed_label != "REPLAYED" else "AUTHENTIC"
                    action = "jammed"
                elif cur_mode in ["position_rewrite", "altitude_rewrite", "gps_freeze", "battery_lie", "heartbeat_flood"]:
                    out_bytes, label, meta = mav_mutator.mutate(raw, cur_mode, cur_params)
                    action = "tampered" if meta.get("fallback") else "mutated"
                    field_name = meta.get("reason") if meta.get("fallback") else meta.get("field")

            out_sha = None
            if out_bytes is not None:
                sender.send(out_bytes)
                # Record AFTER forward so get_replay() only returns confirmed-sent frames
                replay_buf.record(raw)
                out_sha = hashlib.sha256(out_bytes).hexdigest()
                with state.lock:
                    state.stats["forwarded"] += 1
                    if action in ["tampered", "spoofed", "replayed", "jammed", "mutated"]:
                        state.stats["mutated"] += 1
            else:
                with state.lock:
                    state.stats["dropped"] += 1

            pkt_seq = extract_seq(raw)
            pkt_epoch = extract_epoch(raw) or 1
            if pkt_seq is not None:
                pending_actions.append({
                    "seq": pkt_seq,
                    "epoch": pkt_epoch,
                    "intended_label": label,
                    "action": action,
                })

            if len(pending_actions) >= 10 or (now - last_action_flush >= 0.1):
                flush_actions()

            if log_file:
                entry = {
                    "ts": now,
                    "in_sha256": in_sha,
                    "out_sha256": out_sha,
                    "action": action,
                    "intended_label": label,
                    "mode_at_time": cur_mode,
                    "field_changed": field_name,
                }
                log_file.write(json.dumps(entry) + "\n")
                log_file.flush()

    finally:
        flush_actions()
        if log_file:
            log_file.close()
        receiver.close()
        sender.close()


if __name__ == "__main__":
    main()
