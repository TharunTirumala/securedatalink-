"""Ground Control Station (C2) receiver and terminal telemetry display.

Listens for clean MAVLink datagrams from RX gateway, logs them, and displays flight status.
"""

import argparse
import json
import time
from typing import Optional

from securelink.cli.common import GracefulExit, parse_host_port, post_json_background, setup_stdio
from securelink.transport.udp import UdpReceiver

try:
    import pymavlink.dialects.v20.common as mavlink2
except ImportError:
    mavlink2 = None


def main():
    setup_stdio()
    parser = argparse.ArgumentParser(description="SecureLink C2 Display Receiver")
    parser.add_argument("--listen", required=True, help="HOST:PORT to receive MAVLink datagrams")
    parser.add_argument("--dashboard", default=None, help="Dashboard URL")
    parser.add_argument("--session-id", default=None, help="Session UUID")
    parser.add_argument("--log", default=None, help="JSONL log path for received telemetry")
    parser.add_argument("--quiet", action="store_true", help="Suppress terminal output")
    parser.add_argument("--token", default=None, help="API token for dashboard ingest")
    args = parser.parse_args()

    host, port = parse_host_port(args.listen)
    receiver = UdpReceiver(host, port)
    mav = mavlink2.MAVLink(None) if mavlink2 else None
    killer = GracefulExit()

    log_file = open(args.log, "a", encoding="utf-8") if args.log else None
    last_post = 0.0

    print(f"[C2 View] Listening on {host}:{port} for MAVLink telemetry...")

    try:
        while not killer.stop:
            item = receiver.recv(timeout=0.1)
            if item is None:
                continue

            raw, _ = item
            now = time.time()
            if not mav:
                continue

            try:
                msgs = mav.parse_buffer(raw)
            except Exception:
                continue

            if not msgs:
                continue

            msg = msgs[0]
            mtype = msg.get_type()
            data = msg.to_dict()
            seq = getattr(msg, "get_seq", lambda: 0)()
            tb_ms = data.get("time_boot_ms")
            if tb_ms is None and "time_usec" in data:
                tb_ms = int(data["time_usec"] / 1000)

            # Extract human-readable flight variables
            lat = data.get("lat", 0) / 1e7 if "lat" in data else None
            lon = data.get("lon", 0) / 1e7 if "lon" in data else None
            alt = data.get("relative_alt", data.get("alt", 0)) / 1000.0 if "alt" in data else None
            hdg = data.get("hdg", 0) / 100.0 if "hdg" in data else None
            bat = data.get("battery_remaining", None)

            telem_payload = {
                "ts": now,
                "msg_type": mtype,
                "msg_seq": seq,
                "time_boot_ms": tb_ms,
                "lat": lat,
                "lon": lon,
                "alt": alt,
                "hdg": hdg,
                "bat": bat,
            }

            if not args.quiet and mtype in ("GLOBAL_POSITION_INT", "GPS_RAW_INT", "SYS_STATUS"):
                parts = [f"[C2] {mtype}"]
                if lat is not None and lon is not None:
                    parts.append(f"POS: {lat:.6f},{lon:.6f}")
                if alt is not None:
                    parts.append(f"ALT: {alt:.1f}m")
                if bat is not None:
                    parts.append(f"BAT: {bat}%")
                print(" | ".join(parts))

            if log_file:
                log_file.write(json.dumps(telem_payload) + "\n")
                log_file.flush()

            if args.dashboard and (now - last_post >= 0.1):
                post_json_background(
                    f"{args.dashboard}/api/ingest/telemetry",
                    {"component": "c2", "session_id": args.session_id, "telemetry": telem_payload}
                )
                last_post = now

    finally:
        if log_file:
            log_file.close()
        receiver.close()
        print("[C2 View] Receiver closed.")


if __name__ == "__main__":
    main()
