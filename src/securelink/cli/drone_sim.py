"""Simulated UAV Telemetry Generator CLI (MAVLink 2 over UDP)."""

import argparse
import json
import secrets
import sys
import time
from typing import Tuple

from securelink.cli.common import (
    GracefulExit,
    parse_host_port,
    post_json_background,
    setup_stdio,
)
from securelink.simulation.drone.mini_drone import MiniDroneSimulator
from securelink.transport.udp import UdpSender


def parse_home(val: str) -> Tuple[float, float]:
    """Parse 'LAT,LON' into (lat, lon) floats."""
    parts = val.split(",")
    if len(parts) != 2:
        return 37.7749, -122.4194
    return float(parts[0].strip()), float(parts[1].strip())


def run_drone_sim(args):
    setup_stdio()
    exit_handler = GracefulExit()
    send_host, send_port = parse_host_port(args.send, default_host="127.0.0.1", default_port=14550)
    sender = UdpSender(send_host, send_port)

    seed = args.seed if args.seed is not None else secrets.randbelow(1_000_000)
    home_coord = parse_home(args.home)

    print(f"flight seed {seed} (simulated UAV telemetry) -- route {args.route} @ {args.speed} m/s")
    print(f"Streaming MAVLink 2 datagrams to {send_host}:{send_port}...")

    sim = MiniDroneSimulator(
        route_pattern=args.route,
        home=home_coord,
        speed=args.speed,
        seed=seed,
    )

    t0 = time.monotonic()
    total_sent = 0
    last_log_t = 0.0
    last_telem_post = 0.0
    pending_telem = []
    log_f = open(args.log, "w", encoding="utf-8") if args.log else None

    try:
        while not exit_handler.stop_requested:
            elapsed = time.monotonic() - t0
            if args.duration and elapsed >= args.duration:
                break
            if args.count and total_sent >= args.count:
                break

            packets = sim.step(elapsed)
            now_wall = time.time()
            for raw_bytes, st in packets:
                sender.send(raw_bytes)
                total_sent += 1
                record = {
                    "ts": now_wall,
                    "msg_type": st.get("msg_type", "GLOBAL_POSITION_INT"),
                    "msg_seq": total_sent,
                    "time_boot_ms": st.get("time_boot_ms"),
                    "lat": st["lat"],
                    "lon": st["lon"],
                    "alt": st["alt_m"],
                    "hdg": st["heading"],
                    "bat": st["battery_pct"],
                }
                pending_telem.append(record)
                if log_f:
                    log_f.write(json.dumps(record) + "\n")
                    log_f.flush()

                if args.count and total_sent >= args.count:
                    break

            if pending_telem and (now_wall - last_telem_post >= 0.2):
                if args.dashboard and args.dashboard.lower() != "none":
                    batch = pending_telem[:200]
                    pending_telem = pending_telem[len(batch):]
                    post_json_background(
                        f"{args.dashboard}/api/ingest/telemetry",
                        {"session_id": args.session_id or "default", "samples": batch},
                    )
                else:
                    pending_telem.clear()
                last_telem_post = now_wall

            if elapsed - last_log_t >= 2.0 and packets:
                last_log_t = elapsed
                st = packets[-1][1]
                print(f"DRONE [{elapsed:.1f}s]: lat {st['lat']:.5f} lon {st['lon']:.5f} alt {st['alt_m']:.1f}m speed {st['speed']:.1f}m/s bat {st['battery_pct']:.0f}% (pkts {total_sent})")

            # Rate control
            sleep_step = 1.0 / (args.rate_hz or 50.0)
            time.sleep(min(0.05, max(0.005, sleep_step)))
    finally:
        if log_f:
            log_f.close()
        sender.close()
        duration = time.monotonic() - t0
        print(f"Drone sim finished: {total_sent} MAVLink packets sent in {duration:.2f}s (seed {seed})")


def main():
    setup_stdio()
    parser = argparse.ArgumentParser(description="Simulated UAV MAVLink 2 Telemetry Generator")
    parser.add_argument("--send", default="127.0.0.1:14550", help="Destination HOST:PORT for TX gateway")
    parser.add_argument("--route", choices=["random", "circle", "square", "survey"], default="random")
    parser.add_argument("--home", default="37.7749,-122.4194", help="Home position 'LAT,LON'")
    parser.add_argument("--speed", type=float, default=12.0, help="Cruise speed in m/s")
    parser.add_argument("--seed", type=int, default=None, help="Flight random seed")
    parser.add_argument("--duration", type=float, default=None, help="Flight duration in seconds")
    parser.add_argument("--count", type=int, default=None, help="Max packet count")
    parser.add_argument("--rate-hz", type=float, default=50.0, help="Stepping rate")
    parser.add_argument("--log", default=None, help="JSONL log path for drone truth")
    parser.add_argument("--dashboard", default="http://127.0.0.1:8000", help="Dashboard URL")
    parser.add_argument("--session-id", default=None, help="Session UUID or identifier")
    parser.add_argument("--token", default=None, help="API token for dashboard ingest")
    args = parser.parse_args()
    run_drone_sim(args)


if __name__ == "__main__":
    main()
