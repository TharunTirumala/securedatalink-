"""Measure startup latency and process readiness for SecureLink transport."""

import argparse
import json
import os
import re
import socket
import subprocess
import sys
import time
import urllib.error
import urllib.request
from pathlib import Path


def find_free_port() -> int:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


def http_req(url: str, method: str = "GET", data: dict = None) -> dict:
    body = json.dumps(data).encode("utf-8") if data else None
    headers = {"Content-Type": "application/json"} if data else {}
    req = urllib.request.Request(url, data=body, headers=headers, method=method)
    with urllib.request.urlopen(req, timeout=5.0) as resp:
        return json.loads(resp.read().decode("utf-8"))


def main():
    parser = argparse.ArgumentParser(description="Measure startup latency")
    parser.add_argument("--base-url", default=None, help="Base URL of dashboard server")
    args = parser.parse_args()

    server_proc = None
    base_url = args.base_url
    if not base_url:
        port = find_free_port()
        base_url = f"http://127.0.0.1:{port}"
        env = os.environ.copy()
        env["PYTHONPATH"] = "src;."
        server_proc = subprocess.Popen(
            [sys.executable, "-m", "uvicorn", "dashboard.backend.server:app", "--host", "127.0.0.1", "--port", str(port)],
            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, env=env
        )
        for _ in range(60):
            try:
                http_req(f"{base_url}/api/transport/status")
                break
            except Exception:
                time.sleep(0.05)

    try:
        try:
            http_req(f"{base_url}/api/transport/stop", "POST", {})
        except Exception:
            pass
        time.sleep(0.1)

        sid = f"measure_{int(time.time())}"
        payload = {
            "session_id": sid, "source_type": "drone", "rate_pps": 20,
            "count": 100, "protect": True, "attack_mode": "pass", "restart": True,
            "dashboard_url": base_url,
        }

        t_click_epoch = time.time()
        t_click = time.perf_counter()
        resp = http_req(f"{base_url}/api/transport/start", "POST", payload)
        post_ret_ms = (time.perf_counter() - t_click) * 1000.0

        t_first_sent, t_first_telem, t_first_recv, t_finished = None, None, None, None
        deadline = time.perf_counter() + 20.0

        while time.perf_counter() < deadline:
            st = http_req(f"{base_url}/api/transport/status?live=1")
            now_ms = (time.perf_counter() - t_click) * 1000.0
            cnt = st.get("counters", {})
            s, r = cnt.get("sent", 0), cnt.get("received", 0)

            # Check drone telemetry from live field or ingest endpoint fallback
            drone_telem = st.get("live", {}).get("drone") if "live" in st else None
            if not drone_telem:
                try:
                    live_raw = http_req(f"{base_url}/api/ingest/live")
                    drone_telem = live_raw.get("drone") or live_raw.get("latest_drone_telemetry")
                except Exception:
                    pass

            if t_first_sent is None and s > 0:
                t_first_sent = now_ms
            if t_first_telem is None and drone_telem:
                t_first_telem = now_ms
            if t_first_recv is None and r > 0:
                t_first_recv = now_ms
            if s >= 100 and r >= 100:
                t_finished = now_ms
                break
            if st.get("state") in ("finished", "stopped", "idle") and (s > 0 or r > 0) and (now_ms > 2000):
                t_finished = now_ms
                break
            time.sleep(0.05)

        # Parse READY lines from session logs
        ready_events = {}
        s_dir = Path("data/sessions") / sid / "logs"
        if s_dir.exists():
            for lf in s_dir.glob("*.log"):
                try:
                    content = lf.read_text(encoding="utf-8", errors="replace")
                    for m in re.finditer(r"READY name=(\S+) t=([\d.]+) import_sec=([\d.]+)", content):
                        name, t_sec, imp_sec = m.group(1), float(m.group(2)), float(m.group(3))
                        ready_events[name] = {
                            "ready_ms": (t_sec - t_click_epoch) * 1000.0,
                            "import_sec": imp_sec
                        }
                except Exception:
                    pass

        print("\n" + "=" * 62)
        print("          SECURELINK STARTUP TIMING MEASUREMENT")
        print("=" * 62)
        print(f"Session ID                   : {sid}")
        print(f"POST /api/transport/start    : {post_ret_ms:7.1f} ms")
        print(f"First counters.sent > 0      : {(t_first_sent or -1):7.1f} ms")
        print(f"First drone telemetry non-null: {(t_first_telem or -1):7.1f} ms")
        print(f"First counters.received > 0  : {(t_first_recv or -1):7.1f} ms")
        print(f"Session finished             : {(t_finished or -1):7.1f} ms")
        print("-" * 62)
        print("CHILD PROCESS READY EVENTS (from process launch):")
        print(f"  {'Process':<12} {'Import Sec':<14} {'Ready (ms since click)':<22}")
        for name in ("c2", "rx", "attacker", "tx", "drone"):
            info = ready_events.get(name, {})
            imp = f"{info.get('import_sec', 0.0):.4f}s" if "import_sec" in info else "N/A"
            r_ms = f"{info.get('ready_ms', 0.0):.1f} ms" if "ready_ms" in info else "N/A"
            print(f"  {name:<12} {imp:<14} {r_ms:<22}")
        print("=" * 62 + "\n")

    finally:
        if server_proc:
            server_proc.terminate()
            server_proc.wait()


if __name__ == "__main__":
    main()
