"""Process manager orchestrating multi-node UDP pipeline execution and reconciliation."""

import json
import os
import secrets
import subprocess
import sys
import threading
import time
import urllib.request
from pathlib import Path
from typing import Any, Dict, List, Optional

from securelink.sessions.models import SessionConfig, SessionState
from securelink.sessions.reconcile import reconcile_session
from securelink.sessions.store import SessionStore
from securelink.sessions.telemetry_reconcile import reconcile_telemetry
from securelink.sessions.proc_cmds import build_process_commands


class SessionManager:
    """Manages process lifecycles for multi-node SecureLink runs."""

    def __init__(self, store: Optional[SessionStore] = None):
        self.store = store or SessionStore()
        self.active_session_id: Optional[str] = None
        self.active_token: Optional[str] = None
        self.processes: Dict[str, subprocess.Popen] = {}
        self.log_handles: Dict[str, Any] = {}
        self.state_name: str = "idle"
        self.lock = threading.Lock()

    def _validate_ports(self, config: SessionConfig):
        ports = [config.tx_port, config.attacker_port, config.attacker_control_port, config.rx_port, config.c2_port]
        for p in ports:
            if not (1024 <= p <= 65535):
                raise ValueError(f"Port {p} outside valid range 1024..65535")
        if len(ports) != len(set(ports)):
            raise ValueError(f"Port collision detected in config: {ports}")

    def _check_ports_free(self, config: SessionConfig):
        """Try to bind each UDP port; log a warning if any is already in use."""
        import socket
        ports = [config.tx_port, config.attacker_port, config.rx_port, config.c2_port]
        for p in ports:
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            try:
                if sys.platform == "win32":
                    try:
                        s.setsockopt(socket.SOL_SOCKET, socket.SO_EXCLUSIVEADDRUSE, 1)
                    except (AttributeError, OSError):
                        pass
                s.bind(("127.0.0.1", p))
            except OSError as e:
                print(f"[SessionManager] WARNING: Port {p} may be in use: {e}")
            finally:
                s.close()

    def _kill_proc(self, proc: subprocess.Popen):
        if proc.poll() is not None:
            return
        try:
            if sys.platform == "win32":
                subprocess.run(["taskkill", "/F", "/T", "/PID", str(proc.pid)], capture_output=True)
            else:
                proc.terminate()
            proc.wait(timeout=1.0)
        except Exception:
            try:
                proc.kill()
            except Exception:
                pass

    def _read_tail(self, log_path: Path, n: int = 20) -> str:
        """Read last n lines from a log file for failure reporting."""
        try:
            lines = log_path.read_text(encoding="utf-8", errors="replace").splitlines()
            return "\n".join(lines[-n:]) if lines else "(empty)"
        except Exception:
            return "(unreadable)"

    def start_session(self, config: SessionConfig, restart: bool = False) -> SessionState:
        with self.lock:
            # Check if active processes are still alive
            if self.processes:
                alive = any(p.poll() is None for p in self.processes.values())
                if not alive:
                    for p in self.processes.values():
                        self._kill_proc(p)
                    self.processes.clear()
                    self.state_name = "idle"
                    self.active_session_id = None

            if self.state_name == "running" or self.active_session_id:
                if restart:
                    self._do_stop_locked(self.active_session_id or config.session_id, mark_status="stopped")
                    time.sleep(0.15)
                else:
                    raise RuntimeError(f"Session {self.active_session_id} is currently running")

            self._validate_ports(config)
            self._check_ports_free(config)

            s_dir = self.store.get_session_dir(config.session_id)
            self.store.save_config(config)

            token = secrets.token_hex(16)
            self.active_token = token
            self.active_session_id = config.session_id
            self.state_name = "running"

            env = os.environ.copy()
            env["SECURELINK_CONTROL_TOKEN"] = token
            env["SECURELINK_SESSION_TOKEN"] = token
            # Force UTF-8 I/O in all child processes so non-ASCII never crashes on Windows
            env["PYTHONIOENCODING"] = "utf-8"
            env["PYTHONUTF8"] = "1"
            env["PYTHONUNBUFFERED"] = "1"

            logs_dir = s_dir / "logs"
            logs_dir.mkdir(exist_ok=True)
            self.log_handles = {
                name: open(logs_dir / f"{name}.log", "w", encoding="utf-8")
                for name in ("c2", "rx", "attacker", "tx", "drone")
            }

            cmds = build_process_commands(config, s_dir, token)
            pids: Dict[str, int] = {}
            self.processes = {}

            try:
                for name in ("c2", "rx", "attacker", "tx", "drone"):
                    if name in cmds:
                        p = subprocess.Popen(cmds[name], stdout=self.log_handles[name], stderr=subprocess.STDOUT, env=env)
                        self.processes[name] = p
                        pids[name] = p.pid
                        time.sleep(0.1)

                state = SessionState(session_id=config.session_id, status="running", start_time=time.time(), pids=pids)
                self.store.save_state(state)

                # Liveness check: verify all processes still alive after brief settle
                time.sleep(0.5)
                failed = [(n, p) for n, p in self.processes.items() if p.poll() is not None and p.returncode != 0]
                if failed:
                    name, proc = failed[0]
                    log_path = s_dir / "logs" / f"{name}.log"
                    tail = self._read_tail(log_path)
                    self._do_stop_locked(config.session_id, mark_status="failed")
                    raise RuntimeError(f"Process '{name}' exited with code {proc.returncode} immediately after start.\nLast log:\n{tail}")

                # Start background monitoring thread
                threading.Thread(target=self._watchdog, args=(config.session_id,), daemon=True).start()
                return state
            except Exception as e:
                self._do_stop_locked(config.session_id, mark_status="failed")
                raise e

    def _watchdog(self, session_id: str):
        """Monitor ALL child processes. If any exits non-zero while session is running, fail the session."""
        logs_dir = self.store.get_session_dir(session_id) / "logs"
        primary_proc = self.processes.get("drone") or self.processes.get("tx")
        fail_reason: Optional[str] = None

        try:
            while True:
                with self.lock:
                    if self.active_session_id != session_id:
                        return  # Session already stopped externally
                    procs = dict(self.processes)

                # Check if primary is done (natural end)
                if primary_proc and primary_proc.poll() is not None:
                    break

                # Check for unexpected early exits
                for name, proc in procs.items():
                    if proc is primary_proc:
                        continue
                    rc = proc.poll()
                    if rc is not None and rc != 0:
                        log_path = logs_dir / f"{name}.log"
                        tail = self._read_tail(log_path)
                        fail_reason = f"Process '{name}' exited with code {rc}.\nLast log:\n{tail}"
                        print(f"[SessionManager] WATCHDOG: {fail_reason}")
                        break

                if fail_reason:
                    break
                time.sleep(0.2)

            # Draining window
            time.sleep(0.6)
        except Exception as e:
            print(f"[SessionManager] Watchdog error: {e}")
        finally:
            with self.lock:
                if self.active_session_id == session_id:
                    status = "failed" if fail_reason else "finished"
                    self._do_stop_locked(session_id, mark_status=status)

    def stop_session(self, session_id: Optional[str] = None, mark_status: str = "stopped") -> Optional[SessionState]:
        with self.lock:
            sid = session_id or self.active_session_id
            if not sid and self.state_name == "idle" and not self.processes:
                return SessionState(session_id="none", status="idle")
            if session_id and self.active_session_id and self.active_session_id != session_id:
                return self.store.load_state(session_id)
            return self._do_stop_locked(sid or "none", mark_status=mark_status)

    def _do_stop_locked(self, session_id: str, mark_status: str = "stopped") -> Optional[SessionState]:
        self.state_name = "stopping"
        try:
            for name, proc in list(self.processes.items()):
                self._kill_proc(proc)
            self.processes.clear()

            for h in self.log_handles.values():
                try: h.close()
                except Exception: pass
            self.log_handles.clear()

            # Execute multi-hop reconciliation
            s_dir = self.store.get_session_dir(session_id)
            if s_dir.exists():
                try:
                    frame_report = reconcile_session(s_dir)
                    telem_report = reconcile_telemetry(s_dir)
                    combined_report = {
                        "session_id": session_id,
                        "frame_reconciliation": frame_report,
                        "telemetry_reconciliation": telem_report,
                    }
                    self.store.save_reconcile_report(session_id, combined_report)
                except Exception as e:
                    print(f"[SessionManager] Reconcile error: {e}")

            state = self.store.load_state(session_id) or SessionState(session_id=session_id)
            state.status = mark_status
            state.end_time = time.time()
            self.store.save_state(state)
            return state
        finally:
            self.active_session_id = None
            self.active_token = None
            self.state_name = "idle"

    def set_attack(self, session_id: str, mode: str, rate: float, params: Optional[Dict] = None) -> bool:
        cfg = self.store.load_config(session_id)
        if not cfg or not self.active_token:
            return False
        url = f"http://127.0.0.1:{cfg.attacker_control_port}/control"
        data = json.dumps({"mode": mode, "rate": rate, "params": params or {}}).encode()
        req = urllib.request.Request(
            url, data=data,
            headers={"Content-Type": "application/json", "Authorization": f"Bearer {self.active_token}"}
        )
        try:
            with urllib.request.urlopen(req, timeout=2.0) as resp:
                return resp.status == 200
        except Exception:
            return False
