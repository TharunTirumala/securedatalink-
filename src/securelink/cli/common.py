"""Shared utilities for SecureLink CLI transport processes."""

import atexit
import http.client
import json
import logging
import queue
import signal
import socket
import sys
import threading
import time
import urllib.parse
from typing import Tuple, Optional, Dict, Any, Union

logger = logging.getLogger("securelink.cli")

_post_queue: "queue.Queue[Tuple[str, Dict[str, Any], Optional[str]]]" = queue.Queue(maxsize=1000)
_worker_lock = threading.Lock()
_worker_thread: Optional[threading.Thread] = None


def _get_connection(
    connections: Dict[str, Union[http.client.HTTPConnection, http.client.HTTPSConnection]],
    scheme: str,
    netloc: str,
) -> Union[http.client.HTTPConnection, http.client.HTTPSConnection]:
    conn = connections.get(netloc)
    if conn is None:
        if scheme == "https":
            conn = http.client.HTTPSConnection(netloc, timeout=2.0)
        else:
            conn = http.client.HTTPConnection(netloc, timeout=2.0)
        conn.connect()
        if conn.sock:
            try:
                conn.sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
            except Exception:
                pass
        connections[netloc] = conn
    return conn


def _send_post(conn: Union[http.client.HTTPConnection, http.client.HTTPSConnection], path: str, body: bytes, token: Optional[str]):
    headers = {"Content-Type": "application/json"}
    if token:
        headers["X-SecureLink-Token"] = token
    conn.request("POST", path, body=body, headers=headers)
    resp = conn.getresponse()
    resp.read()


def _worker_loop():
    connections: Dict[str, Union[http.client.HTTPConnection, http.client.HTTPSConnection]] = {}
    while True:
        item = _post_queue.get()
        try:
            url, data, token = item
            parts = urllib.parse.urlsplit(url)
            scheme = parts.scheme or "http"
            netloc = parts.netloc
            path = parts.path or "/"
            if parts.query:
                path = f"{path}?{parts.query}"
            body = json.dumps(data).encode("utf-8")

            try:
                conn = _get_connection(connections, scheme, netloc)
                _send_post(conn, path, body, token)
            except Exception:
                old = connections.pop(netloc, None)
                if old:
                    try:
                        old.close()
                    except Exception:
                        pass
                try:
                    conn = _get_connection(connections, scheme, netloc)
                    _send_post(conn, path, body, token)
                except Exception:
                    failed = connections.pop(netloc, None)
                    if failed:
                        try:
                            failed.close()
                        except Exception:
                            pass
        finally:
            _post_queue.task_done()


def _ensure_worker_started():
    global _worker_thread
    if _worker_thread is None or not _worker_thread.is_alive():
        with _worker_lock:
            if _worker_thread is None or not _worker_thread.is_alive():
                t = threading.Thread(target=_worker_loop, daemon=True)
                t.start()
                _worker_thread = t


def flush_posts(timeout: float = 2.0):
    """Wait bounded until pending background posts are processed."""
    t0 = time.monotonic()
    while _post_queue.unfinished_tasks > 0:
        if time.monotonic() - t0 >= timeout:
            break
        time.sleep(0.01)


atexit.register(flush_posts)


def post_json_background(url: str, data: Dict[str, Any], token: Optional[str] = None):
    """Post JSON payload in background thread; silent drop on failure."""
    _ensure_worker_started()
    item = (url, data, token)
    try:
        _post_queue.put_nowait(item)
    except queue.Full:
        try:
            _post_queue.get_nowait()
            _post_queue.task_done()
        except queue.Empty:
            pass
        try:
            _post_queue.put_nowait(item)
        except queue.Full:
            pass


def parse_host_port(val: str, default_host: str = "127.0.0.1", default_port: int = 9999) -> Tuple[str, int]:
    """Parse 'HOST:PORT', ':PORT', or 'PORT' into (host, port)."""
    s = val.strip()
    if not s:
        return default_host, default_port
    if ":" in s:
        parts = s.split(":", 1)
        h = parts[0].strip() or default_host
        p = int(parts[1].strip())
        return h, p
    if s.isdigit():
        return default_host, int(s)
    return s, default_port


def setup_stdio():
    """Reconfigure stdout/stderr to UTF-8 with replacement so non-ASCII never crashes on Windows."""
    try:
        if hasattr(sys.stdout, "reconfigure"):
            sys.stdout.reconfigure(encoding="utf-8", errors="replace")
        if hasattr(sys.stderr, "reconfigure"):
            sys.stderr.reconfigure(encoding="utf-8", errors="replace")
    except Exception:
        pass  # If reconfigure is unavailable (e.g. not a text buffer), silently skip


def session_id_to_uint32(session_id: Optional[Union[str, int]]) -> int:
    """Convert string or int session ID to unsigned 32-bit integer, never returning 0."""
    if session_id is None:
        import secrets
        return secrets.randbelow(0xFFFFFFFF) + 1
    if isinstance(session_id, int):
        v = session_id & 0xFFFFFFFF
        return v if v else 1
    # Hash string to 32-bit uint; mask and ensure non-zero
    import hashlib
    h = hashlib.sha256(session_id.encode("utf-8")).digest()
    v = int.from_bytes(h[:4], "big") & 0xFFFFFFFF
    return v if v else 1


class GracefulExit:
    """Catches SIGINT and SIGTERM to allow clean shutdown of socket loops."""

    def __init__(self):
        self.stop_requested = False
        signal.signal(signal.SIGINT, self._handler)
        signal.signal(signal.SIGTERM, self._handler)

    @property
    def stop(self) -> bool:
        return self.stop_requested

    def trigger(self):
        self.stop_requested = True

    def _handler(self, signum, frame):
        self.stop_requested = True
