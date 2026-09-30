"""Shared utilities for SecureLink CLI transport processes."""

import sys
import json
import signal
import logging
import threading
import urllib.request
import urllib.error
from typing import Tuple, Optional, Dict, Any, Union

logger = logging.getLogger("securelink.cli")


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


def post_json_background(url: str, data: Dict[str, Any], token: Optional[str] = None):
    """Post JSON payload in background thread; silent drop on failure."""
    def _worker():
        try:
            body = json.dumps(data).encode("utf-8")
            req = urllib.request.Request(
                url,
                data=body,
                headers={"Content-Type": "application/json"},
                method="POST",
            )
            if token:
                req.add_header("X-SecureLink-Token", token)
            with urllib.request.urlopen(req, timeout=1.5):
                pass
        except Exception:
            pass  # Silent drop if dashboard is down

    t = threading.Thread(target=_worker, daemon=True)
    t.start()


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
