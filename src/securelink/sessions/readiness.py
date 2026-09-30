"""Process readiness helpers for SecureLink session synchronization."""

from pathlib import Path
import time
from typing import Sequence, Union


def ready_dir(s_dir: Union[str, Path]) -> Path:
    """Return and create the session readiness directory."""
    r = Path(s_dir) / "ready"
    r.mkdir(parents=True, exist_ok=True)
    return r


def mark_ready(path: Union[str, Path]) -> None:
    """Create a readiness marker file indicating a process socket is bound."""
    p = Path(path)
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_bytes(b"ready\n")


def wait_for_ready(paths: Sequence[Union[str, Path]], timeout: float = 8.0) -> bool:
    """Wait for all readiness marker files to exist within the timeout."""
    if not paths:
        return True
    path_objs = [Path(p) for p in paths]
    deadline = time.monotonic() + max(0.0, float(timeout))
    while time.monotonic() < deadline:
        if all(p.exists() for p in path_objs):
            return True
        time.sleep(0.01)
    return all(p.exists() for p in path_objs)
