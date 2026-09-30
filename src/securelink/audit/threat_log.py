"""Audit threat logger writing non-authentic security events to structured JSONL."""

import json
import threading
from collections import deque
from datetime import datetime, timezone
from pathlib import Path
from typing import List, Dict, Any
from securelink.core.types import Event, Verdict


class ThreatLogger:
    """Thread-safe append-only threat incident logger with operator ack support."""

    def __init__(self, log_path: str = "logs/threat_log.jsonl", operator_state: Any = None):
        self.log_path = Path(log_path)
        self.log_path.parent.mkdir(parents=True, exist_ok=True)
        self.operator_state = operator_state
        self._lock = threading.Lock()

    def log_event(self, event: Event):
        """Write event to JSONL only if it represents a threat or rejection."""
        if event.verdict == Verdict.AUTHENTIC.value:
            return

        if not event.incident_id:
            event.incident_id = f"inc-{event.run_id or '0'}-{event.seq}"

        entry = {
            "incident_id": event.incident_id,
            "timestamp": event.ts,
            "iso_time": datetime.fromtimestamp(event.ts, tz=timezone.utc).isoformat(),
            "run_id": event.run_id,
            "seed": event.seed,
            "epoch": event.epoch,
            "seq": event.seq,
            "verdict": event.verdict,
            "reason": event.reason,
            "truth": event.truth,
            "sender_id": event.sender_id,
            "latency_us": event.latency_us,
        }

        with self._lock:
            with open(self.log_path, "a", encoding="utf-8") as f:
                f.write(json.dumps(entry) + "\n")

    def get_latest_incidents(self, limit: int = 50) -> List[Dict[str, Any]]:
        """Retrieve recent incident records using fixed-size deque with ack state."""
        with self._lock:
            if not self.log_path.exists():
                return []

            q: deque[Dict[str, Any]] = deque(maxlen=limit)
            try:
                with open(self.log_path, "r", encoding="utf-8") as f:
                    for line in f:
                        line = line.strip()
                        if line:
                            q.append(json.loads(line))
            except Exception:
                return []

            results = []
            for item in reversed(q):
                inc_id = item.get("incident_id")
                if inc_id and self.operator_state:
                    item["acknowledged"] = self.operator_state.is_incident_acked(inc_id)
                else:
                    item["acknowledged"] = item.get("acknowledged", False)
                results.append(item)
            return results

    def clear(self):
        """Truncate the log file."""
        with self._lock:
            if self.log_path.exists():
                self.log_path.write_text("", encoding="utf-8")

