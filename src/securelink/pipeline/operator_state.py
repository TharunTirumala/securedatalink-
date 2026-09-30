"""Thread-safe operator state managing blocked senders, incident acks, and manual re-key requests."""

import time
import secrets
import threading
from collections import deque
from typing import Set, Dict, Any, Optional, List


class OperatorState:
    def __init__(self):
        self._lock = threading.Lock()
        self.blocked_senders: Set[int] = set()
        self.acknowledged_incidents: Set[str] = set()
        self.pending_rekey: bool = False
        self.total_rekeys: int = 0
        self.current_epoch: int = 1
        self.rekey_history: deque = deque(maxlen=200)

    def block_sender(self, sender_id: int):
        with self._lock:
            self.blocked_senders.add(sender_id)

    def unblock_sender(self, sender_id: int):
        with self._lock:
            self.blocked_senders.discard(sender_id)

    def is_blocked(self, sender_id: int) -> bool:
        with self._lock:
            return sender_id in self.blocked_senders

    def request_rekey(self):
        with self._lock:
            self.pending_rekey = True

    def consume_rekey(self) -> bool:
        with self._lock:
            if self.pending_rekey:
                self.pending_rekey = False
                self.total_rekeys += 1
                return True
            return False

    def record_rekey(
        self,
        from_epoch: int,
        to_epoch: int,
        reason: str = "auto",
        at_packet: int = 0,
        ts: Optional[float] = None,
    ) -> str:
        """Record a re-key transition in the audit history."""
        r_id = f"rek_{secrets.token_hex(4)}"
        entry = {
            "rekey_id": r_id,
            "from_epoch": from_epoch,
            "to_epoch": to_epoch,
            "reason": reason,
            "at_packet": at_packet,
            "ts": ts if ts is not None else time.time(),
        }
        with self._lock:
            self.rekey_history.append(entry)
            self.current_epoch = max(self.current_epoch, to_epoch)
        return r_id

    def get_rekey_history(self, limit: int = 50) -> List[Dict[str, Any]]:
        with self._lock:
            history = list(self.rekey_history)
        history.reverse()
        return history[:limit]

    def ack_incident(self, incident_id: str):
        with self._lock:
            self.acknowledged_incidents.add(incident_id)

    def is_incident_acked(self, incident_id: str) -> bool:
        with self._lock:
            return incident_id in self.acknowledged_incidents

    def update_epoch(self, epoch: int):
        with self._lock:
            self.current_epoch = max(self.current_epoch, epoch)

    def to_dict(self, is_running: bool = False, run_id: Optional[str] = None) -> Dict[str, Any]:
        with self._lock:
            return {
                "running": is_running,
                "epoch": self.current_epoch,
                "rekeys": self.total_rekeys,
                "blocked_senders": sorted(list(self.blocked_senders)),
                "run_id": run_id,
            }

