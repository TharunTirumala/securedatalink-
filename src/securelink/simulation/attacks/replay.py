"""Replay attacker: intercepts legitimate frames and injects stale/duplicate packets."""

import random
from typing import Tuple, Optional, List
from securelink.simulation.attacks.base import BaseAttacker


class ReplayAttacker(BaseAttacker):
    def __init__(self, history_size: int = 64, rng: Optional[random.Random] = None):
        self.history_size = history_size
        self.history: List[bytes] = []
        self.rng = rng or random.Random()

    def has_history(self) -> bool:
        return len(self.history) > 0

    def record_frame(self, wire_bytes: bytes):
        """Passively caches legitimate frames already seen on the wire."""
        self.history.append(wire_bytes)
        if len(self.history) > self.history_size:
            self.history.pop(0)

    def apply(self, wire_bytes: bytes) -> Tuple[Optional[bytes], str]:
        if not self.history:
            return wire_bytes, "AUTHENTIC"


        # Select a strictly historical frame
        replayed_frame = self.rng.choice(self.history)
        return replayed_frame, "REPLAYED"
