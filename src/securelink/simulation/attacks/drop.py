import random
from typing import Tuple, Optional
from securelink.simulation.attacks.base import BaseAttacker


class DropAttacker(BaseAttacker):
    def __init__(self, rng: Optional[random.Random] = None):
        self.rng = rng or random.Random()

    def apply(self, wire_bytes: bytes) -> Tuple[Optional[bytes], str]:
        """Simulate packet loss by returning None."""
        return None, "DROPPED"
