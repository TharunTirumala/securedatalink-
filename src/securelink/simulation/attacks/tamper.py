"""Tamper attacker: corrupts payload, tag, or header bytes on the wire."""

import random
from typing import Tuple, Optional
from securelink.simulation.attacks.base import BaseAttacker


class TamperAttacker(BaseAttacker):
    def __init__(self, rng: Optional[random.Random] = None):
        self.rng = rng or random.Random()

    def apply(self, wire_bytes: bytes) -> Tuple[Optional[bytes], str]:
        if len(wire_bytes) == 0:
            return wire_bytes, "TAMPERED"

        mutated = bytearray(wire_bytes)
        # Flip bits in a random position (either header, body, or tag)
        flip_pos = self.rng.randint(0, len(mutated) - 1)
        mutated[flip_pos] ^= self.rng.choice([0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0xFF])
        return bytes(mutated), "TAMPERED"
