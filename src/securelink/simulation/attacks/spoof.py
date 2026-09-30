"""Spoof attacker: crafts forged packets or tampers with sender identity."""

import os
import random
import struct
from typing import Tuple, Optional
from securelink.simulation.attacks.base import BaseAttacker


class SpoofAttacker(BaseAttacker):
    def __init__(self, rng: Optional[random.Random] = None):
        self.rng = rng or random.Random()

    def apply(self, wire_bytes: bytes) -> Tuple[Optional[bytes], str]:
        # Mutate the sender_id in header (offset 1:3) to an unauthorized sender (e.g. 65530+)
        if len(wire_bytes) >= 20:
            mutated = bytearray(wire_bytes)
            fake_sender_id = self.rng.randint(60000, 65535)
            fake_sender_bytes = struct.pack(">H", fake_sender_id)
            mutated[1:3] = fake_sender_bytes
            return bytes(mutated), "SPOOFED"

        # Otherwise forge random packet
        forged = self.rng.randbytes(120)
        return forged, "SPOOFED"
