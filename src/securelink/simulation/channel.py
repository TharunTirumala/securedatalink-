"""Simulated adversarial RF channel multiplexing electronic warfare attacks."""

import random
from typing import Tuple, Optional
from securelink.core.config import AttackConfig
from securelink.simulation.attacks.tamper import TamperAttacker
from securelink.simulation.attacks.replay import ReplayAttacker
from securelink.simulation.attacks.spoof import SpoofAttacker
from securelink.simulation.attacks.drop import DropAttacker


class AdversarialChannel:
    """Simulates an untrusted physical transmission medium with electronic warfare threats."""

    def __init__(self, attack_config: Optional[AttackConfig] = None, seed: Any = 42):
        self.config = attack_config or AttackConfig()
        self.seed = seed
        self.rng = random.Random(f"{seed}:channel")

        self.tamper_attacker = TamperAttacker(rng=random.Random(f"{seed}:tamper"))
        self.replay_attacker = ReplayAttacker(rng=random.Random(f"{seed}:replay"))
        self.spoof_attacker = SpoofAttacker(rng=random.Random(f"{seed}:spoof"))
        self.drop_attacker = DropAttacker(rng=random.Random(f"{seed}:drop"))

    def transmit(self, wire_bytes: bytes) -> Tuple[Optional[bytes], str]:
        """Process packet through channel and return (output_bytes, truth_label)."""
        roll = self.rng.random()
        p_drop = self.config.drop_prob
        p_tamper = self.config.tamper_prob
        p_replay = self.config.replay_prob
        p_spoof = self.config.spoof_prob

        cum_drop = p_drop
        cum_tamper = cum_drop + p_tamper
        cum_replay = cum_tamper + p_replay
        cum_spoof = cum_replay + p_spoof

        if roll < cum_drop:
            return self.drop_attacker.apply(wire_bytes)
        elif roll < cum_tamper:
            return self.tamper_attacker.apply(wire_bytes)
        elif roll < cum_replay:
            if self.replay_attacker.has_history():
                return self.replay_attacker.apply(wire_bytes)
            else:
                # If no history exists yet to replay, deliver clean and record
                self.replay_attacker.record_frame(wire_bytes)
                return wire_bytes, "AUTHENTIC"
        elif roll < cum_spoof:
            return self.spoof_attacker.apply(wire_bytes)
        else:
            self.replay_attacker.record_frame(wire_bytes)
            return wire_bytes, "AUTHENTIC"
