"""Mock event generator for standalone frontend testing."""

import asyncio
import random
import time
from typing import AsyncIterator, List, Dict, Any
from securelink.core.types import Event, Verdict, Reason


async def generate_mock_events(
    rate_pps: int = 20,
    tamper_prob: float = 0.10,
    replay_prob: float = 0.10,
    spoof_prob: float = 0.05,
    drop_prob: float = 0.05,
) -> AsyncIterator[Dict[str, Any]]:
    """Yield mock events simulating live tactical data transmission."""
    seq = 1
    rng = random.Random(42)

    while True:
        roll = rng.random()
        now = time.time()
        latency_us = round(rng.uniform(250.0, 1200.0), 1)

        if roll < drop_prob:
            verdict = Verdict.DROPPED.value
            reason = Reason.PACKET_DROPPED.value
            truth = "DROPPED"
        elif roll < drop_prob + tamper_prob:
            verdict = Verdict.TAMPERED.value
            reason = Reason.GCM_TAG_MISMATCH.value
            truth = "TAMPERED"
        elif roll < drop_prob + tamper_prob + replay_prob:
            verdict = Verdict.REPLAYED.value
            reason = Reason.DUPLICATE_SEQ.value
            truth = "REPLAYED"
        elif roll < drop_prob + tamper_prob + replay_prob + spoof_prob:
            verdict = Verdict.SPOOFED.value
            reason = Reason.UNKNOWN_SENDER.value
            truth = "SPOOFED"
        else:
            verdict = Verdict.AUTHENTIC.value
            reason = Reason.OK.value
            truth = "AUTHENTIC"

        epoch = (seq - 1) // 100 + 1
        event = Event(
            seq=seq,
            verdict=verdict,
            reason=reason,
            truth=truth,
            latency_us=latency_us,
            sender_id=1,
            ts=round(now, 2),
            epoch=epoch,
            incident_id=f"inc-mock-{seq}",
        )
        yield event.to_dict()

        seq += 1
        await asyncio.sleep(1.0 / max(1, rate_pps))
