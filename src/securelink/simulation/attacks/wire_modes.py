"""Generic wire-level adversarial mutations operating purely on raw bytes."""

import os
import random
from typing import Optional, Tuple, List


def apply_wire_pass(raw_bytes: bytes) -> Tuple[bytes, str]:
    """Pass bytes through unaltered."""
    return raw_bytes, "AUTHENTIC"


def apply_wire_tamper(raw_bytes: bytes, seed: Optional[int] = None) -> Tuple[bytes, str]:
    """Flip 1 to 3 bytes in the frame, guaranteeing the output differs from input.

    XOR values are chosen so that at least one byte changes (no XOR cancellation).
    """
    if not raw_bytes:
        return raw_bytes, "AUTHENTIC"
    rng = random.Random(seed) if seed is not None else random
    arr = bytearray(raw_bytes)
    flips = rng.randint(1, min(3, len(arr)))
    # Pick indices without replacement to avoid cancellation at the same byte
    positions = rng.sample(range(len(arr)), min(flips, len(arr)))
    for idx in positions:
        # XOR value is non-zero; no multi-flip cancellation because each index is unique
        arr[idx] ^= rng.randint(1, 255)
    result = bytes(arr)
    # Safety check: guarantee at least 1 byte changed (XOR with 1 at first position)
    if result == raw_bytes:
        arr2 = bytearray(result)
        arr2[0] ^= 1
        result = bytes(arr2)
    return result, "TAMPERED"


def apply_wire_drop(raw_bytes: bytes) -> Tuple[None, str]:
    """Simulate packet loss by suppressing the datagram."""
    return None, "DROPPED"


def apply_wire_spoof(raw_bytes: bytes, seed: Optional[int] = None) -> Tuple[bytes, str]:
    """Inject synthesized or garbage bytes mimicking a spoofed frame."""
    rng = random.Random(seed) if seed is not None else random
    length = len(raw_bytes) if raw_bytes else 120
    # Generate random bytes of similar length
    spoofed = bytes(rng.getrandbits(8) for _ in range(max(30, length)))
    return spoofed, "SPOOFED"


class WireReplayBuffer:
    """Maintains a bounded window of captured datagrams for delayed re-injection.

    IMPORTANT: Call record() ONLY AFTER a frame has been forwarded to the receiver,
    so that the buffer contains only frames that RX has already accepted (or could have).
    This ensures replay labels are accurate: if a replayed frame matches one the RX has
    seen, the RX's replay guard will correctly flag it as REPLAYED.
    """

    def __init__(self, max_size: int = 100):
        self.max_size = max_size
        self.buffer: List[bytes] = []

    def record(self, raw_bytes: bytes):
        if raw_bytes:
            self.buffer.append(raw_bytes)
            if len(self.buffer) > self.max_size:
                self.buffer.pop(0)

    def get_replay(self, seed: Optional[int] = None) -> Optional[bytes]:
        if not self.buffer:
            return None
        rng = random.Random(seed) if seed is not None else random
        return rng.choice(self.buffer)


class WireJammer:
    """Simulates RF jamming: burst corruption, delays, and bounded reordering.

    Labels:
    - "corrupt" → "TAMPERED": bytes were modified, RX GCM/sig will fail
    - "delay" released → "AUTHENTIC": frame was only delayed, not modified or replayed
    - "delay" still queued → "DROPPED": frame not yet forwarded
    - "pass" → "AUTHENTIC": forwarded as-is
    """

    def __init__(self, burst_size: int = 3):
        self.burst_size = burst_size
        self.reorder_queue: List[bytes] = []

    def handle(self, raw_bytes: bytes, seed: Optional[int] = None) -> Tuple[Optional[bytes], str]:
        rng = random.Random(seed) if seed is not None else random
        action = rng.choice(["corrupt", "delay", "pass"])
        if action == "corrupt":
            tampered, _ = apply_wire_tamper(raw_bytes, seed=seed)
            return tampered, "TAMPERED"
        elif action == "delay":
            self.reorder_queue.append(raw_bytes)
            if len(self.reorder_queue) >= self.burst_size:
                released = self.reorder_queue.pop(0)
                # The released frame is unmodified and delivered once; not a replay
                return released, "AUTHENTIC"
            return None, "DROPPED"
        return raw_bytes, "AUTHENTIC"
