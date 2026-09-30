"""Anti-replay protection using a sliding window bitmask and timestamp freshness validation."""

import time
from typing import Dict, Tuple, Optional, Callable
from securelink.core.types import Reason


class SenderReplayState:
    """Tracks sequence numbers for a single sender using a 64-packet bitmask sliding window."""

    def __init__(self, window_size: int = 64):
        self.window_size = window_size
        self.highest_seq: int = 0
        self.bitmap: int = 0
        self.initialized: bool = False

    def check_and_update(self, seq: int) -> Tuple[bool, Reason]:
        if not self.initialized:
            self.highest_seq = seq
            self.bitmap = 1  # mark seq as seen
            self.initialized = True
            return True, Reason.OK

        if seq > self.highest_seq:
            # Advance window
            diff = seq - self.highest_seq
            if diff >= self.window_size:
                self.bitmap = 1
            else:
                mask = (1 << self.window_size) - 1
                self.bitmap = ((self.bitmap << diff) | 1) & mask
            self.highest_seq = seq
            return True, Reason.OK
        else:
            diff = self.highest_seq - seq
            if diff >= self.window_size:
                # Too old, outside sliding window
                return False, Reason.SEQ_OUT_OF_WINDOW
            # Inside window, check bit
            mask = 1 << diff
            if (self.bitmap & mask) != 0:
                # Already received
                return False, Reason.DUPLICATE_SEQ
            # Valid out-of-order within window
            self.bitmap |= mask
            return True, Reason.OK


class _SenderStateDict(dict):
    """Dictionary supporting lookup by (sender_id, session_id, epoch), (sender_id, epoch), or sender_id."""

    def __getitem__(self, key):
        if isinstance(key, int):
            for k, state in reversed(list(self.items())):
                if isinstance(k, tuple) and k[0] == key:
                    return state
            return super().__getitem__((key, 0, 1))
        elif isinstance(key, tuple) and len(key) == 2:
            sid, ep = key
            for k, state in reversed(list(self.items())):
                if isinstance(k, tuple) and len(k) == 3 and k[0] == sid and k[2] == ep:
                    return state
            return super().__getitem__((sid, 0, ep))
        return super().__getitem__(key)


class ReplayGuard:
    """Multi-sender, multi-session, multi-epoch replay guard with optional timestamp freshness checks."""

    def __init__(
        self,
        window_size: int = 64,
        max_clock_skew: float = 30.0,
        enforce_timestamp: bool = True,
        clock: Optional[Callable[[], float]] = None,
    ):
        self.window_size = window_size
        self.max_clock_skew = max_clock_skew
        self.enforce_timestamp = enforce_timestamp
        self.clock = clock or time.time
        self.senders: Dict[Tuple[int, int, int], SenderReplayState] = _SenderStateDict()

    def reset(self):
        self.senders.clear()

    def check_and_update(
        self,
        sender_id: int,
        seq: int,
        timestamp: float,
        current_time: float = None,
        epoch: int = 1,
        session_id: int = 0,
    ) -> Tuple[bool, Reason]:
        """Validate sequence freshness in the (sender_id, session_id, epoch) window and timestamp window."""
        # 1. Timestamp freshness check (if enabled)
        if self.enforce_timestamp:
            now = current_time if current_time is not None else self.clock()
            if not (abs(now - timestamp) <= self.max_clock_skew):
                return False, Reason.STALE_TIMESTAMP

        # 2. Sequence sliding window check partitioned by (sender_id, session_id, epoch)
        key = (sender_id, session_id, epoch)
        if key not in self.senders:
            self.senders[key] = SenderReplayState(self.window_size)

        state = self.senders[key]
        return state.check_and_update(seq)


