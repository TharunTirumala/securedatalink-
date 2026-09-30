"""Abstract base class for channel attackers."""

from abc import ABC, abstractmethod
from typing import Tuple, Optional


class BaseAttacker(ABC):
    """Base class for all simulated channel attackers.

    CRITICAL RULE: Attackers must never import keystore, private keys, or RX pipeline.
    """

    @abstractmethod
    def apply(self, wire_bytes: bytes) -> Tuple[Optional[bytes], str]:
        """Mutate or replace wire_bytes and return (altered_bytes, truth_label)."""
        pass
