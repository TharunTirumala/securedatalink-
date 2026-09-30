"""Base abstraction for telemetry sources."""

from abc import ABC, abstractmethod
from typing import Iterator
from securelink.core.types import TelemetryData


class BaseTelemetrySource(ABC):
    """Abstract interface for sensor and telemetry generators."""

    @abstractmethod
    def generate_packet(self, seq: int) -> TelemetryData:
        """Generate a single telemetry packet with the given sequence number."""
        pass

    @abstractmethod
    def generate_stream(self, count: int) -> Iterator[TelemetryData]:
        """Stream count telemetry packets."""
        pass
