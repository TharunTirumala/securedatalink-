"""Reproducible synthetic UAV telemetry generator using isolated PRNG state."""

import math
import random
from typing import Iterator, Union
from securelink.core.types import TelemetryData
from securelink.sources.base import BaseTelemetrySource


class SyntheticTelemetrySource(BaseTelemetrySource):
    """Generates synthetic UAV flight data with smooth trajectories and seed reproducibility."""

    def __init__(
        self,
        seed: Union[int, str, random.Random] = 42,
        sender_id: int = 1,
        base_lat: float = 17.3850,
        base_lon: float = 78.4867,
        base_alt: float = 500.0,
        base_time: float = 1700000000.0,
    ):
        self.seed = seed
        self.sender_id = sender_id
        self.base_lat = base_lat
        self.base_lon = base_lon
        self.base_alt = base_alt
        self.base_time = base_time

        self.reset()

    def reset(self):
        """Reset the internal generator to the initial seed state."""
        if isinstance(self.seed, random.Random):
            self.rng = self.seed
        else:
            self.rng = random.Random(self.seed)
        self.lat = self.base_lat
        self.lon = self.base_lon
        self.alt = self.base_alt
        self.heading = 45.0
        self.speed = 30.0
        self.battery = 100.0

    def generate_packet(self, seq: int) -> TelemetryData:
        """Advance simulation state and generate next telemetry message."""
        # Simulated flight dynamics
        heading_delta = (self.rng.random() - 0.5) * 5.0
        self.heading = (self.heading + heading_delta) % 360.0

        rad = math.radians(self.heading)
        dist = (self.speed * 0.1) / 111320.0  # Approx meters to deg
        self.lat += dist * math.cos(rad)
        self.lon += dist * math.sin(rad)

        alt_delta = (self.rng.random() - 0.5) * 2.0
        self.alt = max(50.0, min(1500.0, self.alt + alt_delta))

        # Battery slow depletion
        self.battery = max(0.0, self.battery - 0.01)

        timestamp = self.base_time + (seq * 0.05)

        return TelemetryData(
            seq=seq,
            sender_id=self.sender_id,
            timestamp=timestamp,
            lat=round(self.lat, 6),
            lon=round(self.lon, 6),
            alt=round(self.alt, 2),
            speed=round(self.speed, 2),
            heading=round(self.heading, 1),
            battery=round(self.battery, 2),
        )

    def generate_stream(self, count: int) -> Iterator[TelemetryData]:
        for i in range(1, count + 1):
            yield self.generate_packet(i)
