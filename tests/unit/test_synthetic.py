"""Unit test for synthetic telemetry reproducibility."""

import pytest
from securelink.sources.synthetic import SyntheticTelemetrySource


def test_synthetic_source_reproducibility():
    source1 = SyntheticTelemetrySource(seed=1337)
    source2 = SyntheticTelemetrySource(seed=1337)

    packets1 = list(source1.generate_stream(50))
    packets2 = list(source2.generate_stream(50))

    assert len(packets1) == 50
    assert len(packets2) == 50

    for p1, p2 in zip(packets1, packets2):
        assert p1.seq == p2.seq
        assert p1.lat == p2.lat
        assert p1.lon == p2.lon
        assert p1.alt == p2.alt
        assert p1.heading == p2.heading
        assert p1.battery == p2.battery
        assert p1.to_bytes() == p2.to_bytes()


def test_different_seeds_give_different_output():
    source1 = SyntheticTelemetrySource(seed=100)
    source2 = SyntheticTelemetrySource(seed=200)

    p1 = source1.generate_packet(seq=1)
    p2 = source2.generate_packet(seq=1)

    assert p1.lat != p2.lat or p1.heading != p2.heading
