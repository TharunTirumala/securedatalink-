"""Unit tests for MiniDroneSimulator and waypoint generation."""

from pymavlink.dialects.v20 import common as mavlink
from securelink.simulation.drone.route import (
    generate_route,
    interpolate_position,
    lat_lon_distance_m,
)
from securelink.simulation.drone.mini_drone import MiniDroneSimulator


def test_mavlink_crc_valid_for_all_messages():
    """Verify all MAVLink 2 messages parse back cleanly with valid CRCs."""
    sim = MiniDroneSimulator(route_pattern="circle", seed=101)
    parser = mavlink.MAVLink(None)

    total_checked = 0
    # Step through 2 full seconds of simulated flight to cover all message types (1Hz, 5Hz, 10Hz)
    for t_step in range(25):
        t_sec = t_step * 0.1
        pkts = sim.step(t_sec)
        for raw_bytes, _ in pkts:
            parsed_msgs = parser.parse_buffer(raw_bytes)
            assert parsed_msgs is not None
            assert len(parsed_msgs) == 1
            msg = parsed_msgs[0]
            assert msg.get_msgId() in (
                mavlink.MAVLINK_MSG_ID_HEARTBEAT,
                mavlink.MAVLINK_MSG_ID_GLOBAL_POSITION_INT,
                mavlink.MAVLINK_MSG_ID_ATTITUDE,
                mavlink.MAVLINK_MSG_ID_GPS_RAW_INT,
                mavlink.MAVLINK_MSG_ID_VFR_HUD,
                mavlink.MAVLINK_MSG_ID_SYS_STATUS,
            )
            total_checked += 1

    assert total_checked >= 20


def test_seed_determinism_and_uniqueness():
    """Same seed must yield identical telemetry; different seeds must differ."""
    sim_a1 = MiniDroneSimulator(route_pattern="random", seed=555)
    sim_a2 = MiniDroneSimulator(route_pattern="random", seed=555)
    sim_b = MiniDroneSimulator(route_pattern="random", seed=999)

    pkts_a1 = sim_a1.step(5.0)
    pkts_a2 = sim_a2.step(5.0)
    pkts_b = sim_b.step(5.0)

    # Identical seed
    assert len(pkts_a1) == len(pkts_a2)
    assert pkts_a1[0][0] == pkts_a2[0][0]
    assert pkts_a1[0][1]["lat"] == pkts_a2[0][1]["lat"]
    assert pkts_a1[0][1]["lon"] == pkts_a2[0][1]["lon"]

    # Different seed
    assert pkts_a1[0][1]["lat"] != pkts_b[0][1]["lat"] or pkts_a1[0][1]["lon"] != pkts_b[0][1]["lon"]


def test_route_smoothness_no_large_jumps():
    """Consecutive 10 Hz samples must not jump more than 50 meters."""
    wps = generate_route("random", seed=777, speed=15.0)
    prev_pos = None

    for t_i in range(100):
        t_sec = t_i * 0.1
        lat, lon, alt, spd, hdg = interpolate_position(wps, t_sec, seed=777)
        if prev_pos is not None:
            dist = lat_lon_distance_m(prev_pos[0], prev_pos[1], lat, lon)
            assert dist < 50.0, f"Position jump too large at t={t_sec}: {dist:.2f}m >= 50m"
        prev_pos = (lat, lon)
