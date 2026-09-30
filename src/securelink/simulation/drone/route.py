"""Route and waypoint generators for simulated drone flights."""

import math
import random
from dataclasses import dataclass
from typing import List, Tuple


@dataclass
class Waypoint:
    lat: float
    lon: float
    alt_m: float
    speed_ms: float


def meters_to_lat_lon(d_north_m: float, d_east_m: float, ref_lat: float, ref_lon: float) -> Tuple[float, float]:
    """Convert local North/East offsets in meters to WGS-84 (lat, lon)."""
    lat_deg = ref_lat + (d_north_m / 111139.0)
    lon_deg = ref_lon + (d_east_m / (111139.0 * math.cos(math.radians(ref_lat))))
    return lat_deg, lon_deg


def lat_lon_distance_m(lat1: float, lon1: float, lat2: float, lon2: float) -> float:
    """Compute approximate ground distance in meters between two coordinates."""
    d_lat = (lat2 - lat1) * 111139.0
    d_lon = (lon2 - lon1) * 111139.0 * math.cos(math.radians((lat1 + lat2) / 2.0))
    return math.hypot(d_lat, d_lon)


def compute_bearing_deg(lat1: float, lon1: float, lat2: float, lon2: float) -> float:
    """Compute heading in degrees [0, 360) from point 1 to point 2."""
    y = math.sin(math.radians(lon2 - lon1)) * math.cos(math.radians(lat2))
    x = math.cos(math.radians(lat1)) * math.sin(math.radians(lat2)) - (
        math.sin(math.radians(lat1)) * math.cos(math.radians(lat2)) * math.cos(math.radians(lon2 - lon1))
    )
    b = math.degrees(math.atan2(y, x))
    return (b + 360.0) % 360.0


def generate_route(
    pattern: str = "random",
    home: Tuple[float, float] = (37.7749, -122.4194),
    speed: float = 12.0,
    seed: int = 42,
    cruise_alt: float = 100.0,
) -> List[Waypoint]:
    """Generate smooth waypoints for a flight profile."""
    rng = random.Random(seed)
    home_lat, home_lon = home
    wps: List[Waypoint] = [Waypoint(lat=home_lat, lon=home_lon, alt_m=0.0, speed_ms=0.0)]

    if pattern == "circle":
        radius = 450.0
        n_pts = 12
        for i in range(n_pts + 1):
            ang = (2.0 * math.pi * i) / n_pts
            dn = radius * math.cos(ang)
            de = radius * math.sin(ang)
            w_lat, w_lon = meters_to_lat_lon(dn, de, home_lat, home_lon)
            wps.append(Waypoint(lat=w_lat, lon=w_lon, alt_m=cruise_alt, speed_ms=speed))
    elif pattern == "square":
        half = 250.0
        offsets = [(half, -half), (half, half), (-half, half), (-half, -half), (half, -half)]
        for dn, de in offsets:
            w_lat, w_lon = meters_to_lat_lon(dn, de, home_lat, home_lon)
            wps.append(Waypoint(lat=w_lat, lon=w_lon, alt_m=cruise_alt, speed_ms=speed))
    elif pattern == "survey":
        # Lawnmower pattern
        transects = 4
        length = 400.0
        spacing = 100.0
        for i in range(transects):
            de = (i - transects / 2.0) * spacing
            dn1 = -length / 2.0 if i % 2 == 0 else length / 2.0
            dn2 = length / 2.0 if i % 2 == 0 else -length / 2.0
            la1, lo1 = meters_to_lat_lon(dn1, de, home_lat, home_lon)
            la2, lo2 = meters_to_lat_lon(dn2, de, home_lat, home_lon)
            wps.append(Waypoint(lat=la1, lon=lo1, alt_m=cruise_alt, speed_ms=speed))
            wps.append(Waypoint(lat=la2, lon=lo2, alt_m=cruise_alt, speed_ms=speed))
    else:
        # Default: random waypoints (4 to 8) within 300 to 800m of home
        n_pts = rng.randint(5, 8)
        for _ in range(n_pts):
            dist = rng.uniform(300.0, 800.0)
            bearing = rng.uniform(0.0, 2.0 * math.pi)
            dn = dist * math.cos(bearing)
            de = dist * math.sin(bearing)
            w_lat, w_lon = meters_to_lat_lon(dn, de, home_lat, home_lon)
            s = rng.uniform(max(6.0, speed - 4.0), min(18.0, speed + 4.0))
            wps.append(Waypoint(lat=w_lat, lon=w_lon, alt_m=cruise_alt + rng.uniform(-15.0, 15.0), speed_ms=s))

    # Final waypoint returns to home and descends
    wps.append(Waypoint(lat=home_lat, lon=home_lon, alt_m=0.0, speed_ms=speed * 0.5))
    return wps


def interpolate_position(
    waypoints: List[Waypoint],
    elapsed_sec: float,
    seed: int = 42,
) -> Tuple[float, float, float, float, float]:
    """Calculate current (lat, lon, alt_m, speed, heading) for elapsed flight time."""
    if len(waypoints) < 2:
        wp = waypoints[0]
        return wp.lat, wp.lon, wp.alt_m, wp.speed_ms, 0.0

    # Calculate segment durations
    seg_durations = []
    for i in range(len(waypoints) - 1):
        w1, w2 = waypoints[i], waypoints[i + 1]
        dist = lat_lon_distance_m(w1.lat, w1.lon, w2.lat, w2.lon)
        avg_speed = max(3.0, (w1.speed_ms + w2.speed_ms) / 2.0)
        seg_durations.append(dist / avg_speed)

    total_time = sum(seg_durations)
    t = elapsed_sec % max(1.0, total_time)

    accum = 0.0
    for i, dur in enumerate(seg_durations):
        if accum + dur >= t or i == len(seg_durations) - 1:
            frac = (t - accum) / max(0.001, dur)
            frac = max(0.0, min(1.0, frac))
            w1, w2 = waypoints[i], waypoints[i + 1]

            cur_lat = w1.lat + (w2.lat - w1.lat) * frac
            cur_lon = w1.lon + (w2.lon - w1.lon) * frac
            cur_alt = w1.alt_m + (w2.alt_m - w1.alt_m) * frac
            cur_speed = w1.speed_ms + (w2.speed_ms - w1.speed_ms) * frac
            cur_heading = compute_bearing_deg(w1.lat, w1.lon, w2.lat, w2.lon)

            # Add subtle deterministic wind drift based on seed (< 2m offset)
            wind_drift = math.sin(elapsed_sec * 0.2 + seed) * (0.5 / 111139.0)
            return cur_lat + wind_drift, cur_lon + wind_drift, max(0.0, cur_alt), cur_speed, cur_heading
        accum += dur

    last = waypoints[-1]
    return last.lat, last.lon, last.alt_m, last.speed_ms, 0.0
