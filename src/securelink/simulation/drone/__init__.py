"""Simulated drone and MAVLink 2 telemetry generator."""

from securelink.simulation.drone.route import Waypoint, generate_route, interpolate_position
from securelink.simulation.drone.mini_drone import MiniDroneSimulator

__all__ = ["Waypoint", "generate_route", "interpolate_position", "MiniDroneSimulator"]
