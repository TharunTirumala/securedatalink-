"""Simulated Drone generating compliant MAVLink 2 telemetry streams."""

import time
import math
from typing import List, Tuple, Dict, Any, Iterator
from pymavlink.dialects.v20 import common as mavlink

from securelink.simulation.drone.route import Waypoint, generate_route, interpolate_position


class MiniDroneSimulator:
    """Generates continuous, realistic MAVLink 2 flight telemetry packets."""

    def __init__(
        self,
        route_pattern: str = "random",
        home: Tuple[float, float] = (37.7749, -122.4194),
        speed: float = 12.0,
        seed: int = 42,
        sysid: int = 1,
        compid: int = 1,
    ):
        self.route_pattern = route_pattern
        self.home = home
        self.speed = speed
        self.seed = seed
        self.sysid = sysid
        self.compid = compid

        self.waypoints = generate_route(
            pattern=route_pattern,
            home=home,
            speed=speed,
            seed=seed,
            cruise_alt=100.0,
        )
        self.mav = mavlink.MAVLink(None, srcSystem=sysid, srcComponent=compid)
        self.msg_seq = 0
        self.start_mono = time.monotonic()
        self.last_1hz = 0.0
        self.last_5hz = 0.0
        self.last_10hz = 0.0

    def step(self, elapsed_sec: float) -> List[Tuple[bytes, Dict[str, Any]]]:
        """Step simulation to elapsed_sec, generating due MAVLink 2 messages.

        Returns list of (raw_mavlink_bytes, state_dict).
        """
        lat, lon, alt_m, speed, heading = interpolate_position(self.waypoints, elapsed_sec, self.seed)
        battery_pct = max(10.0, 100.0 - (self.msg_seq * 0.08) - (elapsed_sec * 0.15))
        time_boot_ms = int(elapsed_sec * 1000)

        # Roll and pitch bank gently with turns
        rad_hdg = math.radians(heading)
        roll_rad = math.sin(elapsed_sec * 0.5) * 0.1
        pitch_rad = 0.05 if alt_m < 90.0 else -0.02

        state = {
            "lat": lat,
            "lon": lon,
            "alt_m": round(alt_m, 2),
            "speed": round(speed, 2),
            "heading": round(heading, 1),
            "battery_pct": round(battery_pct, 1),
            "mode": "AUTO",
            "time_boot_ms": time_boot_ms,
        }

        generated: List[Tuple[bytes, Dict[str, Any]]] = []

        # 10 Hz messages: GLOBAL_POSITION_INT, ATTITUDE
        if elapsed_sec - self.last_10hz >= 0.095:
            self.last_10hz = elapsed_sec
            self.msg_seq += 1
            lat_e7 = int(lat * 1e7)
            lon_e7 = int(lon * 1e7)
            alt_mm = int(alt_m * 1000)
            vx_cm = int(speed * math.cos(rad_hdg) * 100)
            vy_cm = int(speed * math.sin(rad_hdg) * 100)
            hdg_cdeg = int(heading * 100) % 36000

            gpos = self.mav.global_position_int_encode(
                time_boot_ms=time_boot_ms,
                lat=lat_e7,
                lon=lon_e7,
                alt=alt_mm,
                relative_alt=alt_mm,
                vx=vx_cm,
                vy=vy_cm,
                vz=0,
                hdg=hdg_cdeg,
            )
            generated.append((gpos.pack(self.mav), {**state, "msg_type": "GLOBAL_POSITION_INT"}))

            att = self.mav.attitude_encode(
                time_boot_ms=time_boot_ms,
                roll=roll_rad,
                pitch=pitch_rad,
                yaw=rad_hdg,
                rollspeed=0.0,
                pitchspeed=0.0,
                yawspeed=0.0,
            )
            generated.append((att.pack(self.mav), {**state, "msg_type": "ATTITUDE"}))

        # 5 Hz messages: GPS_RAW_INT, VFR_HUD
        if elapsed_sec - self.last_5hz >= 0.195:
            self.last_5hz = elapsed_sec
            gps = self.mav.gps_raw_int_encode(
                time_usec=int(elapsed_sec * 1e6),
                fix_type=3,
                lat=int(lat * 1e7),
                lon=int(lon * 1e7),
                alt=int(alt_m * 1000),
                eph=120,
                epv=140,
                vel=int(speed * 100),
                cog=int(heading * 100),
                satellites_visible=14,
            )
            generated.append((gps.pack(self.mav), {**state, "msg_type": "GPS_RAW_INT"}))

            vfr = self.mav.vfr_hud_encode(
                airspeed=speed,
                groundspeed=speed,
                heading=int(heading),
                throttle=65,
                alt=alt_m,
                climb=0.0,
            )
            generated.append((vfr.pack(self.mav), {**state, "msg_type": "VFR_HUD"}))

        # 1 Hz messages: HEARTBEAT, SYS_STATUS
        if elapsed_sec - self.last_1hz >= 0.995:
            self.last_1hz = elapsed_sec
            hb = self.mav.heartbeat_encode(
                type=mavlink.MAV_TYPE_QUADROTOR,
                autopilot=mavlink.MAV_AUTOPILOT_ARDUPILOTMEGA,
                base_mode=mavlink.MAV_MODE_FLAG_SAFETY_ARMED | mavlink.MAV_MODE_FLAG_AUTO_ENABLED,
                custom_mode=3,
                system_status=mavlink.MAV_STATE_ACTIVE,
            )
            generated.append((hb.pack(self.mav), {**state, "msg_type": "HEARTBEAT"}))

            sys_stat = self.mav.sys_status_encode(
                onboard_control_sensors_present=0xFFFFFFFF,
                onboard_control_sensors_enabled=0xFFFFFFFF,
                onboard_control_sensors_health=0xFFFFFFFF,
                load=320,
                voltage_battery=int(14800 * (battery_pct / 100.0)),
                current_battery=1250,
                battery_remaining=int(battery_pct),
                drop_rate_comm=0,
                errors_comm=0,
                errors_count1=0,
                errors_count2=0,
                errors_count3=0,
                errors_count4=0,
            )
            generated.append((sys_stat.pack(self.mav), {**state, "msg_type": "SYS_STATUS"}))

        return generated

