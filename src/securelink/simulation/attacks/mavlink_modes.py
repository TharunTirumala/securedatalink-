"""MAVLink-aware semantic mutators with valid CRC recomputation.

Falls back to byte tamper when operating on encrypted/non-MAVLink payloads.
Strict isolation: NEVER import crypto, rx_pipeline, tx_pipeline, or keystores.
"""

from typing import Any, Dict, Optional, Tuple
from securelink.simulation.attacks.wire_modes import apply_wire_tamper

try:
    import pymavlink.dialects.v20.common as mavlink2
except ImportError:
    mavlink2 = None


class MavlinkMutator:
    """Applies semantic domain-level mutations to MAVLink 2 datagrams."""

    def __init__(self):
        self.frozen_pos: Optional[Tuple[int, int, int]] = None
        self._mav = mavlink2.MAVLink(None) if mavlink2 else None

    def mutate(
        self,
        raw_bytes: bytes,
        mode: str,
        params: Optional[Dict[str, Any]] = None,
    ) -> Tuple[Optional[bytes], str, Dict[str, Any]]:
        """Mutate a datagram based on MAVLink semantics or fallback to wire tamper."""
        params = params or {}
        if not self._mav or not raw_bytes:
            tampered, tag = apply_wire_tamper(raw_bytes)
            return tampered, "TAMPERED", {"fallback": True, "reason": "wire_corruption_payload_encrypted", "field": "raw_bytes"}

        try:
            mav_parser = mavlink2.MAVLink(None)
            msgs = mav_parser.parse_buffer(raw_bytes)
            if not msgs:
                tampered, tag = apply_wire_tamper(raw_bytes)
                return tampered, "TAMPERED", {"fallback": True, "reason": "wire_corruption_payload_encrypted", "field": "wire_bytes"}
            msg = msgs[0]
        except Exception:
            tampered, tag = apply_wire_tamper(raw_bytes)
            return tampered, "TAMPERED", {"fallback": True, "reason": "wire_corruption_payload_encrypted", "field": "wire_bytes"}

        msg_type = msg.get_type()
        meta: Dict[str, Any] = {"msg_type": msg_type, "fallback": False}

        if mode == "position_rewrite":
            lat_off = int(params.get("lat_offset_deg", 0.005) * 1e7)
            lon_off = int(params.get("lon_offset_deg", 0.005) * 1e7)
            if msg_type == "GLOBAL_POSITION_INT":
                meta.update({"field": "lat/lon", "orig_lat": msg.lat, "orig_lon": msg.lon})
                msg.lat += lat_off
                msg.lon += lon_off
                meta.update({"new_lat": msg.lat, "new_lon": msg.lon})
                return msg.pack(self._mav), "MUTATED", meta
            elif msg_type == "GPS_RAW_INT":
                meta.update({"field": "lat/lon", "orig_lat": msg.lat, "orig_lon": msg.lon})
                msg.lat += lat_off
                msg.lon += lon_off
                meta.update({"new_lat": msg.lat, "new_lon": msg.lon})
                return msg.pack(self._mav), "MUTATED", meta

        elif mode == "altitude_rewrite":
            alt_off_m = float(params.get("alt_offset_m", 100.0))
            if msg_type == "GLOBAL_POSITION_INT":
                meta.update({"field": "alt", "orig_alt": msg.alt})
                msg.alt += int(alt_off_m * 1000)
                msg.relative_alt += int(alt_off_m * 1000)
                meta.update({"new_alt": msg.alt})
                return msg.pack(self._mav), "MUTATED", meta
            elif msg_type == "GPS_RAW_INT":
                meta.update({"field": "alt", "orig_alt": msg.alt})
                msg.alt += int(alt_off_m * 1000)
                meta.update({"new_alt": msg.alt})
                return msg.pack(self._mav), "MUTATED", meta
            elif msg_type == "VFR_HUD":
                meta.update({"field": "alt", "orig_alt": msg.alt})
                msg.alt += alt_off_m
                meta.update({"new_alt": msg.alt})
                return msg.pack(self._mav), "MUTATED", meta

        elif mode == "gps_freeze":
            if msg_type == "GLOBAL_POSITION_INT":
                if self.frozen_pos is None:
                    self.frozen_pos = (msg.lat, msg.lon, msg.alt)
                meta.update({"field": "gps_frozen", "orig_lat": msg.lat, "orig_lon": msg.lon})
                msg.lat, msg.lon, msg.alt = self.frozen_pos
                meta.update({"frozen_lat": msg.lat, "frozen_lon": msg.lon})
                return msg.pack(self._mav), "MUTATED", meta

        elif mode == "battery_lie":
            if msg_type == "SYS_STATUS":
                meta.update({"field": "battery_remaining", "orig_bat": msg.battery_remaining})
                msg.battery_remaining = int(params.get("lie_percent", 100))
                meta.update({"new_bat": msg.battery_remaining})
                return msg.pack(self._mav), "MUTATED", meta

        elif mode == "heartbeat_flood":
            if msg_type == "HEARTBEAT":
                meta.update({"field": "system_status", "orig_status": msg.system_status})
                msg.system_status = 0
                return msg.pack(self._mav), "MUTATED", meta

        # If mode does not apply to this message type, return unmodified
        return raw_bytes, "AUTHENTIC", meta
