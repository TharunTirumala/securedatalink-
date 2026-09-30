"""Core data structures, enums, and models for SecureLink."""

from dataclasses import dataclass, asdict
from enum import Enum
from typing import Optional, Dict, Any


class Verdict(str, Enum):
    AUTHENTIC = "AUTHENTIC"
    TAMPERED = "TAMPERED"
    REPLAYED = "REPLAYED"
    SPOOFED = "SPOOFED"
    DROPPED = "DROPPED"


class Reason(str, Enum):
    OK = "ok"
    FRAME_MALFORMED = "frame_malformed"
    FRAME_TOO_SHORT = "frame_too_short"
    UNKNOWN_SENDER = "unknown_sender"
    GCM_TAG_MISMATCH = "gcm_tag_mismatch"
    INVALID_SIGNATURE = "invalid_signature"
    DUPLICATE_SEQ = "duplicate_seq"
    SEQ_OUT_OF_WINDOW = "seq_out_of_window"
    STALE_TIMESTAMP = "stale_timestamp"
    UNKNOWN_EPOCH = "unknown_epoch"
    EPOCH_EXPIRED = "epoch_expired"
    SENDER_BLOCKED = "sender_blocked"
    PACKET_DROPPED = "packet_dropped"



@dataclass(frozen=True)
class Header:
    version: int
    sender_id: int
    key_epoch: int
    seq: int
    timestamp: float
    session_id: int = 0


@dataclass
class SecureFrame:
    header: Header
    ciphertext_with_tag: bytes
    signature: bytes


@dataclass
class TelemetryData:
    seq: int
    sender_id: int
    timestamp: float
    lat: float
    lon: float
    alt: float
    speed: float
    heading: float
    battery: float

    def to_bytes(self) -> bytes:
        import json
        return json.dumps(asdict(self)).encode("utf-8")

    @classmethod
    def from_bytes(cls, data: bytes) -> "TelemetryData":
        import json
        payload = json.loads(data.decode("utf-8"))
        return cls(**payload)


@dataclass
class Event:
    seq: int
    verdict: str
    reason: str
    truth: str
    latency_us: float
    sender_id: int
    ts: float
    run_id: Optional[str] = None
    seed: Optional[int] = None
    epoch: Optional[int] = None
    incident_id: Optional[str] = None

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)

