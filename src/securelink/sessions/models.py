"""Session configuration and lifecycle models."""

from dataclasses import asdict, dataclass, field
from typing import Any, Dict, Optional


@dataclass
class SessionConfig:
    session_id: str
    source_type: str = "drone"  # drone, synthetic, csv, json
    source_path: Optional[str] = None
    protect: bool = True
    rate_pps: int = 20
    count: Optional[int] = None
    rekey_every: int = 100
    drone_seed: int = 42
    drone_route: str = "circle"
    attack_mode: str = "pass"
    attack_rate: float = 1.0
    attack_params: Dict[str, Any] = field(default_factory=dict)
    attack_seed: int = 123
    tx_port: int = 14550
    attacker_port: int = 8888
    attacker_control_port: int = 8889
    rx_port: int = 9999
    c2_port: int = 14551
    keys_dir: str = "keys"
    dashboard_url: str = "http://127.0.0.1:8000"

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "SessionConfig":
        valid_keys = cls.__dataclass_fields__.keys()
        filtered = {k: v for k, v in data.items() if k in valid_keys}
        return cls(**filtered)


@dataclass
class SessionState:
    session_id: str
    status: str = "created"  # created, starting, running, draining, finished, failed, stopped
    start_time: Optional[float] = None
    end_time: Optional[float] = None
    exit_code: Optional[int] = None
    error_message: Optional[str] = None
    stats: Dict[str, Any] = field(default_factory=lambda: {
        "drone": {}, "tx": {}, "attacker": {}, "rx": {}, "c2": {}
    })
    pids: Dict[str, int] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "SessionState":
        valid_keys = cls.__dataclass_fields__.keys()
        filtered = {k: v for k, v in data.items() if k in valid_keys}
        return cls(**filtered)
