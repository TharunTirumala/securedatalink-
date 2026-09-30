"""Configuration loader with strong typing and default fallbacks."""

import yaml
from pathlib import Path
from dataclasses import dataclass, field
from typing import Dict, Any, Optional


@dataclass
class SimulationConfig:
    seed: Optional[int] = None
    count: int = 200
    rate_pps: int = 20
    sender_id: int = 1
    key_epoch: int = 1
    rekey_every_packets: int = 100
    rekey_grace_epochs: int = 1

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "SimulationConfig":
        """Unify CLI, YAML ('rate_pps', 'seed: null'), and API ('rate_hz', 'duration_s') params."""
        rate = data.get("rate_pps")
        if rate is None:
            rate = data.get("rate_hz")
        if rate is None:
            rate = 20

        count = data.get("count")
        if count is None and data.get("duration_s") is not None:
            count = int(float(data["duration_s"]) * rate)
        if count is None:
            count = 200

        seed_val = data.get("seed")
        if seed_val in (None, "", "null", "random", "none"):
            seed_val = None
        else:
            try:
                seed_val = int(seed_val)
            except (ValueError, TypeError):
                seed_val = hash(str(seed_val)) & 0xFFFFFFFF

        return cls(
            seed=seed_val,
            count=int(count),
            rate_pps=int(rate),
            sender_id=int(data.get("sender_id") or 1),
            key_epoch=int(data.get("key_epoch") or 1),
            rekey_every_packets=int(data.get("rekey_every_packets") or 100),
            rekey_grace_epochs=int(data.get("rekey_grace_epochs") or 1),
        )


@dataclass
class AttackConfig:
    tamper_prob: float = 0.10
    replay_prob: float = 0.10
    spoof_prob: float = 0.05
    drop_prob: float = 0.05

    def __post_init__(self):
        total = round(self.tamper_prob + self.replay_prob + self.spoof_prob + self.drop_prob, 6)
        if total > 1.0:
            raise ValueError(f"Sum of attack probabilities ({total}) cannot exceed 1.0")


    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "AttackConfig":
        """Normalize both YAML ('tamper_prob') and API ('tamper') keys in one place."""
        def get_prob(name: str, default: float) -> float:
            val = data.get(f"{name}_prob")
            if val is None:
                val = data.get(name)
            if val is None:
                val = default
            return float(val)

        return cls(
            tamper_prob=get_prob("tamper", 0.10),
            replay_prob=get_prob("replay", 0.10),
            spoof_prob=get_prob("spoof", 0.05),
            drop_prob=get_prob("drop", 0.05),
        )



@dataclass
class ReplayGuardConfig:
    window_size: int = 64
    max_clock_skew_sec: float = 30.0
    enforce_timestamp: bool = True


@dataclass
class ServerConfig:
    host: str = "127.0.0.1"
    port: int = 8000


@dataclass
class LabConfig:
    max_bytes: int = 5242880
    max_rows: int = 5000
    max_columns: int = 64
    max_payload_bytes: int = 1024
    default_rate_pps: int = 100
    default_rekey_every_packets: int = 50


@dataclass
class AppConfig:
    simulation: SimulationConfig = field(default_factory=SimulationConfig)
    attacks: AttackConfig = field(default_factory=AttackConfig)
    replay_guard: ReplayGuardConfig = field(default_factory=ReplayGuardConfig)
    server: ServerConfig = field(default_factory=ServerConfig)
    lab: LabConfig = field(default_factory=LabConfig)
    threat_log_path: str = "logs/threat_log.jsonl"

    @classmethod
    def load(cls, config_path: str = "configs/default.yaml") -> "AppConfig":
        path = Path(config_path)
        if not path.exists():
            return cls()

        with open(path, "r", encoding="utf-8") as f:
            data = yaml.safe_load(f) or {}

        sim_data = data.get("simulation", {})
        att_data = data.get("attacks", {})
        rg_data = data.get("replay_guard", {})
        srv_data = data.get("server", {})
        lab_data = data.get("lab", {})
        audit_data = data.get("audit", {})

        return cls(
            simulation=SimulationConfig.from_dict(sim_data) if sim_data else SimulationConfig(),
            attacks=AttackConfig.from_dict(att_data) if att_data else AttackConfig(),
            replay_guard=ReplayGuardConfig(**rg_data) if rg_data else ReplayGuardConfig(),
            server=ServerConfig(**srv_data) if srv_data else ServerConfig(),
            lab=LabConfig(**lab_data) if lab_data else LabConfig(),
            threat_log_path=audit_data.get("threat_log_path", "logs/threat_log.jsonl"),
        )


