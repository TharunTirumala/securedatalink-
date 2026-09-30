"""Process command builders for SecureLink session execution."""

import sys
from pathlib import Path
from typing import Dict, List
from securelink.sessions.models import SessionConfig


def build_process_commands(config: SessionConfig, s_dir: Path, token: str) -> Dict[str, List[str]]:
    """Build command-line argument lists for all pipeline child processes."""
    cmds: Dict[str, List[str]] = {}

    # 1. C2 View
    cmds["c2"] = [
        sys.executable, "-m", "securelink.cli.c2_view",
        "--listen", f"127.0.0.1:{config.c2_port}",
        "--dashboard", config.dashboard_url,
        "--session-id", config.session_id,
        "--log", str(s_dir / "c2_received.jsonl"),
        "--token", token,
    ]

    # 2. RX Gateway
    cmds["rx"] = [
        sys.executable, "-m", "securelink.cli.rx",
        "--listen", f"127.0.0.1:{config.rx_port}",
        "--keys-dir", config.keys_dir,
        "--protect", "on" if config.protect else "off",
        "--dashboard", config.dashboard_url,
        "--session-id", config.session_id,
        "--events-log", str(s_dir / "rx_events.jsonl"),
        "--output-log", str(s_dir / "rx_output.jsonl"),
        "--mavlink-out", f"127.0.0.1:{config.c2_port}",
        "--token", token,
    ]

    # 3. Attacker
    cmds["attacker"] = [
        sys.executable, "-m", "securelink.cli.attacker",
        "--listen", f"127.0.0.1:{config.attacker_port}",
        "--forward", f"127.0.0.1:{config.rx_port}",
        "--mode", config.attack_mode,
        "--rate", str(config.attack_rate),
        "--control-port", str(config.attacker_control_port),
        "--seed", str(config.attack_seed),
        "--log", str(s_dir / "attacker_log.jsonl"),
        "--dashboard", config.dashboard_url,
        "--session-id", config.session_id,
        "--token", token,
    ]

    # 4. TX Gateway
    tx_source = "mavlink" if config.source_type == "drone" else config.source_type
    tx_cmd = [
        sys.executable, "-m", "securelink.cli.tx",
        "--send", f"127.0.0.1:{config.attacker_port}",
        "--source", tx_source,
        "--protect", "on" if config.protect else "off",
        "--rate-pps", str(config.rate_pps),
        "--rekey-every", str(config.rekey_every),
        "--keys-dir", config.keys_dir,
        "--session-id", config.session_id,
        "--manifest", str(s_dir / "tx_manifest.jsonl"),
        "--dashboard", config.dashboard_url,
        "--token", token,
    ]
    if config.source_type == "drone":
        tx_cmd += ["--mavlink-listen", f"127.0.0.1:{config.tx_port}"]
    if config.source_path:
        tx_cmd += ["--path", str(config.source_path)]
    if config.count:
        tx_cmd += ["--count", str(config.count)]
    cmds["tx"] = tx_cmd

    # 5. Drone Sim (if applicable)
    if config.source_type == "drone":
        d_cmd = [
            sys.executable, "-m", "securelink.cli.drone_sim",
            "--send", f"127.0.0.1:{config.tx_port}",
            "--seed", str(config.drone_seed),
            "--route", config.drone_route,
            "--rate-hz", str(config.rate_pps),
            "--dashboard", config.dashboard_url,
            "--session-id", config.session_id,
            "--log", str(s_dir / "drone_truth.jsonl"),
        ]
        if config.count:
            d_cmd += ["--count", str(config.count)]
        cmds["drone"] = d_cmd

    return cmds
