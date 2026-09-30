"""Integration tests for Transport session state machine resilience and authoritative counters."""

import socket
import time
from fastapi.testclient import TestClient
import pytest

from dashboard.backend.server import app
from dashboard.backend.transport_state import manager


@pytest.fixture(scope="module")
def client():
    with TestClient(app) as c:
        yield c


def _verify_ports_free(udp_ports, tcp_ports):
    """Verify that ports can be bound to immediately after session stop."""
    for p in udp_ports:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        try:
            s.bind(("127.0.0.1", p))
        finally:
            s.close()
    for p in tcp_ports:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        try:
            s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            s.bind(("127.0.0.1", p))
        finally:
            s.close()


def test_start_stop_start_and_port_rebind(client):
    cfg = {
        "session_id": "test-resilience-rebind-1",
        "source_type": "synthetic",
        "count": 50,
        "rate_pps": 50,
        "protect": True,
        "tx_port": 31550,
        "attacker_port": 31888,
        "attacker_control_port": 31889,
        "rx_port": 31999,
        "c2_port": 31551,
    }
    # 1. Start first run
    r1 = client.post("/api/transport/start", json=cfg)
    assert r1.status_code == 200

    # 2. Stop first run
    r_stop = client.post("/api/transport/stop", json={"session_id": "test-resilience-rebind-1"})
    assert r_stop.status_code == 200
    assert r_stop.json()["state"] == "idle"

    # 3. Verify ports are released immediately
    time.sleep(0.3)
    _verify_ports_free(
        udp_ports=[31550, 31888, 31999, 31551],
        tcp_ports=[31889]
    )

    # 4. Start second run on the exact same ports
    cfg2 = dict(cfg)
    cfg2["session_id"] = "test-resilience-rebind-2"
    r2 = client.post("/api/transport/start", json=cfg2)
    assert r2.status_code == 200
    assert r2.json()["status"] == "started"

    # Clean up
    client.post("/api/transport/stop", json={"session_id": "test-resilience-rebind-2"})


def test_start_while_running_409_and_restart_true(client):
    cfg = {
        "session_id": "test-resilience-conflict-1",
        "source_type": "synthetic",
        "count": 100,
        "rate_pps": 50,
        "protect": True,
        "tx_port": 32550,
        "attacker_port": 32888,
        "attacker_control_port": 32889,
        "rx_port": 32999,
        "c2_port": 32551,
    }
    r1 = client.post("/api/transport/start", json=cfg)
    assert r1.status_code == 200

    # Concurrent start without restart flag must return 409
    r_conflict = client.post("/api/transport/start", json=cfg)
    assert r_conflict.status_code == 409
    conf_data = r_conflict.json()
    assert conf_data["session_id"] == "test-resilience-conflict-1"
    assert conf_data["state"] == "running"

    # Start with restart: true must cleanly restart
    cfg_restart = dict(cfg)
    cfg_restart["session_id"] = "test-resilience-conflict-2"
    cfg_restart["restart"] = True
    r_restart = client.post("/api/transport/start", json=cfg_restart)
    assert r_restart.status_code == 200
    assert r_restart.json()["session_id"] == "test-resilience-conflict-2"

    client.post("/api/transport/stop", json={"session_id": "test-resilience-conflict-2"})


def test_crash_recovery_to_idle(client):
    # A short session that finishes naturally
    cfg = {
        "session_id": "test-resilience-finish-1",
        "source_type": "synthetic",
        "count": 5,
        "rate_pps": 50,
        "protect": True,
        "tx_port": 33550,
        "attacker_port": 33888,
        "attacker_control_port": 33889,
        "rx_port": 33999,
        "c2_port": 33551,
    }
    r = client.post("/api/transport/start", json=cfg)
    assert r.status_code == 200

    # Wait for process exit and watchdog completion
    time.sleep(1.8)

    # Status must return idle
    r_stat = client.get("/api/transport/status")
    assert r_stat.status_code == 200
    stat_data = r_stat.json()
    assert stat_data["state"] in ("idle", "stopping")

    # Stop endpoint is idempotent
    r_stop = client.post("/api/transport/stop", json={})
    assert r_stop.status_code == 200
    assert r_stop.json()["state"] == "idle"


def test_100_frame_counter_match_and_status(client):
    sid = "test-100-frames-session"
    client.post("/api/transport/start", json={
        "session_id": sid,
        "source_type": "synthetic",
        "count": 100,
        "rate_pps": 100,
        "protect": True,
        "tx_port": 34550,
        "attacker_port": 34888,
        "attacker_control_port": 34889,
        "rx_port": 34999,
        "c2_port": 34551,
    })

    # Simulate TX stats: 100 sent
    client.post("/api/ingest/stats", json={
        "role": "tx", "session_id": sid, "sent": 100, "epoch": 1, "rate": 50.0
    })

    # Simulate Attacker: 10 dropped, 10 tampered, 80 passed
    client.post("/api/ingest/stats", json={
        "component": "attacker", "session_id": sid,
        "stats": {"received": 100, "forwarded": 90, "mutated": 10, "dropped": 10}
    })
    atk_actions = []
    for seq in range(1, 11):
        atk_actions.append({"seq": seq, "intended_label": "DROPPED", "action": "dropped"})
    for seq in range(11, 21):
        atk_actions.append({"seq": seq, "intended_label": "TAMPERED", "action": "tampered"})
    for seq in range(21, 101):
        atk_actions.append({"seq": seq, "intended_label": "AUTHENTIC", "action": "pass"})
    client.post("/api/ingest/attacker_actions", json={"session_id": sid, "actions": atk_actions})

    # Simulate RX: received 90 frames (10 tampered, 80 authentic)
    rx_events = []
    for seq in range(11, 21):
        rx_events.append({"seq": seq, "verdict": "TAMPERED", "epoch": 1, "reason": "tag_mismatch"})
    for seq in range(21, 101):
        rx_events.append({"seq": seq, "verdict": "AUTHENTIC", "epoch": 1, "reason": "ok"})
    client.post("/api/ingest/events", json={"session_id": sid, "events": rx_events})

    # Verify status counters match the ground truth exactly
    r_stat = client.get("/api/transport/status")
    assert r_stat.status_code == 200
    counters = r_stat.json()["counters"]

    assert counters["sent"] == 100
    assert counters["received"] == 90
    assert counters["dropped"] == 10
    assert counters["tampered"] == 10
    assert counters["authentic"] == 80
    assert counters["false_accepts"] == 0
    assert counters["false_rejects"] == 0
    assert counters["received"] + counters["dropped"] == 100

    client.post("/api/transport/stop", json={"session_id": sid})


def test_counters_restart_at_zero(client):
    # Ensure any previous session is stopped
    client.post("/api/transport/stop", json={})
    time.sleep(0.3)

    sid = "test-reset-session-next"
    # Start session
    r1 = client.post("/api/transport/start", json={
        "session_id": sid,
        "source_type": "synthetic",
        "count": 20,
        "rate_pps": 50,
        "protect": True,
        "restart": True,
        "tx_port": 35550,
        "attacker_port": 35888,
        "attacker_control_port": 35889,
        "rx_port": 35999,
        "c2_port": 35551,
    })
    assert r1.status_code == 200

    # Ingest stats
    client.post("/api/ingest/stats", json={"role": "tx", "session_id": sid, "sent": 20})
    r_stat1 = client.get("/api/transport/status")
    assert r_stat1.status_code == 200
    assert r_stat1.json()["counters"]["sent"] == 20

    # Stop session
    r_stop = client.post("/api/transport/stop", json={"session_id": sid})
    assert r_stop.status_code == 200
    time.sleep(0.3)

    # Start new session
    sid2 = "test-reset-session-clean"
    r2 = client.post("/api/transport/start", json={
        "session_id": sid2,
        "source_type": "synthetic",
        "count": 20,
        "rate_pps": 50,
        "protect": True,
        "tx_port": 35550,
        "attacker_port": 35888,
        "attacker_control_port": 35889,
        "rx_port": 35999,
        "c2_port": 35551,
    })
    assert r2.status_code == 200

    # Counters must be cleanly reset to 0
    r_stat2 = client.get("/api/transport/status")
    counters2 = r_stat2.json()["counters"]
    assert counters2["sent"] == 0
    assert counters2["received"] == 0
    assert counters2["authentic"] == 0
    assert counters2["tampered"] == 0
    assert counters2["dropped"] == 0
    assert counters2["false_accepts"] == 0

    client.post("/api/transport/stop", json={"session_id": sid2})
