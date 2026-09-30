"""Integration tests for transport and ingest REST APIs."""

import time
from fastapi.testclient import TestClient
import pytest
from dashboard.backend.server import app


@pytest.fixture(scope="module")
def client():
    with TestClient(app) as c:
        yield c


def test_transport_api_lifecycle(client):
    # 1. Start a session
    start_payload = {
        "session_id": "test-api-session-1",
        "source_type": "synthetic",
        "count": 10,
        "rate_pps": 50,
        "protect": True,
        "attack_mode": "pass",
        "tx_port": 25550,
        "attacker_port": 28888,
        "attacker_control_port": 28889,
        "rx_port": 29999,
        "c2_port": 25551,
    }
    resp = client.post("/api/transport/start", json=start_payload)
    assert resp.status_code == 200
    data = resp.json()
    assert data["status"] == "started"
    assert data["session_id"] == "test-api-session-1"

    # 2. Concurrency rejection
    resp_conflict = client.post("/api/transport/start", json=start_payload)
    assert resp_conflict.status_code == 409

    # 3. Dynamic attack control
    resp_atk = client.post("/api/transport/attack", json={
        "session_id": "test-api-session-1",
        "mode": "tamper",
        "rate": 0.5,
    })
    # Control server should respond with ok
    assert resp_atk.status_code == 200

    # 4. Ingest stats and telemetry
    resp_stats = client.post("/api/ingest/stats", json={
        "component": "tx",
        "session_id": "test-api-session-1",
        "stats": {"sent": 10},
    })
    assert resp_stats.status_code == 200

    resp_telem = client.post("/api/ingest/telemetry", json={
        "component": "drone",
        "session_id": "test-api-session-1",
        "telemetry": {"lat": 37.7749, "lon": -122.4194},
    })
    assert resp_telem.status_code == 200

    resp_live = client.get("/api/ingest/live")
    assert resp_live.status_code == 200
    live_data = resp_live.json()
    assert live_data["drone"]["lat"] == 37.7749

    # 5. Stop session
    resp_stop = client.post("/api/transport/stop", json={"session_id": "test-api-session-1"})
    assert resp_stop.status_code == 200

    # 6. Reconcile report
    resp_rec = client.get("/api/transport/session/test-api-session-1/reconcile")
    assert resp_rec.status_code == 200
    rec_data = resp_rec.json()
    assert "frame_reconciliation" in rec_data


def test_transport_counter_freshness_and_invariants(client):
    sid = "test-freshness-1"
    from dashboard.backend.transport_state import get_session_counters, reset_session_counters
    reset_session_counters(sid)

    # (a) posting rx stats with total=10 before events does NOT change received (stays 0)
    resp_stats = client.post("/api/ingest/stats", json={
        "component": "rx",
        "session_id": sid,
        "counts": {"total": 10, "AUTHENTIC": 10},
        "received": 10,
    })
    assert resp_stats.status_code == 200
    cnts = get_session_counters(sid)
    assert cnts["received"] == 0, f"Expected received=0 before events, got {cnts['received']}"

    # (b) then posting 10 events sets received == 10 exactly
    events = [
        {"seq": i, "epoch": 1, "verdict": "AUTHENTIC", "reason": "valid_signature"}
        for i in range(1, 11)
    ]
    resp_ev = client.post("/api/ingest/events", json={
        "session_id": sid,
        "events": events,
    })
    assert resp_ev.status_code == 200
    cnts = get_session_counters(sid)
    assert cnts["received"] == 10, f"Expected received=10 after events, got {cnts['received']}"
    assert cnts["authentic"] == 10

    # (c) tx sent counter never decreases with out-of-order posts
    client.post("/api/ingest/stats", json={
        "component": "tx",
        "session_id": sid,
        "sent": 25,
    })
    cnts = get_session_counters(sid)
    assert cnts["sent"] == 25

    # Out-of-order post with lower sent count
    client.post("/api/ingest/stats", json={
        "component": "tx",
        "session_id": sid,
        "sent": 18,
    })
    cnts = get_session_counters(sid)
    assert cnts["sent"] == 25, f"Expected sent to remain 25, got {cnts['sent']}"
