"""Integration tests for FastAPI REST endpoints and WebSocket functionality."""

import pytest
from fastapi.testclient import TestClient
from dashboard.backend.server import app


@pytest.fixture
def client():
    return TestClient(app)


def test_rest_api_lifecycle(client):
    # Stats initial
    resp = client.get("/api/stats")
    assert resp.status_code == 200
    data = resp.json()
    assert "total" in data

    # Run API
    run_payload = {
        "count": 50,
        "rate_pps": 0,
        "seed": 42,
        "attacks": {
            "tamper": 0.1,
            "replay": 0.1,
            "spoof": 0.05,
            "drop": 0.05,
        },
    }
    resp = client.post("/api/run", json=run_payload)
    assert resp.status_code == 200
    res_data = resp.json()
    assert res_data["status"] == "started"
    assert res_data["seed"] == 42
    assert "run_id" in res_data


    # Stop API
    resp = client.post("/api/stop")
    assert resp.status_code == 200
    assert resp.json()["status"] == "stopped"

    # Incidents
    resp = client.get("/api/incidents")
    assert resp.status_code == 200
    assert isinstance(resp.json(), list)


def test_excessive_attack_probabilities_rejected(client):
    run_payload = {
        "count": 50,
        "tamper": 0.5,
        "replay": 0.5,
        "spoof": 0.1,  # total 1.1 > 1.0
    }
    resp = client.post("/api/run", json=run_payload)
    assert resp.status_code == 422



def test_websocket_mock_feed(client):
    with client.websocket_connect("/ws/events?mock=1") as ws:
        msg = ws.receive_json()
        assert "seed" in msg
        assert "events" in msg
        events = msg["events"]
        assert isinstance(events, list)
        assert len(events) > 0
        event = events[0]
        assert "seq" in event
        assert "verdict" in event
        assert "truth" in event
        assert "latency_us" in event


def test_operator_endpoints(client):
    # 1. State initial
    resp = client.get("/api/state")
    assert resp.status_code == 200
    state = resp.json()
    assert "epoch" in state
    assert "blocked_senders" in state
    assert "rekeys" in state

    # 2. Rekey request
    resp = client.post("/api/rekey")
    assert resp.status_code == 200
    assert resp.json()["status"] == "rekey_requested"

    # 3. Block and unblock sender
    resp = client.post("/api/block/2")
    assert resp.status_code == 200
    assert resp.json()["status"] == "blocked"

    state = client.get("/api/state").json()
    assert 2 in state["blocked_senders"]

    resp = client.post("/api/unblock/2")
    assert resp.status_code == 200
    assert resp.json()["status"] == "unblocked"

    state = client.get("/api/state").json()
    assert 2 not in state["blocked_senders"]

    # 4. Incident ack
    resp = client.post("/api/incidents/inc-test-1/ack")
    assert resp.status_code == 200
    assert resp.json()["status"] == "acknowledged"


def test_rekey_mid_run_increments_epoch(client):
    """Requirement 3: Calling /api/rekey mid-run increments active epoch."""
    import time
    client.post("/api/run", json={"count": 200, "rate_pps": 30, "seed": 42})
    time.sleep(0.2)
    s1 = client.get("/api/state").json()
    e1 = s1["epoch"]

    # Trigger manual rekey
    resp = client.post("/api/rekey")
    assert resp.status_code == 200
    time.sleep(0.3)

    s2 = client.get("/api/state").json()
    assert s2["epoch"] >= e1 + 1
    assert s2["rekeys"] >= 1

    client.post("/api/stop")


def test_rekey_endpoints_and_history(client):
    """Test /api/rekey endpoints: state, history, epochs, config, and replay-old."""
    # 1. Rekey state
    resp = client.get("/api/rekey/state")
    assert resp.status_code == 200
    state = resp.json()
    assert "epoch" in state
    assert "key_id" in state
    assert len(state["key_id"]) == 8
    # Ensure no raw cryptographic key material leaked
    for forbidden in ("master_secret", "aes_key", "session_salt", "salt", "private_key"):
        assert forbidden not in state

    # 2. Rekey config update
    resp = client.post("/api/rekey/config", json={"rekey_every_packets": 50})
    assert resp.status_code == 200
    assert resp.json()["rekey_every_packets"] == 50

    # 3. Invalid config rejected with 422
    resp = client.post("/api/rekey/config", json={"rekey_every_packets": 5})
    assert resp.status_code == 422

    # 4. Replay-old without running simulation returns 409
    resp = client.post("/api/rekey/replay-old", json={"epochs_back": 1})
    assert resp.status_code == 409

    # 5. History and epochs endpoints
    resp = client.get("/api/rekey/history")
    assert resp.status_code == 200
    assert isinstance(resp.json(), list)

    resp = client.get("/api/rekey/epochs")
    assert resp.status_code == 200
    assert isinstance(resp.json(), list)


