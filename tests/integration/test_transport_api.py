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


def test_reset_live_telemetry_and_status_live_flag(client):
    import time
    from dashboard.backend.transport_state import update_drone_telemetry, reset_live_telemetry

    # Feed drone telemetry
    update_drone_telemetry({"lat": 37.77, "lon": -122.41, "alt_m": 12.0})

    # Status without live=1 keeps same keys as before
    resp = client.get("/api/transport/status")
    assert resp.status_code == 200
    data = resp.json()
    assert "live" not in data
    assert set(data.keys()) == {"state", "session_id", "uptime_sec", "seed", "protect", "counters"}

    # Status with live=1 adds "live" containing drone, c2, divergence_m
    resp_live = client.get("/api/transport/status?live=1")
    assert resp_live.status_code == 200
    data_live = resp_live.json()
    assert "live" in data_live
    assert "drone" in data_live["live"]
    assert "c2" in data_live["live"]
    assert "divergence_m" in data_live["live"]
    assert data_live["live"]["drone"]["lat"] == 37.77

    # reset_live_telemetry clears stale telemetry
    reset_live_telemetry()
    resp_cleared = client.get("/api/transport/status?live=1")
    assert resp_cleared.json()["live"]["drone"] is None


def test_transport_start_duration_under_one_second(client):
    import time
    client.post("/api/transport/stop", json={})
    time.sleep(0.1)

    t0 = time.perf_counter()
    resp = client.post("/api/transport/start", json={
        "session_id": "test_fast_start_1",
        "source_type": "synthetic",
        "count": 20,
        "rate_pps": 50,
        "protect": True,
        "restart": True,
    })
    elapsed = time.perf_counter() - t0
    assert resp.status_code == 200
    assert elapsed < 1.0, f"Expected start to return in < 1.0s, took {elapsed:.3f}s"
    client.post("/api/transport/stop", json={})


def test_drone_session_e2e_reaches_sent_and_telemetry_under_ten_seconds(client):
    import time
    import socket
    import threading
    import uvicorn
    from dashboard.backend.server import app

    client.post("/api/transport/stop", json={})
    time.sleep(0.1)

    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind(("127.0.0.1", 0))
        port = s.getsockname()[1]

    server = uvicorn.Server(uvicorn.Config(app, host="127.0.0.1", port=port, log_level="warning"))
    srv_thread = threading.Thread(target=server.run, daemon=True)
    srv_thread.start()
    time.sleep(0.2)

    sid = f"drone_e2e_{int(time.time())}"
    try:
        resp = client.post("/api/transport/start", json={
            "session_id": sid,
            "source_type": "drone",
            "count": 100,
            "rate_pps": 20,
            "protect": True,
            "attack_mode": "pass",
            "dashboard_url": f"http://127.0.0.1:{port}",
            "restart": True,
        })
        assert resp.status_code == 200

        t_start = time.perf_counter()
        sent_seen, telem_seen = False, False

        deadline = t_start + 10.0
        while time.perf_counter() < deadline:
            st = client.get("/api/transport/status?live=1").json()
            cnt = st.get("counters", {})
            if cnt.get("sent", 0) > 0:
                sent_seen = True
            if st.get("live", {}).get("drone") is not None:
                telem_seen = True
            if sent_seen and telem_seen:
                break
            time.sleep(0.05)

        assert sent_seen, "Expected counters.sent > 0 within 10s"
        assert telem_seen, "Expected live drone telemetry within 10s"

        from dashboard.backend.transport_state import get_session_counters

        end_deadline = time.perf_counter() + 15.0
        while time.perf_counter() < end_deadline:
            st = client.get("/api/transport/status?live=1").json()
            cnt = get_session_counters(sid)
            if cnt.get("sent", 0) >= 100 and cnt.get("received", 0) >= 100:
                break
            if st.get("state") in ("finished", "stopped", "idle") and cnt.get("sent", 0) >= 100 and cnt.get("received", 0) >= 100:
                break
            time.sleep(0.1)

        final_cnt = get_session_counters(sid)
        assert final_cnt["sent"] == 100
        assert final_cnt["received"] == 100
    finally:
        client.post("/api/transport/stop", json={})
        server.should_exit = True
        srv_thread.join(timeout=1.0)
