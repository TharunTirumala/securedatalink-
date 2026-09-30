"""Exactness tests for Transport counter correctness and session state machine."""

import time
import pytest
from fastapi.testclient import TestClient

from dashboard.backend.server import app
from dashboard.backend import transport_state


@pytest.fixture(scope="module")
def client():
    with TestClient(app) as c:
        yield c


def _stop_all(client):
    client.post("/api/transport/stop", json={})
    time.sleep(0.2)


def _ingest_tx(client, sid, count):
    client.post("/api/ingest/stats", json={
        "role": "tx", "session_id": sid, "sent": count
    })


def _ingest_rx_events(client, sid, events):
    client.post("/api/ingest/events", json={"session_id": sid, "events": events})


def _ingest_atk(client, sid, actions):
    client.post("/api/ingest/attacker_actions", json={"session_id": sid, "actions": actions})


def _counters(client):
    return client.get("/api/transport/status").json()["counters"]


class TestExactCounters:
    """Counter invariant checks for 100-packet runs."""

    def test_clean_100_run_counters_exact(self, client):
        _stop_all(client)
        sid = "exact-clean-100"
        client.post("/api/transport/start", json={
            "session_id": sid, "source_type": "synthetic",
            "count": 100, "rate_pps": 100, "protect": True,
            "tx_port": 41550, "attacker_port": 41888,
            "attacker_control_port": 41889, "rx_port": 41999, "c2_port": 41551,
        })
        _ingest_tx(client, sid, 100)
        atk = [{"seq": i, "intended_label": "AUTHENTIC", "action": "pass"} for i in range(1, 101)]
        _ingest_atk(client, sid, atk)
        rx = [{"seq": i, "verdict": "AUTHENTIC", "epoch": 1, "reason": "ok"} for i in range(1, 101)]
        _ingest_rx_events(client, sid, rx)
        c = _counters(client)
        assert c["sent"] == 100, f"sent={c['sent']}"
        assert c["received"] == 100, f"received={c['received']}"
        assert c["authentic"] == 100, f"authentic={c['authentic']}"
        assert c["tampered"] == 0
        assert c["dropped"] == 0
        assert c["false_accepts"] == 0
        assert c["false_rejects"] == 0
        _stop_all(client)

    def test_100_tamper_all_invariants(self, client):
        _stop_all(client)
        sid = "exact-tamper-100"
        client.post("/api/transport/start", json={
            "session_id": sid, "source_type": "synthetic",
            "count": 100, "rate_pps": 100, "protect": True,
            "tx_port": 42550, "attacker_port": 42888,
            "attacker_control_port": 42889, "rx_port": 42999, "c2_port": 42551,
        })
        _ingest_tx(client, sid, 100)
        atk = [{"seq": i, "intended_label": "TAMPERED", "action": "tampered"} for i in range(1, 101)]
        _ingest_atk(client, sid, atk)
        rx = [{"seq": i, "verdict": "TAMPERED", "epoch": 1, "reason": "tag_mismatch"} for i in range(1, 101)]
        _ingest_rx_events(client, sid, rx)
        c = _counters(client)
        assert c["sent"] == 100
        assert c["received"] == 100
        assert c["authentic"] == 0
        assert c["tampered"] == 100
        assert c["received"] == c["authentic"] + c["tampered"] + c["replayed"] + c["spoofed"]
        assert c["false_accepts"] == 0
        # truth=TAMPERED + verdict=TAMPERED → no false reject (false reject requires truth=AUTHENTIC + verdict≠AUTHENTIC)
        assert c["false_rejects"] == 0
        _stop_all(client)

    def test_mixed_attack_invariants(self, client):
        _stop_all(client)
        sid = "exact-mixed-100"
        client.post("/api/transport/start", json={
            "session_id": sid, "source_type": "synthetic",
            "count": 100, "rate_pps": 100, "protect": True,
            "tx_port": 43550, "attacker_port": 43888,
            "attacker_control_port": 43889, "rx_port": 43999, "c2_port": 43551,
        })
        _ingest_tx(client, sid, 100)
        atk = []
        for i in range(1, 11):
            atk.append({"seq": i, "intended_label": "DROPPED", "action": "dropped"})
        for i in range(11, 21):
            atk.append({"seq": i, "intended_label": "TAMPERED", "action": "tampered"})
        for i in range(21, 31):
            atk.append({"seq": i, "intended_label": "REPLAYED", "action": "replayed"})
        for i in range(31, 101):
            atk.append({"seq": i, "intended_label": "AUTHENTIC", "action": "pass"})
        _ingest_atk(client, sid, atk)
        rx = []
        for i in range(11, 21):
            rx.append({"seq": i, "verdict": "TAMPERED", "epoch": 1, "reason": "tag_mismatch"})
        for i in range(21, 31):
            rx.append({"seq": i, "verdict": "REPLAYED", "epoch": 1, "reason": "duplicate_seq"})
        for i in range(31, 101):
            rx.append({"seq": i, "verdict": "AUTHENTIC", "epoch": 1, "reason": "ok"})
        _ingest_rx_events(client, sid, rx)
        c = _counters(client)
        assert c["sent"] == 100
        assert c["dropped"] == 10
        assert c["received"] == 90
        assert c["tampered"] == 10
        assert c["replayed"] == 10
        assert c["authentic"] == 70
        assert c["received"] + c["dropped"] == 100
        assert c["received"] == c["authentic"] + c["tampered"] + c["replayed"] + c["spoofed"]
        _stop_all(client)

    def test_deduplication_prevents_double_count(self, client):
        _stop_all(client)
        sid = "exact-dedup-100"
        client.post("/api/transport/start", json={
            "session_id": sid, "source_type": "synthetic",
            "count": 50, "rate_pps": 100, "protect": True,
            "tx_port": 44550, "attacker_port": 44888,
            "attacker_control_port": 44889, "rx_port": 44999, "c2_port": 44551,
        })
        _ingest_tx(client, sid, 50)
        rx1 = [{"seq": i, "verdict": "AUTHENTIC", "epoch": 1, "reason": "ok"} for i in range(1, 51)]
        rx2 = list(rx1)  # identical second batch
        _ingest_rx_events(client, sid, rx1)
        _ingest_rx_events(client, sid, rx2)  # second flush should be deduped
        c = _counters(client)
        assert c["received"] == 50, f"expected 50 got {c['received']}"
        assert c["authentic"] == 50
        _stop_all(client)


class TestSessionStateMachine:
    """State machine correctness: IDLE -> RUNNING -> IDLE."""

    def test_auto_return_to_idle_after_finish(self, client):
        sid = "exact-fsm-finish"
        r = client.post("/api/transport/start", json={
            "session_id": sid, "source_type": "synthetic",
            "count": 5, "rate_pps": 100, "protect": True,
            "tx_port": 45550, "attacker_port": 45888,
            "attacker_control_port": 45889, "rx_port": 45999, "c2_port": 45551,
        })
        assert r.status_code == 200
        time.sleep(2.0)
        stat = client.get("/api/transport/status").json()
        assert stat["state"] in ("idle", "stopping", "finished")
        _stop_all(client)

    def test_back_to_back_sessions_clean_counters(self, client):
        _stop_all(client)
        sid1 = "exact-back2back-1"
        client.post("/api/transport/start", json={
            "session_id": sid1, "source_type": "synthetic",
            "count": 20, "rate_pps": 100, "protect": True,
            "tx_port": 46550, "attacker_port": 46888,
            "attacker_control_port": 46889, "rx_port": 46999, "c2_port": 46551,
        })
        _ingest_tx(client, sid1, 20)
        _stop_all(client)
        assert transport_state.manager.active_session_id is None
        sid2 = "exact-back2back-2"
        client.post("/api/transport/start", json={
            "session_id": sid2, "source_type": "synthetic",
            "count": 20, "rate_pps": 100, "protect": True,
            "tx_port": 46550, "attacker_port": 46888,
            "attacker_control_port": 46889, "rx_port": 46999, "c2_port": 46551,
        })
        c = _counters(client)
        assert c["sent"] == 0, f"Session 2 should start at 0, got sent={c['sent']}"
        assert c["received"] == 0
        _stop_all(client)

    def test_session_filter_rejects_stale_ingest(self, client):
        _stop_all(client)
        sid_active = "exact-filter-active"
        sid_stale = "exact-filter-stale"
        client.post("/api/transport/start", json={
            "session_id": sid_active, "source_type": "synthetic",
            "count": 20, "rate_pps": 100, "protect": True,
            "tx_port": 47550, "attacker_port": 47888,
            "attacker_control_port": 47889, "rx_port": 47999, "c2_port": 47551,
        })
        _ingest_tx(client, sid_active, 50)
        # This should be ignored (stale session)
        r_stale = client.post("/api/ingest/stats", json={
            "role": "tx", "session_id": sid_stale, "sent": 999
        })
        assert r_stale.json()["status"] in ("ignored", "ok")
        c = _counters(client)
        assert c["sent"] == 50, f"expected 50 got sent={c['sent']}"
        _stop_all(client)
