"""Ingest endpoints receiving stats, events, and telemetry from transport processes."""

import os
from typing import Any, Dict, List, Optional
from fastapi import APIRouter, Body, Request, HTTPException
from dashboard.backend.transport_state import (
    get_live_state,
    ingest_lock,
    record_attacker_actions,
    record_attacker_stats,
    record_rx_events,
    record_rx_stats,
    record_tx_stats,
    session_stats_cache,
    update_c2_telemetry,
    update_drone_telemetry,
    manager,
)

router = APIRouter(prefix="/api/ingest", tags=["ingest"])


def _check_auth(request: Request, payload: Dict[str, Any]):
    if not manager.active_token:
        return
    req_token = request.headers.get("x-securelink-token") or payload.get("token")
    enforce = os.environ.get("SECURELINK_REQUIRE_INGEST_AUTH") == "1"
    if req_token is not None and req_token != manager.active_token:
        raise HTTPException(status_code=401, detail="Invalid session token")
    if enforce and (not req_token or req_token != manager.active_token):
        raise HTTPException(status_code=401, detail="Missing or invalid session token")


@router.post("/stats")
def ingest_stats(request: Request, payload: Dict[str, Any] = Body(...)):
    _check_auth(request, payload)
    comp = payload.get("component") or payload.get("role", "unknown")
    sid = payload.get("session_id", "default")
    active_sid = manager.active_session_id
    if active_sid and sid != active_sid:
        return {"status": "ignored", "reason": "session_mismatch"}
    st = payload.get("stats") or {}

    if comp == "tx" or "sent" in payload:
        sent_cnt = payload.get("sent", st.get("sent", 0))
        ep = payload.get("epoch", st.get("epoch", 1))
        rate = payload.get("rate", st.get("rate", 0.0))
        record_tx_stats(sid, sent_cnt, ep, rate)
        if not st:
            st = {"sent": sent_cnt, "epoch": ep, "rate": rate}
        st.setdefault("sent", sent_cnt)

    elif comp == "rx" or "counts" in payload:
        counts = payload.get("counts") or st.get("counts") or {}
        tot = payload.get("received", st.get("received", counts.get("total", 0)))
        record_rx_stats(sid, counts, total_received=tot)
        if not st:
            st = {
                "received": tot, "counts": counts,
                "authentic": counts.get("AUTHENTIC", 0),
                "tampered": counts.get("TAMPERED", 0),
                "replayed": counts.get("REPLAYED", 0),
                "spoofed": counts.get("SPOOFED", 0),
            }
        else:
            st.setdefault("received", tot)
            st.setdefault("counts", counts)
            st.setdefault("authentic", counts.get("AUTHENTIC", 0))
            st.setdefault("tampered", counts.get("TAMPERED", 0))
            st.setdefault("replayed", counts.get("REPLAYED", 0))
            st.setdefault("spoofed", counts.get("SPOOFED", 0))

    elif comp == "attacker":
        record_attacker_stats(sid, st or payload)

    with ingest_lock:
        if sid not in session_stats_cache:
            session_stats_cache[sid] = {}
        session_stats_cache[sid][comp] = st

    return {"status": "ok"}


@router.post("/events")
def ingest_events(request: Request, payload: Dict[str, Any] = Body(...)):
    _check_auth(request, payload)
    from dashboard.backend import server
    sid = payload.get("session_id", "default")
    active_sid = manager.active_session_id
    if active_sid and sid != active_sid:
        return {"status": "ignored", "reason": "session_mismatch"}
    events = payload.get("events", [])
    if events:
        record_rx_events(sid, events)
        with server.buffer_lock:
            for ev in events:
                server.event_buffer.append(ev)
    return {"status": "ok", "count": len(events)}


@router.post("/attacker_actions")
def ingest_attacker_actions(request: Request, payload: Dict[str, Any] = Body(...)):
    _check_auth(request, payload)
    sid = payload.get("session_id", "default")
    active_sid = manager.active_session_id
    if active_sid and sid != active_sid:
        return {"status": "ignored", "reason": "session_mismatch"}
    actions = payload.get("actions", [])
    if actions:
        record_attacker_actions(sid, actions)
    return {"status": "ok", "count": len(actions)}


@router.post("/telemetry")
def ingest_telemetry(request: Request, payload: Dict[str, Any] = Body(...)):
    _check_auth(request, payload)
    active_sid = manager.active_session_id
    sid = payload.get("session_id")
    if active_sid and sid and sid != active_sid:
        return {"status": "ignored", "reason": "session_mismatch"}
    comp = payload.get("component")
    telem = payload.get("telemetry")
    samples = payload.get("samples")

    if samples:
        for s in samples:
            role = s.get("role")
            if role == "drone" or not comp:
                update_drone_telemetry(s)
            elif role == "c2":
                update_c2_telemetry(s)
    elif telem:
        if comp == "c2":
            update_c2_telemetry(telem)
        else:
            update_drone_telemetry(telem)

    return {"status": "ok"}


@router.get("/live")
def get_live():
    return get_live_state()
