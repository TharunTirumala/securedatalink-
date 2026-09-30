"""Transport control routes for starting, stopping, and inspecting UDP sessions."""

import secrets
import time
from typing import Any, Dict, List, Optional
from fastapi import APIRouter, Body, HTTPException, Path as FPath
from fastapi.responses import JSONResponse
from pydantic import BaseModel, Field

from dashboard.backend.transport_state import (
    get_session_counters,
    manager,
    reset_session_counters,
    session_stats_cache,
    store,
)
from securelink.sessions.models import SessionConfig

router = APIRouter(prefix="/api/transport", tags=["transport"])


@router.get("/role")
def get_role():
    import os
    role = os.environ.get("SECURELINK_ROLE", "full").lower()
    if role not in ("full", "sender", "receiver"):
        role = "full"
    return {"role": role}


@router.get("/status")
def get_transport_status():
    sid = manager.active_session_id
    cfg = store.load_config(sid) if sid else None
    st = store.load_state(sid) if sid else None
    uptime = round(time.time() - st.start_time, 1) if (st and st.start_time and not st.end_time) else 0.0
    counters = get_session_counters(sid)
    return {
        "state": manager.state_name,
        "session_id": sid,
        "uptime_sec": uptime,
        "seed": cfg.drone_seed if cfg else None,
        "protect": cfg.protect if cfg else True,
        "counters": counters,
    }


class StartTransportRequest(BaseModel):
    session_id: Optional[str] = None
    source_type: str = "drone"
    source_path: Optional[str] = None
    protect: bool = True
    rate_pps: int = Field(default=20, ge=1, le=200)
    count: Optional[int] = Field(default=100, ge=1)
    rekey_every: int = Field(default=100, ge=1)
    drone_seed: int = Field(default_factory=lambda: secrets.randbits(32) % 1_000_000)
    drone_route: str = "circle"
    attack_mode: str = "pass"
    attack_rate: float = Field(default=1.0, ge=0.0, le=1.0)
    attack_params: Dict[str, Any] = Field(default_factory=dict)
    attack_seed: int = 123
    tx_port: int = 14550
    attacker_port: int = 8888
    attacker_control_port: int = 8889
    rx_port: int = 9999
    c2_port: int = 14551
    keys_dir: str = "keys"
    dashboard_url: str = "http://127.0.0.1:8000"
    restart: bool = False


class AttackUpdateRequest(BaseModel):
    session_id: Optional[str] = None
    mode: str = "pass"
    rate: float = Field(default=1.0, ge=0.0, le=1.0)
    params: Dict[str, Any] = Field(default_factory=dict)


@router.post("/start")
def start_transport(req: StartTransportRequest):
    if manager.state_name == "running" or manager.active_session_id:
        if not req.restart:
            st = store.load_state(manager.active_session_id)
            return JSONResponse(
                status_code=409,
                content={
                    "detail": f"Session {manager.active_session_id} is currently running",
                    "session_id": manager.active_session_id,
                    "state": "running",
                    "started_at": st.start_time if st else None,
                },
            )

    sid = req.session_id or f"sess_{secrets.token_hex(4)}"
    data = req.model_dump()
    data["session_id"] = sid
    data.pop("restart", None)
    cfg = SessionConfig.from_dict(data)

    try:
        reset_session_counters(sid)
        st = manager.start_session(cfg, restart=req.restart)
        return {"status": "started", "session_id": sid, "state": st.to_dict()}
    except RuntimeError as e:
        return JSONResponse(
            status_code=409,
            content={
                "detail": str(e),
                "session_id": manager.active_session_id,
                "state": manager.state_name,
            },
        )
    except ValueError as e:
        raise HTTPException(status_code=422, detail=str(e))
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@router.post("/stop")
def stop_transport(payload: Dict[str, Any] = Body(default={})):
    sid = payload.get("session_id") or manager.active_session_id
    if not sid or manager.state_name in ("idle", "stopping") or not manager.active_session_id:
        if manager.active_session_id and manager.state_name != "idle":
            manager.stop_session(sid, mark_status="stopped")
        return {"status": "ok", "state": "idle", "session_id": sid}
    st = manager.stop_session(sid, mark_status="stopped")
    return {"status": "stopped", "session_id": sid, "state": "idle", "session_state": st.to_dict() if st else None}


@router.post("/attack")
def update_attack(req: AttackUpdateRequest):
    sid = req.session_id or manager.active_session_id
    if not sid:
        raise HTTPException(status_code=400, detail="No active session specified")
    ok = manager.set_attack(sid, mode=req.mode, rate=req.rate, params=req.params)
    if not ok:
        raise HTTPException(status_code=502, detail="Failed to contact attacker proxy control port")
    return {"status": "ok", "mode": req.mode, "rate": req.rate}


@router.get("/sessions")
def list_sessions():
    return store.list_sessions()


@router.get("/session/{session_id}")
def get_session(session_id: str = FPath(...)):
    cfg = store.load_config(session_id)
    st = store.load_state(session_id)
    if not cfg:
        raise HTTPException(status_code=404, detail=f"Session {session_id} not found")
    stats = session_stats_cache.get(session_id, {})
    return {
        "session_id": session_id,
        "config": cfg.to_dict(),
        "state": st.to_dict() if st else None,
        "stats": stats,
    }


@router.get("/session/{session_id}/reconcile")
def get_reconcile(session_id: str = FPath(...)):
    report = store.load_reconcile_report(session_id)
    if not report:
        s_dir = store.get_session_dir(session_id)
        if s_dir.exists():
            from securelink.sessions.reconcile import reconcile_session
            from securelink.sessions.telemetry_reconcile import reconcile_telemetry
            f_rep = reconcile_session(s_dir)
            t_rep = reconcile_telemetry(s_dir)
            report = {
                "session_id": session_id,
                "frame_reconciliation": f_rep,
                "telemetry_reconciliation": t_rep,
            }
            store.save_reconcile_report(session_id, report)
        else:
            raise HTTPException(status_code=404, detail="No reconciliation report found")
    return report


@router.get("/session/{session_id}/logs/{component}")
def get_log(session_id: str = FPath(...), component: str = FPath(...)):
    s_dir = store.get_session_dir(session_id)
    log_file = s_dir / "logs" / f"{component}.log"
    if not log_file.exists():
        return {"component": component, "lines": []}
    try:
        lines = log_file.read_text(encoding="utf-8").splitlines()
        return {"component": component, "lines": lines[-100:]}
    except Exception as e:
        return {"component": component, "lines": [], "error": str(e)}
