"""FastAPI backend server providing REST control APIs, WebSocket telemetry streaming, and UI hosting."""

import asyncio
import os
import secrets
import threading
from contextlib import asynccontextmanager
from pathlib import Path
from typing import List, Dict, Any, Optional, Set, Union
from fastapi import FastAPI, WebSocket, WebSocketDisconnect, Query
from fastapi.middleware.cors import CORSMiddleware
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel, Field, model_validator

from securelink.core.config import AppConfig, AttackConfig, SimulationConfig
from securelink.core.types import Event
from securelink.simulation.runner import SimulationRunner, SimulationStats
from securelink.audit.threat_log import ThreatLogger
from securelink.pipeline.operator_state import OperatorState
from dashboard.backend.mock_feed import generate_mock_events


class AttackProbabilities(BaseModel):
    tamper: float = Field(default=0.10, ge=0.0, le=1.0)
    replay: float = Field(default=0.10, ge=0.0, le=1.0)
    spoof: float = Field(default=0.05, ge=0.0, le=1.0)
    drop: float = Field(default=0.05, ge=0.0, le=1.0)


class RunRequest(BaseModel):
    count: Optional[int] = None
    rate_pps: Optional[int] = None
    rate_hz: Optional[int] = None
    duration_s: Optional[float] = None
    seed: Optional[Union[int, str]] = None
    run_id: Optional[str] = None
    tamper: Optional[float] = None
    tamper_prob: Optional[float] = None
    replay: Optional[float] = None
    replay_prob: Optional[float] = None
    spoof: Optional[float] = None
    spoof_prob: Optional[float] = None
    drop: Optional[float] = None
    drop_prob: Optional[float] = None
    attacks: Optional[Union[AttackProbabilities, Dict[str, float]]] = None

    @model_validator(mode="after")
    def validate_attack_sum(self):
        raw = self.model_dump()
        d = dict(raw)
        if self.attacks:
            d.update(self.attacks.model_dump() if isinstance(self.attacks, AttackProbabilities) else self.attacks)

        def gp(k: str, def_v: float) -> float:
            v = d.get(f"{k}_prob") if d.get(f"{k}_prob") is not None else d.get(k)
            return float(v) if v is not None else def_v

        tot = round(gp("tamper", 0.10) + gp("replay", 0.10) + gp("spoof", 0.05) + gp("drop", 0.05), 6)
        if tot > 1.0:
            raise ValueError(f"Sum of attack probabilities ({tot}) cannot exceed 1.0")
        return self


class ConnectionManager:
    def __init__(self):
        self.active_connections: Set[WebSocket] = set()
        self.lock = asyncio.Lock()

    async def connect(self, websocket: WebSocket):
        async with self.lock:
            self.active_connections.add(websocket)

    async def disconnect(self, websocket: WebSocket):
        async with self.lock:
            self.active_connections.discard(websocket)

    async def broadcast_batch(self, batch: Dict[str, Any]):
        if not batch:
            return
        async with self.lock:
            conns = list(self.active_connections)
        dead = set()
        for ws in conns:
            try:
                await asyncio.wait_for(ws.send_json(batch), timeout=0.5)
            except Exception:
                dead.add(ws)
        if dead:
            async with self.lock:
                self.active_connections.difference_update(dead)


manager = ConnectionManager()
config = AppConfig.load()
operator_state = OperatorState()
threat_logger = ThreatLogger(config.threat_log_path, operator_state=operator_state)

runner_lock = threading.Lock()
active_runner: Optional[SimulationRunner] = None
runner_thread: Optional[threading.Thread] = None

event_buffer: List[Dict[str, Any]] = []
buffer_lock = threading.Lock()

current_run_seed: Optional[int] = None
current_run_id: Optional[str] = None


def on_runner_event(event: Event):
    with buffer_lock:
        if event.run_id == current_run_id:
            event_buffer.append(event.to_dict())


async def event_broadcaster_task():
    while True:
        await asyncio.sleep(0.10)
        batch: List[Dict[str, Any]] = []
        with buffer_lock:
            if event_buffer:
                batch = list(event_buffer)
                event_buffer.clear()
        if batch:
            payload = {"seed": current_run_seed, "run_id": current_run_id, "events": batch}
            await manager.broadcast_batch(payload)


@asynccontextmanager
async def lifespan(app: FastAPI):
    broadcaster = asyncio.create_task(event_broadcaster_task())
    yield
    broadcaster.cancel()
    with runner_lock:
        if active_runner:
            active_runner.stop()


from dashboard.backend.routes_rekey import router as rekey_router
from dashboard.backend.routes_lab import router as lab_router
from dashboard.backend.routes_transport import router as transport_router
from dashboard.backend.routes_ingest import router as ingest_router
from fastapi import Request
from fastapi.responses import JSONResponse

app = FastAPI(title="SecureLink C2 Server", version="1.0.0", lifespan=lifespan)
app.add_middleware(CORSMiddleware, allow_origins=["*"], allow_methods=["*"], allow_headers=["*"])


@app.middleware("http")
async def security_hardening_middleware(request: Request, call_next):
    token = os.environ.get("SECURELINK_API_TOKEN")
    if token and request.method in ("POST", "DELETE", "PUT", "PATCH"):
        if request.headers.get("X-SecureLink-Token") != token:
            return JSONResponse(status_code=401, content={"detail": "Invalid or missing X-SecureLink-Token"})
    return await call_next(request)


app.include_router(rekey_router)
app.include_router(lab_router)
app.include_router(transport_router)
app.include_router(ingest_router)


@app.post("/api/run")
def api_run(req: RunRequest):
    global active_runner, runner_thread, current_run_seed, current_run_id
    with runner_lock:
        if active_runner and active_runner.is_running:
            active_runner.stop()
            if runner_thread:
                runner_thread.join(timeout=1.0)

        threat_logger.clear()
        with buffer_lock:
            event_buffer.clear()

        raw_dict = req.model_dump(exclude_unset=False)
        sim_cfg = SimulationConfig.from_dict(raw_dict)
        atk_dict = dict(raw_dict)
        if req.attacks:
            atk_dict.update(req.attacks.model_dump() if isinstance(req.attacks, AttackProbabilities) else req.attacks)
        atk_cfg = AttackConfig.from_dict(atk_dict)

        resolved_seed = sim_cfg.seed if sim_cfg.seed is not None else secrets.randbits(32)
        resolved_run_id = req.run_id or secrets.token_hex(4)
        current_run_seed = resolved_seed
        current_run_id = resolved_run_id

        runner = SimulationRunner(
            config=config,
            event_callback=on_runner_event,
            threat_logger=threat_logger,
            operator_state=operator_state,
        )
        active_runner = runner

        def worker():
            runner.run(
                count=sim_cfg.count,
                rate_pps=sim_cfg.rate_pps,
                seed=resolved_seed,
                attack_config=atk_cfg,
                run_id=resolved_run_id,
            )

        runner_thread = threading.Thread(target=worker, daemon=True)
        runner_thread.start()

    return {
        "status": "started",
        "count": sim_cfg.count,
        "rate_pps": sim_cfg.rate_pps,
        "seed": resolved_seed,
        "run_id": resolved_run_id,
    }


@app.post("/api/stop")
def api_stop():
    with runner_lock:
        if active_runner:
            active_runner.stop()
    return {"status": "stopped"}


@app.get("/api/stats")
def api_stats():
    with runner_lock:
        if active_runner:
            return active_runner.stats.to_dict()
    return SimulationStats().to_dict()


@app.get("/api/incidents")
def api_incidents(limit: int = Query(default=50, ge=1, le=500)):
    return threat_logger.get_latest_incidents(limit=limit)


@app.post("/api/rekey")
def api_rekey():
    operator_state.request_rekey()
    return {"status": "rekey_requested"}

@app.post("/api/block/{sender_id}")
def api_block(sender_id: int):
    operator_state.block_sender(sender_id)
    return {"status": "blocked", "sender_id": sender_id}

@app.post("/api/unblock/{sender_id}")
def api_unblock(sender_id: int):
    operator_state.unblock_sender(sender_id)
    return {"status": "unblocked", "sender_id": sender_id}

@app.post("/api/incidents/{incident_id}/ack")
def api_ack_incident(incident_id: str):
    operator_state.ack_incident(incident_id)
    return {"status": "acknowledged", "incident_id": incident_id}


@app.get("/api/state")
def api_state():
    with runner_lock:
        is_run = bool(active_runner and active_runner.is_running)
    from dashboard.backend.transport_state import manager as tr_mgr
    if tr_mgr.state_name == "running":
        is_run = True
    return operator_state.to_dict(is_running=is_run, run_id=current_run_id or tr_mgr.active_session_id)


@app.websocket("/ws/events")
async def websocket_events(websocket: WebSocket, mock: int = Query(default=0)):
    await websocket.accept()
    if mock == 1:
        try:
            batch = []
            async for event in generate_mock_events(rate_pps=20):
                batch.append(event)
                if len(batch) >= 2:
                    await websocket.send_json({"seed": 42, "events": batch})
                    batch = []
        except Exception:
            pass
        return

    await manager.connect(websocket)
    try:
        while True:
            await websocket.receive_text()
    except (WebSocketDisconnect, asyncio.CancelledError):
        pass
    finally:
        await manager.disconnect(websocket)


frontend_dir = Path(__file__).resolve().parents[1] / "frontend"
if frontend_dir.exists():
    app.mount("/", StaticFiles(directory=str(frontend_dir), html=True), name="frontend")
