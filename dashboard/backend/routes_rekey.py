"""FastAPI route handlers for Dynamic Re-Keying observability and controls."""

from typing import List, Dict, Any, Optional
from fastapi import APIRouter, HTTPException, Query, status
from pydantic import BaseModel, Field

router = APIRouter(prefix="/api/rekey", tags=["rekey"])


class RekeyConfigPatch(BaseModel):
    rekey_every_packets: int = Field(..., ge=10, le=10000, description="Packets per epoch (10..10000)")


class ReplayOldEpochRequest(BaseModel):
    epochs_back: int = Field(..., ge=1, le=5, description="Epochs in the past to replay (1..5)")


@router.get("/state")
def get_rekey_state() -> Dict[str, Any]:
    """Return live epoch, key ID, grace window, and rotation state."""
    import dashboard.backend.server as srv

    runner = srv.active_runner
    is_running = bool(runner and runner.is_running)
    cur_epoch = srv.operator_state.current_epoch
    grace_epochs = srv.config.simulation.rekey_grace_epochs
    rekey_interval = srv.config.simulation.rekey_every_packets

    accepted = [cur_epoch - i for i in range(grace_epochs + 1) if (cur_epoch - i) >= 1]

    packets_in_epoch = 0
    kid = "00000000"
    if runner:
        rekey_interval = runner.config.simulation.rekey_every_packets
        ep_data = runner.stats.epoch_stats.get(cur_epoch, {})
        packets_in_epoch = ep_data.get("packets", 0)
        kid = runner.keystore.get_key_id(cur_epoch, runner.config.simulation.sender_id)

    return {
        "epoch": cur_epoch,
        "rekeys": srv.operator_state.total_rekeys,
        "packets_in_epoch": packets_in_epoch,
        "rekey_every_packets": rekey_interval,
        "grace_epochs": grace_epochs,
        "accepted_epochs": accepted,
        "key_id": kid,
        "running": is_running,
    }


@router.get("/history")
def get_rekey_history(limit: int = Query(default=50, ge=1, le=200)) -> List[Dict[str, Any]]:
    """Return bounded audit trail of re-key transitions."""
    import dashboard.backend.server as srv
    return srv.operator_state.get_rekey_history(limit=limit)


@router.get("/epochs")
def get_epoch_stats(limit: int = Query(default=20, ge=1, le=50)) -> List[Dict[str, Any]]:
    """Return per-epoch operational metrics with active/grace/expired status."""
    import dashboard.backend.server as srv

    runner = srv.active_runner
    cur_epoch = srv.operator_state.current_epoch
    grace_epochs = srv.config.simulation.rekey_grace_epochs

    known_epochs = set()
    if runner and runner.stats.epoch_stats:
        known_epochs.update(runner.stats.epoch_stats.keys())
    known_epochs.add(cur_epoch)

    sorted_epochs = sorted(list(known_epochs), reverse=True)[:limit]
    result = []
    for ep in sorted_epochs:
        if ep == cur_epoch:
            ep_status = "active"
        elif cur_epoch - grace_epochs <= ep < cur_epoch:
            ep_status = "grace"
        else:
            ep_status = "expired"

        stat = runner.stats.epoch_stats.get(ep, {}) if runner else {}
        result.append({
            "epoch": ep,
            "status": ep_status,
            "packets": stat.get("packets", 0),
            "authentic": stat.get("authentic", 0),
            "rejected": stat.get("rejected", 0),
            "first_ts": stat.get("first_ts"),
            "last_ts": stat.get("last_ts"),
        })
    return result


@router.post("/config")
def update_rekey_config(req: RekeyConfigPatch) -> Dict[str, Any]:
    """Dynamically set the packet rotation interval bounded within 10..10000."""
    import dashboard.backend.server as srv

    srv.config.simulation.rekey_every_packets = req.rekey_every_packets
    runner = srv.active_runner
    if runner:
        runner.set_rekey_interval(req.rekey_every_packets)

    return {
        "status": "updated",
        "rekey_every_packets": req.rekey_every_packets,
    }


@router.post("/replay-old")
def replay_old_epoch(req: ReplayOldEpochRequest) -> Dict[str, Any]:
    """Inject an authentic frame from a prior epoch into the active simulation."""
    import dashboard.backend.server as srv

    runner = srv.active_runner
    if not runner or not runner.is_running:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail="Simulation is not running. Start a simulation first to capture and replay frames.",
        )

    success = runner.inject_replay_old_epoch(req.epochs_back)
    if not success:
        target = srv.operator_state.current_epoch - req.epochs_back
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail=f"No authentic frame captured yet for epoch {target} (epochs_back={req.epochs_back}).",
        )

    return {
        "status": "queued",
        "epochs_back": req.epochs_back,
    }
