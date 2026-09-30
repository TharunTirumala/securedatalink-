"""FastAPI routes for File Lab dataset import, wire capture, edits, verification, and reconciliation."""

from typing import List, Dict, Any, Optional
from fastapi import APIRouter, HTTPException, Query, Request, Response, status
from pydantic import BaseModel, Field

from securelink.lab.store import (
    validate_file_id, load_edits, save_edits, delete_lab_file,
    load_wire_file, save_wire_file, generate_file_id,
    load_source_rows, load_manifest, save_source_rows, save_manifest,
    save_inferred_labels, load_inferred_labels,
)
from securelink.lab.service import (
    preview_dataset_content, import_dataset_file, generate_wire_capture,
    list_lab_files, get_lab_file_frames, get_frame_detail,
    verify_lab_file, get_last_verification,
)
from securelink.protocol.wire_file import read_wire_file, write_wire_file, MAX_FILE_BYTES
from securelink.simulation.manual.edits import create_edit_entry, apply_edits
from securelink.simulation.manual.diff import infer_labels
from securelink.sources.tabular import DatasetError

router = APIRouter(prefix="/api/lab", tags=["lab"])
MAX_DATASET_BYTES: int = 5 * 1024 * 1024


async def _read_text_body(request: Request, max_bytes: int) -> str:
    body = bytearray()
    async for chunk in request.stream():
        body.extend(chunk)
        if len(body) > max_bytes:
            raise HTTPException(
                status_code=status.HTTP_413_REQUEST_ENTITY_TOO_LARGE,
                detail=f"Payload exceeds limit of {max_bytes} bytes",
            )
    return body.decode("utf-8", errors="replace")


def _check_id(file_id: str) -> str:
    try:
        return validate_file_id(file_id)
    except ValueError:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=f"File ID '{file_id}' not found")


class GenerateFileRequest(BaseModel):
    name: Optional[str] = None
    count: int = Field(default=100, ge=10, le=5000)
    seed: Optional[int] = None
    rekey_every_packets: int = Field(default=25, ge=5, le=1000)


class EditOperationRequest(BaseModel):
    op: str = Field(..., pattern="^(tamper|replay|spoof|drop)$")
    params: Dict[str, Any] = Field(default_factory=dict)


class VerifyRequest(BaseModel):
    mode: str = Field(default="working", pattern="^(working|original)$")


@router.post("/datasets/preview")
async def api_preview_dataset(
    request: Request, format: str = Query(default="auto"), columns: Optional[str] = Query(default=None),
) -> Dict[str, Any]:
    text = await _read_text_body(request, max_bytes=MAX_DATASET_BYTES)
    cols = [c.strip() for c in columns.split(",")] if columns else None
    try:
        return preview_dataset_content(text, fmt=format, columns=cols)
    except DatasetError as e:
        raise HTTPException(status_code=status.HTTP_422_UNPROCESSABLE_ENTITY, detail=str(e))


@router.post("/datasets/import")
async def api_import_dataset(
    request: Request, name: Optional[str] = Query(default=None), format: str = Query(default="auto"),
    columns: Optional[str] = Query(default=None), rate_pps: int = Query(default=100, ge=1, le=2000),
    rekey_every_packets: int = Query(default=50, ge=5, le=1000),
) -> Dict[str, Any]:
    text = await _read_text_body(request, max_bytes=MAX_DATASET_BYTES)
    cols = [c.strip() for c in columns.split(",")] if columns else None
    try:
        fid, meta = import_dataset_file(
            text=text, name=name, fmt=format, columns=cols,
            rate_pps=rate_pps, rekey_every_packets=rekey_every_packets,
        )
        return {"file_id": fid, "meta": meta}
    except DatasetError as e:
        raise HTTPException(status_code=status.HTTP_422_UNPROCESSABLE_ENTITY, detail=str(e))


@router.post("/files/generate")
def api_generate_file(req: GenerateFileRequest) -> Dict[str, Any]:
    fid, meta = generate_wire_capture(
        count=req.count, seed=req.seed, rekey_every_packets=req.rekey_every_packets, name=req.name,
    )
    return {"file_id": fid, "meta": meta}


@router.post("/files/upload")
async def api_upload_file(
    request: Request, name: Optional[str] = Query(default=None), parent_id: Optional[str] = Query(default=None),
) -> Dict[str, Any]:
    text = await _read_text_body(request, max_bytes=MAX_FILE_BYTES)
    try:
        meta, entries, errors = read_wire_file(text)
    except Exception as exc:
        raise HTTPException(status_code=status.HTTP_422_UNPROCESSABLE_ENTITY, detail=str(exc))

    fid = generate_file_id()
    meta["file_id"] = fid
    if name:
        meta["name"] = name

    if parent_id:
        try:
            pid = _check_id(parent_id)
            meta["parent_id"] = pid
            _, p_entries, _ = read_wire_file(load_wire_file(pid))
            p_source, p_manifest = load_source_rows(pid), load_manifest(pid)
            if p_source:
                save_source_rows(fid, p_source)
            if p_manifest:
                save_manifest(fid, p_manifest)

            inferred, _ = infer_labels(p_entries, entries)
            save_inferred_labels(fid, inferred)
        except Exception:
            pass

    save_wire_file(fid, write_wire_file(meta, entries))
    return {"file_id": fid, "meta": meta, "warnings": errors}


@router.get("/files")
def api_list_files() -> List[Dict[str, Any]]:
    return list_lab_files()


@router.get("/files/{file_id}")
def api_get_file_info(file_id: str) -> Dict[str, Any]:
    fid = _check_id(file_id)
    try:
        text = load_wire_file(fid)
    except FileNotFoundError:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=f"File '{fid}' not found")
    meta, entries, _ = read_wire_file(text)
    inferred = load_inferred_labels(fid)
    return {
        "file_id": fid, "meta": meta, "frame_count": len(entries),
        "edits": load_edits(fid), "source_kind": meta.get("source_kind", "synthetic"),
        "inferred_labels": inferred, "parent_id": meta.get("parent_id"),
    }


@router.get("/files/{file_id}/source")
def api_get_source_rows(
    file_id: str, offset: int = Query(default=0, ge=0), limit: int = Query(default=100, ge=1, le=200),
) -> Dict[str, Any]:
    fid = _check_id(file_id)
    rows = load_source_rows(fid)
    return {"file_id": fid, "offset": offset, "limit": limit, "total": len(rows), "rows": rows[offset:offset+limit]}


@router.get("/files/{file_id}/frames")
def api_get_frames(
    file_id: str, view: str = Query(default="working", pattern="^(working|original)$"),
    offset: int = Query(default=0, ge=0), limit: int = Query(default=100, ge=1, le=5000),
) -> Dict[str, Any]:
    fid = _check_id(file_id)
    try:
        meta, rows, total = get_lab_file_frames(fid, view=view, offset=offset, limit=limit)
    except FileNotFoundError:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=f"File '{fid}' not found")
    return {"file_id": fid, "view": view, "offset": offset, "limit": limit, "total": total, "rows": rows}


@router.get("/files/{file_id}/frames/{eid}")
def api_get_frame_inspect(file_id: str, eid: str) -> Dict[str, Any]:
    fid = _check_id(file_id)
    try:
        return get_frame_detail(fid, eid)
    except (FileNotFoundError, KeyError) as exc:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=str(exc))


@router.post("/files/{file_id}/edits")
def api_add_edit(file_id: str, req: EditOperationRequest) -> Dict[str, Any]:
    fid = _check_id(file_id)
    try:
        edit_entry = create_edit_entry(req.op, req.params)
    except ValueError as exc:
        raise HTTPException(status_code=status.HTTP_422_UNPROCESSABLE_ENTITY, detail=str(exc))
    edits = load_edits(fid)
    edits.append(edit_entry)
    save_edits(fid, edits)
    return {"status": "added", "edit": edit_entry, "total_edits": len(edits)}


@router.delete("/files/{file_id}/edits/{edit_id}")
def api_remove_edit(file_id: str, edit_id: str) -> Dict[str, Any]:
    fid = _check_id(file_id)
    edits = load_edits(fid)
    new_edits = [e for e in edits if e.get("edit_id") != edit_id]
    if len(new_edits) == len(edits):
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=f"Edit '{edit_id}' not found")
    save_edits(fid, new_edits)
    return {"status": "removed", "edit_id": edit_id, "remaining_edits": len(new_edits)}


@router.post("/files/{file_id}/edits/reset")
def api_reset_edits(file_id: str) -> Dict[str, Any]:
    fid = _check_id(file_id)
    save_edits(fid, [])
    return {"status": "reset", "total_edits": 0}


@router.post("/files/{file_id}/verify")
def api_verify_file(file_id: str, req: VerifyRequest) -> Dict[str, Any]:
    fid = _check_id(file_id)
    try:
        return verify_lab_file(fid, mode=req.mode)
    except FileNotFoundError:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=f"File '{fid}' not found")
    except Exception as exc:
        import logging
        logging.getLogger("securelink.lab").exception("Verification error for file %s", fid)
        raise HTTPException(status_code=status.HTTP_422_UNPROCESSABLE_ENTITY, detail=f"Verification failed: {exc}")


@router.get("/files/{file_id}/verify/last")
def api_get_last_verify(
    file_id: str, mode: str = Query(default="working", pattern="^(working|original)$"),
    view: str = Query(default="rows", pattern="^(rows|clean|feed)$"),
    verdict: Optional[str] = Query(default=None),
    offset: int = Query(default=0, ge=0), limit: int = Query(default=100, ge=1, le=5000),
) -> Dict[str, Any]:
    fid = _check_id(file_id)
    try:
        v_data = get_last_verification(fid, mode=mode) or verify_lab_file(fid, mode=mode)
    except Exception as exc:
        raise HTTPException(status_code=status.HTTP_422_UNPROCESSABLE_ENTITY, detail=f"Verification failed: {exc}")
    if view == "clean":
        clean_rows = v_data.get("clean_output", [])
        return {
            "file_id": fid, "view": "clean", "total": len(clean_rows),
            "rows": clean_rows[offset:offset+limit], "delivery": v_data.get("delivery", {}),
        }
    if view == "feed":
        feed_data = v_data.get("feed") or {}
        feed_rows = feed_data.get("rows", [])
        if verdict:
            feed_rows = [r for r in feed_rows if str(r.get("verdict", "")).upper() == verdict.upper()]
        return {
            "file_id": fid, "mode": mode, "view": "feed", "total": len(feed_rows),
            "rows": feed_rows[offset:offset+limit], "counts": feed_data.get("counts", {}),
            "epoch_changes": feed_data.get("epoch_changes", []),
            "incidents": feed_data.get("incidents", []),
            "summary": v_data.get("summary", {}), "delivery": v_data.get("delivery", {}),
        }
    all_rows = v_data.get("rows", [])
    if verdict:
        all_rows = [r for r in all_rows if str(r.get("verdict", "")).upper() == verdict.upper()]
    return {
        "file_id": fid, "view": "rows", "total": len(all_rows),
        "rows": all_rows[offset:offset+limit], "summary": v_data.get("summary", {}),
    }


@router.get("/files/{file_id}/download")
def api_download_file(file_id: str, view: str = Query(default="working", pattern="^(working|original)$")) -> Response:
    fid = _check_id(file_id)
    try:
        raw_text = load_wire_file(fid)
    except FileNotFoundError:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=f"File '{fid}' not found")
    if view == "original":
        content = raw_text
    else:
        meta, entries, _ = read_wire_file(raw_text)
        working_entries, _ = apply_edits(entries, load_edits(fid))
        content = write_wire_file(meta, working_entries)
    return Response(
        content=content, media_type="text/plain; charset=utf-8",
        headers={"Content-Disposition": f'attachment; filename="securelink-{fid[:8]}-{view}.wire.txt"'},
    )


@router.delete("/files/{file_id}")
def api_delete_file(file_id: str) -> Dict[str, Any]:
    fid = _check_id(file_id)
    if not delete_lab_file(fid):
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=f"File '{fid}' not found")
    return {"status": "deleted", "file_id": fid}
