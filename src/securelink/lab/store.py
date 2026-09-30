"""Persistent filesystem storage and keystore manager for File Lab."""

import os
import re
import json
import uuid
from pathlib import Path
from typing import List, Dict, Any, Optional
from securelink.crypto.keystore import KeyStore

LAB_DATA_DIR: Path = Path("data/lab")
HEX_ID_REGEX = re.compile(r"^[a-f0-9]{32}$")


def validate_file_id(file_id: str) -> str:
    """Validate that file_id is strictly a 32-character hexadecimal string to prevent directory traversal."""
    if not isinstance(file_id, str) or not HEX_ID_REGEX.match(file_id):
        raise ValueError(f"Invalid file_id '{file_id}'. Must be exactly 32 hex characters.")
    return file_id


def generate_file_id() -> str:
    """Generate a secure, random 32-character hex file ID."""
    return uuid.uuid4().hex


def get_file_path(file_id: str) -> Path:
    fid = validate_file_id(file_id)
    p_txt = LAB_DATA_DIR / f"{fid}.wire.txt"
    if p_txt.is_file():
        return p_txt
    p_jsonl = LAB_DATA_DIR / f"{fid}.jsonl"
    if p_jsonl.is_file():
        return p_jsonl
    return p_txt


def get_source_path(file_id: str) -> Path:
    fid = validate_file_id(file_id)
    return LAB_DATA_DIR / f"{fid}.source.jsonl"


def get_manifest_path(file_id: str) -> Path:
    fid = validate_file_id(file_id)
    return LAB_DATA_DIR / f"{fid}.manifest.json"


def get_edits_path(file_id: str) -> Path:
    fid = validate_file_id(file_id)
    return LAB_DATA_DIR / f"{fid}.edits.json"


def save_wire_file(file_id: str, content: str) -> Path:
    LAB_DATA_DIR.mkdir(parents=True, exist_ok=True)
    p = get_file_path(file_id)
    p.write_text(content, encoding="utf-8")
    return p


def load_wire_file(file_id: str) -> str:
    p = get_file_path(file_id)
    if not p.is_file():
        raise FileNotFoundError(f"Lab file '{file_id}' not found")
    return p.read_text(encoding="utf-8")


def save_source_rows(file_id: str, rows: List[Dict[str, Any]]) -> Path:
    LAB_DATA_DIR.mkdir(parents=True, exist_ok=True)
    p = get_source_path(file_id)
    lines = [json.dumps(r, ensure_ascii=False) for r in rows]
    p.write_text("\n".join(lines) + ("\n" if lines else ""), encoding="utf-8")
    return p


def load_source_rows(file_id: str) -> List[Dict[str, Any]]:
    p = get_source_path(file_id)
    if not p.is_file():
        return []
    return [json.loads(line) for line in p.read_text(encoding="utf-8").splitlines() if line.strip()]


def save_manifest(file_id: str, manifest: Dict[str, Any]) -> Path:
    LAB_DATA_DIR.mkdir(parents=True, exist_ok=True)
    p = get_manifest_path(file_id)
    p.write_text(json.dumps(manifest, indent=2), encoding="utf-8")
    return p


def load_manifest(file_id: str) -> Dict[str, Any]:
    p = get_manifest_path(file_id)
    if not p.is_file():
        return {}
    try:
        return json.loads(p.read_text(encoding="utf-8"))
    except Exception:
        return {}


def save_edits(file_id: str, edits: List[Dict[str, Any]]) -> Path:
    LAB_DATA_DIR.mkdir(parents=True, exist_ok=True)
    p = get_edits_path(file_id)
    p.write_text(json.dumps(edits, indent=2), encoding="utf-8")
    return p


def load_edits(file_id: str) -> List[Dict[str, Any]]:
    p = get_edits_path(file_id)
    if not p.is_file():
        return []
    try:
        return json.loads(p.read_text(encoding="utf-8"))
    except Exception:
        return []


def get_inferred_labels_path(file_id: str) -> Path:
    fid = validate_file_id(file_id)
    return LAB_DATA_DIR / f"{fid}.inferred.json"


def save_inferred_labels(file_id: str, labels: Dict[str, str]) -> Path:
    LAB_DATA_DIR.mkdir(parents=True, exist_ok=True)
    p = get_inferred_labels_path(file_id)
    p.write_text(json.dumps(labels, indent=2), encoding="utf-8")
    return p


def load_inferred_labels(file_id: str) -> Dict[str, str]:
    p = get_inferred_labels_path(file_id)
    if not p.is_file():
        return {}
    try:
        return json.loads(p.read_text(encoding="utf-8"))
    except Exception:
        return {}


def delete_lab_file(file_id: str) -> bool:
    fid = validate_file_id(file_id)
    deleted = False
    for p in [
        get_file_path(fid),
        LAB_DATA_DIR / f"{fid}.jsonl",
        get_source_path(fid),
        get_manifest_path(fid),
        get_edits_path(fid),
        get_inferred_labels_path(fid),
    ]:
        if p.exists():
            p.unlink()
            deleted = True
    return deleted


_cached_lab_keystore: Optional[KeyStore] = None


def get_lab_keystore() -> KeyStore:
    """Return a persistent KeyStore for File Lab so files remain verifiable across server restarts."""
    global _cached_lab_keystore
    if _cached_lab_keystore is not None:
        return _cached_lab_keystore

    # 1. Try loading production keys/
    try:
        ks = KeyStore.load_from_dir("keys")
        if ks.master_secret and ks.is_sender_known(1):
            _cached_lab_keystore = ks
            return ks
    except Exception:
        pass

    # 2. Try loading or creating data/lab/lab_master.key
    LAB_DATA_DIR.mkdir(parents=True, exist_ok=True)
    master_key_file = LAB_DATA_DIR / "lab_master.key"
    if master_key_file.exists():
        master_secret = master_key_file.read_bytes()
    else:
        master_secret = os.urandom(32)
        master_key_file.write_bytes(master_secret)
        try:
            os.chmod(master_key_file, 0o600)
        except OSError:
            pass

    ks = KeyStore.generate_ephemeral(sender_ids=[1, 2])
    ks.master_secret = master_secret
    _cached_lab_keystore = ks
    return ks
