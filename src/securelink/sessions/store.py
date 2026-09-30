"""Filesystem storage manager for session directories and artifact logs."""

import json
import re
from pathlib import Path
from typing import Any, Dict, List, Optional
from securelink.sessions.models import SessionConfig, SessionState


class SessionStore:
    """Manages files and logs under data/sessions/<session_id>/."""

    def __init__(self, base_dir: Optional[Path] = None):
        if base_dir is None:
            # Default to repo_root / "data" / "sessions"
            self.base_dir = Path(__file__).resolve().parents[3] / "data" / "sessions"
        else:
            self.base_dir = Path(base_dir)
        self.base_dir.mkdir(parents=True, exist_ok=True)

    def get_session_dir(self, session_id: str, create: bool = True) -> Path:
        if not session_id or not re.match(r"^[a-zA-Z0-9_\-]+$", str(session_id)):
            raise ValueError(f"Invalid or unsafe session_id: {session_id!r}")
        s_dir = (self.base_dir / session_id).resolve()
        base_resolved = self.base_dir.resolve()
        try:
            s_dir.relative_to(base_resolved)
        except ValueError:
            raise ValueError(f"Path traversal detected in session_id: {session_id!r}")

        if create:
            s_dir.mkdir(parents=True, exist_ok=True)
            (s_dir / "logs").mkdir(exist_ok=True)
        return s_dir

    def save_config(self, config: SessionConfig) -> Path:
        s_dir = self.get_session_dir(config.session_id, create=True)
        config_file = s_dir / "config.json"
        config_file.write_text(json.dumps(config.to_dict(), indent=2), encoding="utf-8")
        return config_file

    def load_config(self, session_id: str) -> Optional[SessionConfig]:
        try:
            config_file = self.get_session_dir(session_id, create=False) / "config.json"
        except ValueError:
            return None
        if not config_file.exists():
            return None
        data = json.loads(config_file.read_text(encoding="utf-8"))
        return SessionConfig.from_dict(data)

    def save_state(self, state: SessionState) -> Path:
        s_dir = self.get_session_dir(state.session_id, create=True)
        state_file = s_dir / "state.json"
        state_file.write_text(json.dumps(state.to_dict(), indent=2), encoding="utf-8")
        return state_file

    def load_state(self, session_id: str) -> Optional[SessionState]:
        try:
            state_file = self.get_session_dir(session_id, create=False) / "state.json"
        except ValueError:
            return None
        if not state_file.exists():
            return None
        data = json.loads(state_file.read_text(encoding="utf-8"))
        return SessionState.from_dict(data)

    def save_reconcile_report(self, session_id: str, report: Dict[str, Any]) -> Path:
        s_dir = self.get_session_dir(session_id, create=True)
        report_file = s_dir / "reconcile_report.json"
        report_file.write_text(json.dumps(report, indent=2), encoding="utf-8")
        return report_file

    def load_reconcile_report(self, session_id: str) -> Optional[Dict[str, Any]]:
        try:
            report_file = self.get_session_dir(session_id, create=False) / "reconcile_report.json"
        except ValueError:
            return None
        if not report_file.exists():
            return None
        return json.loads(report_file.read_text(encoding="utf-8"))

    def list_sessions(self) -> List[Dict[str, Any]]:
        sessions = []
        for s_dir in sorted(self.base_dir.iterdir(), key=lambda p: p.stat().st_mtime, reverse=True):
            if s_dir.is_dir() and (s_dir / "config.json").exists():
                cfg = self.load_config(s_dir.name)
                st = self.load_state(s_dir.name)
                sessions.append({
                    "session_id": s_dir.name,
                    "status": st.status if st else "unknown",
                    "start_time": st.start_time if st else None,
                    "protect": cfg.protect if cfg else None,
                    "source_type": cfg.source_type if cfg else None,
                    "attack_mode": cfg.attack_mode if cfg else None,
                })
        return sessions
