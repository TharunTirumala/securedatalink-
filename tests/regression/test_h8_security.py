"""H8 regression: Security hygiene tests.

Verifies:
- Path traversal in SessionStore is blocked with ValueError.
- Non-existent session reads do not create directory on disk.
- Ingest endpoints reject requests carrying an invalid session token.
"""

import pytest
from pathlib import Path
from fastapi.testclient import TestClient
from securelink.sessions.store import SessionStore
from dashboard.backend.server import app
from dashboard.backend.transport_state import manager


def test_session_store_path_traversal_blocked(tmp_path):
    """Path traversal sequences in session_id must raise ValueError."""
    store = SessionStore(base_dir=tmp_path)

    traversal_ids = [
        "../escaped",
        "..\\escaped",
        "foo/bar",
        "foo\\bar",
        "/absolute",
        "C:\\Windows",
        "...",
        "has spaces",
        "semi;colon",
        "",
    ]
    for bad_id in traversal_ids:
        with pytest.raises(ValueError):
            store.get_session_dir(bad_id)


def test_session_store_read_does_not_create_empty_dir(tmp_path):
    """Reading state or config for non-existent session must not create folder on disk."""
    store = SessionStore(base_dir=tmp_path)
    res = store.load_config("nonexistent_session_123")
    assert res is None
    assert not (tmp_path / "nonexistent_session_123").exists()

    res_st = store.load_state("nonexistent_session_456")
    assert res_st is None
    assert not (tmp_path / "nonexistent_session_456").exists()


def test_ingest_token_validation_rejects_bad_token():
    """Ingest endpoint rejects payloads with invalid X-SecureLink-Token when session active."""
    client = TestClient(app)
    # Simulate an active session with a token
    manager.active_token = "secret-token-xyz"
    manager.active_session_id = "test-token-sess"

    try:
        # Request with wrong token must be rejected with 401
        res = client.post(
            "/api/ingest/stats",
            json={"session_id": "test-token-sess", "role": "tx", "sent": 10},
            headers={"X-SecureLink-Token": "wrong-token-abc"},
        )
        assert res.status_code == 401

        # Request with correct token succeeds
        res_ok = client.post(
            "/api/ingest/stats",
            json={"session_id": "test-token-sess", "role": "tx", "sent": 10},
            headers={"X-SecureLink-Token": "secret-token-xyz"},
        )
        assert res_ok.status_code == 200
    finally:
        manager.active_token = None
        manager.active_session_id = None
