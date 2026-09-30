@echo off
echo ============================================================
echo      SECURELINK: CYBER-SECURE TACTICAL DATALINK DEMO
echo ============================================================

REM Check if keys exist, if not generate them
if not exist "keys\shared_aes256.key" (
    echo [*] Generating cryptographic keys and certificates...
    python scripts\gen_keys.py keys
)

echo [*] Starting FastAPI C2 Server on http://127.0.0.1:8000 ...
start "" "http://127.0.0.1:8000"

python -m uvicorn dashboard.backend.server:app --host 127.0.0.1 --port 8000
