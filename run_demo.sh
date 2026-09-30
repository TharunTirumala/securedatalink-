#!/usr/bin/env bash
set -e

echo "============================================================"
echo "     SECURELINK: CYBER-SECURE TACTICAL DATALINK DEMO"
echo "============================================================"

# Check if keys exist
if [ ! -f "keys/shared_aes256.key" ]; then
    echo "[*] Generating cryptographic keys..."
    python3 scripts/gen_keys.py keys
fi

echo "[*] Launching browser and starting server on http://127.0.0.1:8000 ..."

# Attempt to open browser in background based on OS
if command -v xdg-open > /dev/null; then
    xdg-open "http://127.0.0.1:8000" &
elif command -v open > /dev/null; then
    open "http://127.0.0.1:8000" &
fi

python3 -m uvicorn dashboard.backend.server:app --host 127.0.0.1 --port 8000
