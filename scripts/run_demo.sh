#!/usr/bin/env bash
# SecureLink One-Click Demo Runner
echo "Starting SecureLink C2 Portal & Transport Gateway..."
python -m uvicorn dashboard.backend.server:app --host 127.0.0.1 --port 8000
