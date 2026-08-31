# verifier/Dockerfile
#
# D35 (Phase 3c-3c): the build context is the repository root, not verifier/,
# because this service now writes a ledger record of its own (the fault
# record) and therefore needs provenance/ - the canonicalization rule it
# shares with every other writer. Same reason control_plane/Dockerfile and
# decision_service/Dockerfile already build from the root.
FROM python:3.11-slim
WORKDIR /app

COPY verifier/requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY verifier/main.py .
COPY provenance/ ./provenance/

# Non-root user; verifier-state volume is owned by root at mount time,
# so the container runs as root to write the state file. In a hardened
# deployment replace with a named uid and chown the volume at init.
EXPOSE 8003

CMD ["python", "-m", "uvicorn", "main:app", "--host", "0.0.0.0", "--port", "8003", "--workers", "1"]
