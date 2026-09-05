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

# P3c3d-9 (Phase 3c-3d): --timeout-keep-alive is stated rather than left to
# uvicorn's 5s default.
#
# The intermittent "Server disconnected without sending a response" that
# survived three passes is an HTTP keep-alive race, demonstrated causally by
# the red team by moving this setting and watching the failure window move
# with it. The integration tests hold module-level pooled httpx clients;
# httpx expires an idle pooled connection at 5.0s, and uvicorn closed an idle
# keep-alive connection at 5.0s, so a request landing on a pooled connection
# at exactly that moment saw the socket close instead of a response - with
# nothing in the server log, because closing an idle connection is normal
# operation, and with ImmuDB uninvolved. Swept against /health on one pooled
# client: 2 of 6 failures at a 5.00s gap and 0 of 6 at 4.99s and 5.01s; moved
# to 2s, the window moved to 2.00s.
#
# 65s so the client always drops an idle connection first and the two sides
# never expire together.
CMD ["python", "-m", "uvicorn", "main:app", "--host", "0.0.0.0", "--port", "8003", "--workers", "1", "--timeout-keep-alive", "65"]
