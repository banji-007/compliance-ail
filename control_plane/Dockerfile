# control_plane/Dockerfile
# Multi-stage build for the AIL Control Plane (FastAPI / uvicorn).
#
# Stage 1 (builder): installs Python dependencies into an isolated prefix so
#   only the compiled packages — not pip, setuptools, or build tooling — are
#   copied to the final image.
# Stage 2 (runtime): copies installed packages + application source; no
#   network access required at container start-up.
#
# D22 (Phase 3b): the build context is the repository root, not
# control_plane/, because this service also needs provenance/ - the
# canonicalization rule it shares with every other writer. Same reason
# decision_service/Dockerfile has built from the root since Phase 2.

# ── Stage 1: dependency installer ──────────────────────────────────────────
FROM python:3.11-slim AS builder

WORKDIR /build

COPY control_plane/requirements.txt .

RUN pip install --no-cache-dir --prefix=/install -r requirements.txt


# ── Stage 2: runtime image ──────────────────────────────────────────────────
FROM python:3.11-slim

WORKDIR /app

# Copy installed packages from builder (no pip / build tools in final image).
COPY --from=builder /install /usr/local

# Bake application source into the image layer.
# policy/ and the SQLite data volume are mounted at runtime by docker-compose.
COPY control_plane/ ./
COPY provenance/ ./provenance/

EXPOSE 8002

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
CMD ["uvicorn", "main:app", "--host", "0.0.0.0", "--port", "8002", "--timeout-keep-alive", "65"]
