# decision_service/Dockerfile
# Multi-stage build for the AIL Decision Service (FastAPI / uvicorn).
#
# Build context is the repo root (see docker-compose.yml), not
# decision_service/ alone, because this service also needs ledger/ - the
# same module the agent's own Dockerfile used to copy before Phase 2 moved
# the ledger write out of the agent process entirely (D12).

# ── Stage 1: dependency installer ──────────────────────────────────────────
FROM python:3.11-slim AS builder

WORKDIR /build

COPY decision_service/requirements.txt .

RUN pip install --no-cache-dir --prefix=/install -r requirements.txt


# ── Stage 2: runtime image ──────────────────────────────────────────────────
FROM python:3.11-slim

WORKDIR /app

COPY --from=builder /install /usr/local

# Application source. ledger/ is the same module tree the agent used to
# carry; it now lives only here.
COPY decision_service/ ./
COPY ledger/ ./ledger/
# D22 (Phase 3b): the canonicalization rule and the signing call
# ledger/immudb_ledger.py uses to sign every record before it is written.
COPY provenance/ ./provenance/

EXPOSE 8010
EXPOSE 8000

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
CMD ["uvicorn", "main:app", "--host", "0.0.0.0", "--port", "8010", "--timeout-keep-alive", "65"]
