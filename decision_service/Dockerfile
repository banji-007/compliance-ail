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

CMD ["uvicorn", "main:app", "--host", "0.0.0.0", "--port", "8010"]
