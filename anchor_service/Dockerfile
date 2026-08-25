# anchor_service/Dockerfile
# D23 (Phase 3b): the periodic Rekor anchoring job.
#
# Build context is the repo root (see docker-compose.yml), because this
# service needs provenance/ - the canonicalization rules it shares with the
# services that write and export records.

FROM python:3.11-slim AS builder
WORKDIR /build
COPY anchor_service/requirements.txt .
RUN pip install --no-cache-dir --prefix=/install -r requirements.txt

FROM python:3.11-slim
WORKDIR /app
COPY --from=builder /install /usr/local
COPY anchor_service/ ./
COPY provenance/ ./provenance/

# No port. This is a loop, not a server: nothing calls it, it calls out.
CMD ["python", "main.py"]
