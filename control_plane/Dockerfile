# control_plane/Dockerfile
# Multi-stage build for the AIL Control Plane (FastAPI / uvicorn).
#
# Stage 1 (builder): installs Python dependencies into an isolated prefix so
#   only the compiled packages — not pip, setuptools, or build tooling — are
#   copied to the final image.
# Stage 2 (runtime): copies installed packages + application source; no
#   network access required at container start-up.

# ── Stage 1: dependency installer ──────────────────────────────────────────
FROM python:3.11-slim AS builder

WORKDIR /build

COPY requirements.txt .

RUN pip install --no-cache-dir --prefix=/install -r requirements.txt


# ── Stage 2: runtime image ──────────────────────────────────────────────────
FROM python:3.11-slim

WORKDIR /app

# Copy installed packages from builder (no pip / build tools in final image).
COPY --from=builder /install /usr/local

# Bake application source into the image layer.
# policy/ and the SQLite data volume are mounted at runtime by docker-compose.
COPY . .

EXPOSE 8002

CMD ["uvicorn", "main:app", "--host", "0.0.0.0", "--port", "8002"]
