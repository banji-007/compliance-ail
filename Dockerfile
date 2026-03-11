# Dockerfile  (root — AIL LangGraph Agent / Interceptor)
# Multi-stage build for the Python agent runtime.
#
# Stage 1 (builder): installs the full dependency set (langchain, langgraph,
#   openai, spiffe, prometheus-client, …) into an isolated prefix.
# Stage 2 (runtime): copies packages + application source; creates the
#   non-root ail-agent user used for privilege drop at runtime.
#
# Runtime behaviour handled by docker-compose (NOT baked into CMD):
#   - SPIRE workload socket wait loop  (requires live /tmp/spire-sockets)
#   - exec su -s /bin/bash ail-agent   (drop privileges before starting demo)
# These steps depend on runtime mounts and must stay in the compose command.

# ── Stage 1: dependency installer ──────────────────────────────────────────
FROM python:3.11-slim AS builder

WORKDIR /build

COPY requirements.txt .

RUN pip install --no-cache-dir --prefix=/install -r requirements.txt


# ── Stage 2: runtime image ──────────────────────────────────────────────────
FROM python:3.11-slim

WORKDIR /app

# Create non-root user for privilege drop at container startup.
# UID 1000 matches the SPIRE workload selector: unix:uid:1000
RUN useradd -u 1000 -m ail-agent

# Copy installed packages from builder.
COPY --from=builder /install /usr/local

# Bake application source into the image layer.
# Only the directories the agent runtime needs — keeps the image lean.
COPY interceptor/   ./interceptor/
COPY framework_integration/ ./framework_integration/
COPY ledger/        ./ledger/
