#!/bin/bash
# SPIRE Agent Refresh Script (Automated Token Generation)
# Run from the project root: bash scripts/refresh-spire-agent.sh
# NOTE: This script restarts the token-generator and agent for fresh tokens

set -e
export MSYS_NO_PATHCONV=1

AGENT_VOLUME="compliance-ail_spire-agent-data"
TOKEN_VOLUME="compliance-ail_spire-tokens"

echo "=== SPIRE Agent Refresh (Automated Tokens) ==="

# 1. Stop dependent containers + agent
echo "Stopping spire-agent and dependents..."
docker compose stop langgraph-demo workload-registrar spire-agent token-generator 2>/dev/null || true

# 2. Remove stale agent data (expired SVID + old keys)
echo "Removing stale agent data volume..."
docker volume rm "$AGENT_VOLUME" 2>/dev/null && echo "  Removed." || echo "  Not found, skipping."

# 3. Remove stale token data to force fresh generation
echo "Removing stale token volume..."
docker volume rm "$TOKEN_VOLUME" 2>/dev/null && echo "  Removed." || echo "  Not found, skipping."

# 4. Bring stack back up (token-generator will run first, then agent)
echo "Restarting stack with fresh token generation..."
docker compose up -d token-generator spire-agent

echo ""
echo "=== Done. Monitor with: ==="
echo "  docker compose logs -f token-generator"
echo "  docker compose logs -f spire-agent"
echo "  docker compose logs -f workload-registrar"
echo ""
echo "New token will be automatically generated and injected."
