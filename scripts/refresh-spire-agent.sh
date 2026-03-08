#!/bin/bash
# Refresh the SPIRE agent when its join token is exhausted or SVID has expired.
# Run from the project root: bash scripts/refresh-spire-agent.sh

set -e
export MSYS_NO_PATHCONV=1

SERVER_CONTAINER="compliance-ail-spire-server-1"
AGENT_CONF="spire/agent/agent.conf"
AGENT_VOLUME="compliance-ail_spire-agent-data"

echo "=== SPIRE Agent Refresh ==="

# 1. Generate a new join token (24h TTL)
echo "Generating new join token..."
RAW=$(docker exec "$SERVER_CONTAINER" \
    /opt/spire/bin/spire-server token generate -ttl 86400 2>&1)
echo "  Server: $RAW"

NEW_TOKEN=$(echo "$RAW" | grep -oE '[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}')
if [ -z "$NEW_TOKEN" ]; then
    echo "ERROR: could not extract token from output above."
    exit 1
fi
echo "  Token: ${NEW_TOKEN:0:8}..."

# 2. Patch agent.conf in-place
echo "Updating spire/agent/agent.conf..."
sed -i "s/join_token[[:space:]]*=.*/join_token        = \"$NEW_TOKEN\"/" "$AGENT_CONF"
echo "  Done."

# 3. Stop dependent containers + agent
echo "Stopping spire-agent and dependents..."
docker compose stop langgraph-demo workload-registrar spire-agent 2>/dev/null || true

# 4. Remove stale agent data (expired SVID + old keys)
echo "Removing stale agent data volume..."
docker volume rm "$AGENT_VOLUME" 2>/dev/null && echo "  Removed." || echo "  Not found, skipping."

# 5. Bring stack back up
echo "Restarting stack..."
docker compose up -d

echo ""
echo "=== Done. Monitor with: ==="
echo "  docker compose logs -f spire-agent"
echo "  docker compose logs -f workload-registrar"
