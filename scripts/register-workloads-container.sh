#!/bin/sh
# SPIRE Workload Registration
# Runs inside docker:cli container; uses docker exec to call the SPIRE server
# binary without needing a shell in the distroless spire-server image.

SERVER="compliance-ail-spire-server-1"
SOCKET="/tmp/spire-server/private/api.sock"

echo "=== SPIRE Workload Registrar ==="

# Wait until the SPIRE server is responsive
echo "Waiting for SPIRE server..."
until docker exec "$SERVER" /opt/spire/bin/spire-server agent list \
    -socketPath "$SOCKET" >/dev/null 2>&1; do
    sleep 3
done
echo "Server ready."

# Wait for agent to attest (up to 90s)
echo "Waiting for SPIRE agent to attest..."
AGENT_ID=""
i=0
while [ $i -lt 30 ]; do
    AGENT_ID=$(docker exec "$SERVER" /opt/spire/bin/spire-server agent list \
        -socketPath "$SOCKET" 2>/dev/null \
        | grep "SPIFFE ID" | head -1 \
        | sed 's/.*SPIFFE ID[[:space:]]*:[[:space:]]*//' | tr -d '[:space:]')
    [ -n "$AGENT_ID" ] && break
    i=$((i + 1))
    printf "  attempt %d/30...\n" "$i"
    sleep 3
done

if [ -z "$AGENT_ID" ]; then
    echo "ERROR: No SPIRE agent attested after 90s."
    exit 1
fi
echo "Agent: $AGENT_ID"
echo ""

register_workload() {
    SPIFFE_ID="$1"
    SELECTOR="$2"
    echo "Registering: $SPIFFE_ID"
    docker exec "$SERVER" /opt/spire/bin/spire-server entry create \
        -socketPath "$SOCKET" \
        -spiffeID   "$SPIFFE_ID" \
        -parentID   "$AGENT_ID" \
        -selector   "$SELECTOR" 2>&1 | head -4 || true
    echo ""
}

register_workload "spiffe://ail.internal/workload/envoy" "unix:path:/usr/local/bin/envoy"
register_workload "spiffe://ail.internal/workload/agent" "unix:path:/usr/local/bin/python3.11"

echo "=== Registered entries ==="
docker exec "$SERVER" /opt/spire/bin/spire-server entry show \
    -socketPath "$SOCKET" 2>/dev/null \
    | grep -E "(SPIFFE ID|Selector)" || true

echo ""
echo "Workload registration complete."
