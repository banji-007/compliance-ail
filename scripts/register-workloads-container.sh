#!/bin/sh
# SPIRE Workload Registration
# Waits for the server socket via shared volume, then uses docker exec to call
# the spire-server binary (distroless image has no shell of its own).
#
# Uses spiffe://ail.internal/agent/local as the stable parentID for all
# workload entries. The watchdog generates this alias on every agent restart,
# so workload registrations remain valid across token rotations.

SERVER="spire-server"
SOCKET="/tmp/spire-server/private/api.sock"
# Stable node alias created by the watchdog for every join-token rotation.
PARENT_ID="spiffe://ail.internal/agent/local"

echo "=== SPIRE Workload Registrar ==="

# Wait until the SPIRE server socket file appears (shared via spire-server-socket volume)
echo "Waiting for SPIRE server socket..."
until [ -S "$SOCKET" ]; do
    sleep 2
done
echo "Server socket ready."

# Wait for agent to attest (up to 90s)
echo "Waiting for SPIRE agent to attest..."
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
echo "Agent: $AGENT_ID (parentID will use stable alias: $PARENT_ID)"
echo ""

# Delete any existing entry for a given SPIFFE ID so stale parentIDs
# from previous runs (with a different join token) are replaced.
delete_existing() {
    SPIFFE_ID="$1"
    ENTRY_ID=$(docker exec "$SERVER" /opt/spire/bin/spire-server entry show \
        -socketPath "$SOCKET" -spiffeID "$SPIFFE_ID" 2>/dev/null \
        | grep "^Entry ID" | sed 's/Entry ID[[:space:]]*:[[:space:]]*//' | tr -d '[:space:]')
    if [ -n "$ENTRY_ID" ]; then
        docker exec "$SERVER" /opt/spire/bin/spire-server entry delete \
            -socketPath "$SOCKET" -entryID "$ENTRY_ID" 2>/dev/null || true
        echo "  Removed stale entry $ENTRY_ID for $SPIFFE_ID"
    fi
}

register_workload() {
    SPIFFE_ID="$1"
    SELECTOR="$2"
    MAX_ATTEMPTS=5
    ATTEMPT=0

    echo "Registering: $SPIFFE_ID"
    # Remove any stale entry with a different parentID before creating.
    delete_existing "$SPIFFE_ID"

    while [ $ATTEMPT -lt $MAX_ATTEMPTS ]; do
        ATTEMPT=$((ATTEMPT + 1))
        OUTPUT=$(docker exec "$SERVER" /opt/spire/bin/spire-server entry create \
            -socketPath "$SOCKET" \
            -spiffeID   "$SPIFFE_ID" \
            -parentID   "$PARENT_ID" \
            -selector   "$SELECTOR" 2>&1)
        EXIT_CODE=$?

        if [ $EXIT_CODE -eq 0 ] || echo "$OUTPUT" | grep -qi "already exists"; then
            echo "  OK (attempt $ATTEMPT)"
            echo "$OUTPUT" | head -4
            echo ""
            return 0
        fi

        echo "  attempt $ATTEMPT/$MAX_ATTEMPTS failed: $OUTPUT"
        if [ $ATTEMPT -lt $MAX_ATTEMPTS ]; then
            BACKOFF=$((ATTEMPT * 3))
            echo "  retrying in ${BACKOFF}s..."
            sleep "$BACKOFF"
        fi
    done

    echo "ERROR: Failed to register $SPIFFE_ID after $MAX_ATTEMPTS attempts."
    exit 1
}

register_workload "spiffe://ail.internal/workload/envoy" "unix:uid:101"
register_workload "spiffe://ail.internal/workload/agent" "unix:uid:1000"
register_workload "spiffe://ail.internal/workload/test"  "unix:uid:0"

echo "=== Registered entries ==="
docker exec "$SERVER" /opt/spire/bin/spire-server entry show \
    -socketPath "$SOCKET" 2>/dev/null \
    | grep -E "(SPIFFE ID|Selector)" || true

echo ""
echo "Workload registration complete."
