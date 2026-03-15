#!/bin/sh
# spire-watchdog.sh — Restart-proof SPIRE agent supervisor.
#
# Runs as a docker:cli companion service. On every agent container exit,
# generates a fresh one-time join token from the SPIRE server (via docker exec),
# writes a new agent.conf to the shared spire-agent-config volume, then
# restarts the stopped container. The cycle repeats indefinitely so that
# SVID expiry or any other crash never requires manual intervention.
#
# Requirements (satisfied by the docker-compose service definition):
#   - /var/run/docker.sock mounted
#   - spire-agent-config volume mounted at /opt/spire/agent-config
#   - spire-server container_name == "spire-server" (set in docker-compose.yml)

set -e

SPIFFE_ID="spiffe://ail.internal/agent/local"
SOCKET_PATH="/tmp/spire-server/private/api.sock"
AGENT_CONF="/opt/spire/agent-config/agent.conf"
# Label used by Docker Compose to tag the agent container.
AGENT_LABEL="com.docker.compose.service=spire-agent"

log() { echo "[watchdog] $(date -u +%H:%M:%S) $*"; }

# ---------------------------------------------------------------------------
# generate_token: calls spire-server inside the running server container
# and extracts the UUID join token from its output.
# ---------------------------------------------------------------------------
generate_token() {
    OUTPUT=$(docker exec spire-server \
        /opt/spire/bin/spire-server token generate \
        -spiffeID "$SPIFFE_ID" \
        -socketPath "$SOCKET_PATH" 2>&1)

    TOKEN=$(echo "$OUTPUT" | grep -oE '[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}')

    if [ -z "$TOKEN" ]; then
        log "ERROR: token generation failed. Server output: $OUTPUT"
        return 1
    fi

    echo "$TOKEN"
}

# ---------------------------------------------------------------------------
# write_agent_conf: writes a complete agent.conf with the given join token.
# Mirrors the template used by the token-generator service exactly.
# ---------------------------------------------------------------------------
write_agent_conf() {
    TOKEN="$1"
    cat > "$AGENT_CONF" << EOF
agent {
    data_dir          = "/opt/spire/data"
    log_level         = "INFO"
    server_address    = "spire-server"
    server_port       = "8081"
    socket_path       = "/tmp/spire-sockets/workload_api.sock"
    trust_domain      = "ail.internal"
    insecure_bootstrap = true
    join_token        = "$TOKEN"
}

plugins {
    NodeAttestor "join_token" {
        plugin_data {}
    }

    KeyManager "disk" {
        plugin_data {
            directory = "/opt/spire/data"
        }
    }

    WorkloadAttestor "unix" {
        plugin_data {}
    }
}
EOF
    log "agent.conf written with token ${TOKEN%%-*}..."
}

# ---------------------------------------------------------------------------
# find_agent_container: returns the container ID of the spire-agent service
# container (running OR stopped) using compose service label.
# ---------------------------------------------------------------------------
find_agent_container() {
    docker ps -a -q --filter "label=$AGENT_LABEL" | head -1
}

# ---------------------------------------------------------------------------
# Main loop
# ---------------------------------------------------------------------------
log "=== SPIRE Agent Watchdog starting ==="
log "Monitoring label: $AGENT_LABEL"

# Wait for the initial compose startup to complete before we take over.
# The token-generator and initial agent start happen in this window.
log "Waiting 40s for initial compose startup..."
sleep 40

while true; do
    CONTAINER_ID=$(find_agent_container)

    if [ -z "$CONTAINER_ID" ]; then
        log "Agent container not found yet, retrying in 10s..."
        sleep 10
        continue
    fi

    STATUS=$(docker inspect --format='{{.State.Status}}' "$CONTAINER_ID" 2>/dev/null || echo "gone")

    case "$STATUS" in
        running|starting|restarting)
            # Agent is alive — nothing to do.
            sleep 10
            continue
            ;;
        exited|dead|gone)
            log "Agent container $CONTAINER_ID is '$STATUS'. Initiating token refresh..."

            # Generate a fresh join token.
            TOKEN=$(generate_token) || { log "Token generation failed, retrying in 15s..."; sleep 15; continue; }

            # Write the new config into the shared volume.
            write_agent_conf "$TOKEN"

            # Restart the stopped container — it will pick up the new agent.conf.
            log "Restarting container $CONTAINER_ID..."
            docker start "$CONTAINER_ID" && log "Container restarted." || {
                log "ERROR: docker start failed. Will retry in 15s."
                sleep 15
                continue
            }

            # Give the agent time to attest before checking again.
            log "Waiting 30s for agent to attest..."
            sleep 30
            ;;
        *)
            log "Unknown agent status '$STATUS', waiting 10s..."
            sleep 10
            ;;
    esac
done
