#!/bin/sh
# SPIRE Agent Entrypoint Script
# Reads join token from shared volume and injects into agent configuration

set -e

echo "=== SPIRE Agent Entrypoint ==="

# Wait for join token to be available
TOKEN_FILE="/opt/spire/tokens/join_token"
MAX_WAIT=60
WAIT_COUNT=0

echo "Waiting for join token at $TOKEN_FILE..."

while [ ! -f "$TOKEN_FILE" ] && [ $WAIT_COUNT -lt $MAX_WAIT ]; do
  echo "  Token not ready, waiting... ($WAIT_COUNT/$MAX_WAIT)"
  sleep 2
  WAIT_COUNT=$((WAIT_COUNT + 1))
done

if [ ! -f "$TOKEN_FILE" ]; then
  echo "ERROR: Join token file not found after $MAX_WAIT seconds"
  exit 1
fi

# Read the token
JOIN_TOKEN=$(cat "$TOKEN_FILE")
echo "Found join token: ${JOIN_TOKEN:0:8}..."

# Update agent configuration with the token
AGENT_CONF="/opt/spire/conf/agent/agent.conf"
echo "Updating $AGENT_CONF with join token..."

# Create backup of original config
cp "$AGENT_CONF" "$AGENT_CONF.backup"

# Replace the join_token field in the configuration
sed -i "s/join_token[[:space:]]*=.*/join_token        = \"$JOIN_TOKEN\"/" "$AGENT_CONF"

echo "Configuration updated successfully."

# Execute the original SPIRE agent command
echo "Starting SPIRE agent..."
exec "$@"
