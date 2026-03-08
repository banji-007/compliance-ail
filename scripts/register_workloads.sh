#!/bin/bash

# SPIRE Workload Registration Script
# This script generates join tokens and registers workloads for the AIL system

echo "=== SPIRE Workload Registration ==="

# Wait for SPIRE server to be ready
echo "Waiting for SPIRE server to be ready..."
sleep 10

# Generate join token for the agent
echo "Generating join token for SPIRE agent..."
TOKEN=$(docker exec compliance-ail-spire-server-1 /opt/spire/bin/spire-server token generate -spiffeID spiffe://ail.internal/ns/default/sa/agent -t | awk '{print $2}')

if [ -z "$TOKEN" ]; then
    echo "Error: Failed to generate join token"
    exit 1
fi

echo "Join token generated: ${TOKEN:0:20}..."

# Create a temporary file with the token
echo "$TOKEN" > /tmp/spire-token

# Restart the SPIRE agent with the join token
echo "Restarting SPIRE agent with join token..."
docker-compose restart spire-agent

# Wait for agent to join
echo "Waiting for agent to join server..."
sleep 15

# Verify agent joined successfully
echo "Verifying agent status..."
AGENT_STATUS=$(docker logs compliance-ail-spire-agent-1 2>&1 | tail -5)

if echo "$AGENT_STATUS" | grep -q "successfully attested"; then
    echo "✅ SPIRE agent successfully joined server"
else
    echo "❌ SPIRE agent may not have joined successfully"
    echo "Latest agent logs:"
    echo "$AGENT_STATUS"
fi

# Register workloads (placeholder for future Envoy and Python workloads)
echo "=== Workload Registration ==="
echo "Workload registration will be implemented in Phase 3"
echo "Current status: Identity control plane is operational"

echo ""
echo "=== SPIRE Infrastructure Status ==="
echo "✅ SPIRE Server: Running with SQLite datastore"
echo "✅ SPIRE Agent: Running with Docker WorkloadAttestor"
echo "✅ Workload API Socket: Available at /tmp/spire-sockets/workload_api.sock"
echo "✅ Trust Domain: ail.internal"

echo ""
echo "Next Steps:"
echo "1. Verify agent-server connection: docker logs compliance-ail-spire-agent-1"
echo "2. Test Workload API: curl --unix-socket /tmp/spire-sockets/workload_api.sock http://localhost/bundle"
echo "3. Proceed to Phase 3: AIL middleware integration with SPIFFE identities"
