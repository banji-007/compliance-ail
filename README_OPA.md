# OPA Integration Setup

This document explains how to set up Open Policy Agent (OPA) for policy enforcement in the compliance AI system.

## Overview

The system now uses OPA instead of hardcoded Python logic for policy decisions:
- **Policy Location**: `policy/cloud_policy.rego`
- **OPA Endpoint**: `http://localhost:8181/v1/data/compliance/cloud/decision`
- **Policy Logic**: Allow `provision_cloud_server` only if `cost_per_hour < 10` AND `region == "us-east-1"`

## Quick Start

### 1. Install Docker
Make sure Docker is installed and running on your system.

### 2. Start OPA Container
Run one of the following commands:

**Windows:**
```bash
start_opa.bat
```

**Linux/Mac:**
```bash
chmod +x start_opa.sh
./start_opa.sh
```

**Manual Docker command:**
```bash
docker run -p 8181:8181 -v "$(pwd)/policy:/policy" openpolicyagent/opa:latest run --server /policy
```

### 3. Verify OPA is Running
```bash
curl http://localhost:8181/health
```

### 4. Test Policy Enforcement
```bash
python test_opa_integration.py
```

## Policy Details

### cloud_policy.rego
```rego
package compliance.cloud

default allow = false

allow {
    input.action == "provision_cloud_server"
    input.cost_per_hour < 10
    input.region == "us-east-1"
}
```

### Test Cases

| Cost | Region | Expected Result |
|------|--------|-----------------|
| $5   | us-east-1 | APPROVED |
| $15  | us-east-1 | DENIED (cost too high) |
| $5   | us-west-2 | DENIED (wrong region) |
| $25  | eu-west-1 | DENIED (both fail) |

## Integration Flow

1. **Agent** makes tool call request
2. **Interceptor** sends payload to OPA via HTTP POST
3. **OPA** evaluates Rego policy and returns decision
4. **Interceptor** logs decision to immutable ledger
5. **Agent** executes or blocks action based on decision

## API Endpoint

**POST** `http://localhost:8181/v1/data/compliance/cloud/decision`

**Request Body:**
```json
{
  "action": "provision_cloud_server",
  "instance_type": "t3.micro",
  "region": "us-east-1",
  "cost_per_hour": 5
}
```

**Response:**
```json
{
  "result": {
    "allowed": true,
    "reason": "Action approved by policy"
  }
}
```

## Troubleshooting

### OPA Not Responding
- Check if Docker container is running: `docker ps`
- Verify port mapping: `docker logs <container_id>`
- Test health endpoint: `curl http://localhost:8181/health`

### Policy Not Loaded
- Check container logs for policy loading errors
- Verify policy file path: `policy/cloud_policy.rego`
- Reload policy by restarting container

### Integration Tests Failing
- Ensure OPA is running before running tests
- Check network connectivity to localhost:8181
- Verify policy decision format matches expected structure

## Security Notes

- OPA runs in a container with limited access
- Policy decisions are deterministic and auditable
- All decisions are logged to the immutable ledger
- System fails safe (denies) if OPA is unavailable
