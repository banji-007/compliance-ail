# OPA Integration Setup

This document explains how to set up Open Policy Agent (OPA) for policy enforcement in the Agentic Integrity Ledger (AIL) compliance system.

## Overview

The system uses OPA for deterministic policy evaluation:
- **Policy Location**: `policy/cloud_policy.rego`
- **OPA Endpoint**: `http://localhost:8181/v1/data/ail/policy`
- **Policy Package**: `ail.policy`
- **Decision Logic**: Deny-based rules for production compliance, instance restrictions, and data residency
- **Note**: `cost_per_hour` is descriptive metadata only - cost is NOT a policy factor

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
docker run -p 8181:8181 -v "$(pwd)/policy:/policy" openpolicyagent/opa:latest run --server --addr=0.0.0.0:8181 /policy
```

**Docker Compose (Recommended):**
```bash
docker-compose up -d
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
package ail.policy

import rego.v1

deny contains msg if {
    payload := input.tool_args
    payload.tags.environment == "prod"
    not payload.tags.cost_center
    msg := "DENIED: Production environments must include a 'cost_center' tag."
}

deny contains msg if {
    payload := input.tool_args
    blocked_instances := {"p4d.24xlarge", "p5.48xlarge"}
    blocked_instances[payload.instance_type]
    not payload.tags.project == "ml-training"
    msg := sprintf("DENIED: Instance type %v is restricted. 'project' tag must be 'ml-training'.", [payload.instance_type])
}

deny contains msg if {
    payload := input.tool_args
    payload.tags.data_classification == "pci-dss"
    not payload.region == "eu-central-1"
    msg := "DENIED: Data Residency Violation. 'pci-dss' workloads must run in 'eu-central-1'."
}
```

### Policy Rules

| Rule | Trigger | Condition | Deny Message |
|------|---------|-----------|--------------|
| Production Compliance | `environment == "prod"` | Missing `cost_center` tag | "Production environments must include a 'cost_center' tag" |
| Instance Restrictions | `p4d.24xlarge` or `p5.48xlarge` | `project != "ml-training"` | "Instance type X is restricted. 'project' tag must be 'ml-training'" |
| Data Residency | `data_classification == "pci-dss"` | `region != "eu-central-1"` | "Data Residency Violation. 'pci-dss' workloads must run in 'eu-central-1'" |

### Test Cases

| Instance Type | Environment | Tags | Region | Expected Result |
|---------------|-------------|------|--------|-----------------|
| t3.micro | prod | cost_center=eng | us-east-1 | APPROVED |
| t3.micro | prod | (none) | us-east-1 | DENIED (missing cost_center) |
| p4d.24xlarge | dev | project=webapp | us-east-1 | DENIED (restricted instance) |
| p4d.24xlarge | dev | project=ml-training | us-east-1 | APPROVED |
| t3.micro | dev | data_classification=pci-dss | us-east-1 | DENIED (data residency) |
| t3.micro | dev | data_classification=pci-dss | eu-central-1 | APPROVED |

## Integration Flow

1. **Agent** makes tool call request with tags
2. **Interceptor** sends payload to OPA via HTTP POST
3. **OPA** evaluates Rego deny rules and returns decision
4. **Interceptor** logs decision to ImmuDB cryptographic ledger
5. **Agent** executes or blocks action based on decision

## API Endpoint

**POST** `http://localhost:8181/v1/data/ail/policy`

**Request Body:**
```json
{
  "input": {
    "tool_args": {
      "instance_type": "t3.micro",
      "region": "us-east-1",
      "cost_per_hour": 5,
      "tags": {
        "environment": "prod",
        "cost_center": "engineering"
      }
    }
  }
}
```

**Response (Approved):**
```json
{
  "result": {
    "deny": []
  }
}
```

**Response (Denied):**
```json
{
  "result": {
    "deny": ["DENIED: Production environments must include a 'cost_center' tag."]
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
- All decisions are logged to the ImmuDB cryptographic ledger
- System fails safe (denies) if OPA is unavailable
- ImmuDB provides Merkle-tree immutability for audit records

## Architecture

The AIL system enforces strict separation of concerns:
- **Agent**: Makes tool call requests
- **Interceptor**: Validates requests via OPA and logs to ImmuDB
- **OPA**: Evaluates policies deterministically
- **ImmuDB**: Provides tamper-evident audit trail

This ensures no single point of failure can compromise compliance enforcement.
