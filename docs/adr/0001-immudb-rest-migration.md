# ADR 0001: ImmuDB REST API Migration

## Status
Accepted

## Context
The Agentic Integrity Ledger (AIL) was experiencing protobuf dependency collisions between the SPIFFE library (requiring protobuf >= 6.31.1) and the immudb-py gRPC client (requiring protobuf < 4.0.0). This collision forced us to disable SPIRE mTLS (`SPIRE_DISABLED=true`) as a temporary workaround, compromising our workload identity security posture.

## Decision
We are migrating from the immudb-py gRPC client to ImmuDB's REST API. This trade-off prioritizes cryptographic workload identity (mTLS) over client-side tamper-evidence verification.

### Technical Changes:
1. **Drop immudb-py gRPC client** - Remove protobuf version conflict
2. **Adopt ImmuDB REST API** - Use standard HTTP requests with Bearer token auth
3. **Re-enable SPIRE mTLS** - Restore workload identity via `SPIRE_DISABLED=false`
4. **Server-side guarantees** - Rely on ImmuDB's server-side Merkle tree verification

## Rationale

### Security Trade-off Analysis:
- **Gained**: Cryptographic workload identity via SPIRE mTLS
- **Lost**: Client-side cryptographic tamper-evidence verification
- **Net Impact**: Positive - workload identity prevents MITM attacks and provides stronger authentication guarantees

### Threat Model Considerations:
- **With mTLS**: Workloads are cryptographically authenticated, preventing spoofed agents
- **Without client verification**: We trust ImmuDB's server-side integrity guarantees
- **Mitigation**: Network-level mTLS tunnel provides tamper-evidence at transport layer

## Implementation

### Infrastructure Changes:
- Expose ImmuDB REST API port 8080
- Update connection URLs to use HTTP instead of gRPC
- Re-enable SPIRE mTLS enforcement

### Code Changes:
- Replace immudb-py SDK with httpx HTTP client
- Implement Bearer token authentication flow
- Base64 encode ledger entries for REST API payload

## Consequences

### Positive:
- Resolves protobuf dependency collision
- Restores SPIRE mTLS enforcement
- Simplifies dependency management
- Reduces attack surface via workload identity

### Negative:
- No client-side Merkle proof verification
- Additional HTTP request latency
- Manual token management required

### Mitigations:
- SPIRE mTLS provides transport-level integrity
- Regular ledger audits can verify consistency
- HTTP requests are still within trusted Docker network

## Future Considerations
- Monitor for official immudb-py updates with modern protobuf support
- Consider implementing client-side verification if threat model changes
- Evaluate ledger performance impact of REST vs gRPC

## References
- ImmuDB REST API Documentation
- SPIFFE mTLS Security Model
- AIL Architecture Requirements
