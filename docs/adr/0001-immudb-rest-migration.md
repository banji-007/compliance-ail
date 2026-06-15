# ADR 0001: ImmuDB Client Architecture

## Status

Accepted (supersedes the original REST-migration decision)

## Context

The AIL interceptor needs cryptographic tamper-evidence for its audit ledger.
Two constraints shape the solution:

1. The SPIFFE library (`spiffe==0.2.5`) requires `protobuf>=6.31.1`. The
   official `immudb-py` gRPC client (pre-1.x) required `protobuf<4.0.0`.
   Running both in the same process was impossible.

2. Switching to ImmuDB's REST API (ADR-0001 v1) resolved the dependency
   collision but conceded client-side tamper-evidence: the REST endpoints
   do not return the Merkle inclusion proofs and consistency proofs that
   `immudb-py verifiedGet / verifiedSet` verify internally. The REST path
   required hand-rolling `TxHeader.Alh()` in Python, which was found to
   be incorrect (wrong field order, `eH` substituted for `innerHash`,
   `innerHash` itself version-dependent).

## Decision

Resolve the conflict with process isolation, not by choosing between the two
libraries. The system is split into two processes:

**Interceptor process** (langgraph-demo container)

- Uses `httpx` over plain HTTP to call the verifier service.
- Holds zero `immudb-py` code and zero protobuf dependency.
- SPIFFE mTLS posture is fully preserved.

**Verifier service** (separate `verifier` container)

- A small FastAPI wrapper around `immudb-py==1.5.0` (gRPC, port 3322).
- `immudb-py 1.5.0` requires `protobuf>=4.25.3`; there is no spiffe import
  in this container, so there is no conflict.
- Exposes `POST /write` (wraps `verifiedSet`) and `POST /verify` (wraps
  `verifiedGet`).
- Maintains a `PersistentRootService` state file in its own Docker volume,
  not shared with the interceptor container.

Both the interceptor (write path) and the control plane (audit read path)
call the verifier over the Docker internal network. Neither holds a copy of
ImmuDB credentials or SDK state.

## What the SDK actually verifies

`verifiedSet` and `verifiedGet` perform three checks:

1. **Inclusion proof** - walks the Merkle tree from the (key, value) leaf to
   `eH` (the transaction's entry hash root), confirming the entry is in the
   tree committed by the server.

2. **Dual consistency proof** - verifies a linear-hash chain from the
   verifier's locally persisted state (tx N) to the current state (tx M),
   confirming no transactions were inserted, removed, or reordered between N
   and M.

3. **State signature** (when `--signingKey` is configured on the server) -
   verifies the server's ECDSA signature over `(db, txId, txHash)` against
   the public key mounted in the verifier container. A forged or rolled-back
   state cannot pass this check without the private key.

## Trust anchor

The verifier's `PersistentRootService` stores the latest verified `(txId,
txHash)` in `/data/verifier-state/immudb.state` (a named Docker volume
mounted only in the verifier container). The interceptor container cannot
write to this volume. Rotating the signing key requires deleting the verifier
state volume so the new root is accepted on the next startup.

## Consequences

**Gained:**

- Full client-side Merkle inclusion and consistency proof verification via the
  official SDK - no hand-rolled crypto.
- SPIFFE mTLS and workload identity are fully preserved in the interceptor.
- The audit read path (`/audit`) verifies every entry through the same SDK
  chain, so the CISO dashboard reflects real proof results, not decorative
  hashes.

**Constraints:**

- The verifier service must be healthy before the interceptor can start. The
  compose dependency is `verifier: condition: service_healthy`. Fail-closed
  posture is maintained: if the verifier is unreachable, every intercepted
  tool call is DENIED.
- `PersistentRootService` uses pickle and is not safe for concurrent access
  across multiple uvicorn workers. The verifier runs with `--workers 1`.
- Per-entry `verifiedGet` on `/audit` is O(n) SDK calls. At the default limit
  of 100 entries this is acceptable; consider lazy verification (verify on
  expand) if audit pages grow large.

## References

- `verifier/main.py` - service implementation
- `immudb/embedded/store/tx.py` in immudb-py 1.5.0 - `Alh()` and
  `innerHash()` source (the correct formula; the earlier hand-rolled version
  was wrong)
- `tests/test_verification.py` - five acceptance tests including tamper
  detection against a corrupted state file and a wrong signing key
