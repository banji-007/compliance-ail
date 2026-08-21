# Phase 3a: Portable evidence bundle and offline verifier

**Run id:** `p3a-bundle`. State run id, working directory, branch first. Not the primary working directory. Remove the scratch directory before reporting.

**Base:** head of `main`. Branch, PR against `main`, CI green before reporting.

Grounded in `docs/reports/spike-offline-verify.md`, which established that `immudb-py==1.5.0`'s verification is pure computation over already-fetched protobuf and can be driven offline with no reimplemented crypto. The gap is that `verifier/main.py` discards the material after computing a boolean.

This is the phase that makes the project shareable: evaluating it becomes opening a file rather than running a stack.

## Standing rules

No design changes beyond D18 to D20. Escalate rather than substitute; do not reimplement crypto under any circumstance, and if a criterion appears to require it, stop and report.

Never widen or weaken an assertion. Explicit Compose project name on every invocation. Scratch clone, `--no-cache`. No em dashes.

Every item has a **demonstrate** half, an **enforce** half, and a named **mutation** that must fail the suite.

---

## Design decisions

### D18. The verifier exports proof material; it does not compute a boolean and discard it

`POST /verify` retains and returns the material the spike enumerated: the prior `State`, the raw `VerifiableEntry` protobuf, and the transaction identifiers needed to reconstruct the check. The verifier's own pass or fail result stays as it is; the material is additional, not a replacement.

The public key is **not** part of the exported material. The spike found `state.publicKey` is never checked during verification, so a bundle that carried its own key would be self-certifying. The key is configuration the checker holds independently, and the bundle names which key it expects by fingerprint.

### D19. A bundle is one file, self-describing, and verifies with no network

An evidence bundle for a single record contains: the record as stored, the proof material from D18, the key fingerprint it expects, and a format version. It is a single file a person can email.

Verification runs in a process with no network. The spike blocked `socket.connect` to prove this is achievable; the verifier tool must make that a property, not an accident.

### D20. The verifier tool reuses the SDK's verification functions unmodified

`store.VerifyInclusion`, `store.VerifyDualProof`, and `State.Verify` are called directly. The shims the spike used to satisfy the SDK's stub and rootservice interfaces are the mechanism. ADR-0001 records a hand-rolled `Alh()` in this project that was wrong; that is the outcome this decision exists to prevent.

Verification failure reports which check failed and why, distinguishing a consistency failure from a signature failure, matching the closed set the verification states already use.

---

## Items

### P3a-1. The verifier exports proof material

Implement D18.

**Demonstrate:** a `/verify` response carrying the material, for a real entry from a live stack.

**Enforce:** a test asserting the response contains every field the offline check needs, enumerated from the spike rather than from this instruction.

**Mutation:** drop one field from the response. Named test must fail.

### P3a-2. A bundle can be exported for any record

An endpoint or command produces a bundle for a given record. Reachable through the same authorization as the audit read, not more permissively.

**Demonstrate:** bundles exported for a `policy_allow`, a `policy_deny`, a `fault`, and a `content_erasure` tombstone.

**Enforce:** tests for each record type, plus one asserting the export requires the read credential.

**Mutation:** remove the credential check. Named test must fail.

### P3a-3. A bundle verifies offline

Implement D19 and D20. The checker is a standalone entry point: no Docker, no ImmuDB, no network.

**Demonstrate:** verification succeeding in a process with outbound sockets blocked, against a stack that has been torn down. Reproduce the spike's method.

**Enforce:** a test that blocks network access and verifies a fixture bundle. The test fails if the checker attempts a connection.

**Mutation:** make the checker fetch anything. Named test must fail.

### P3a-4. Tampering fails with a named error

**Demonstrate:** the spike's byte sweep, rerun against the bundle format rather than the raw proto. Report which byte ranges are semantically meaningful and which are wire framing, and state that plainly rather than claiming every byte is protected.

**Enforce:** tests for a flipped record byte, a flipped proof byte, a substituted state, and a wrong key fingerprint. Each asserts the specific error, never a broad exception.

**Mutation:** widen one assertion to a broad exception. Named test must fail.

### P3a-5. The key is independent of the bundle

The spike found `state.publicKey` is never checked. A bundle that shipped its own key would verify against itself.

**Demonstrate:** a bundle whose embedded fingerprint names a key the checker does not hold is refused, distinctly from a tampered bundle. A bundle verified against the wrong key fails as a signature failure.

**Enforce:** tests for both.

**Mutation:** let the checker read a key from the bundle. Named test must fail.

### P3a-6. Documentation and claim mapping

An ADR covering D18 through D20, including the `state.publicKey` finding and why the key stays out of the bundle.

README gains a section on the evidence bundle: what it proves, what it does not, and the fact that a bundle proves a record was committed and unaltered, not that the policy which approved it was correct. That distinction already exists in section 3.4 and must not be blurred here.

Residual Limits updated. A bundle exported by a compromised writer is still a bundle of whatever that writer recorded; portability does not fix provenance, which is 3b.

**Criterion:** every new or changed claim maps to a test, a reproducible command, or a Residual Limits entry, in the mapping-table format of `docs/reports/phase-1-3-complete.md` section 9, derived per row rather than asserted over the set.

---

## Pre-registered negatives

All false at the end, each confirmed individually and derived per row.

- Any reimplemented cryptographic primitive.
- Any network access during verification.
- Any key material inside a bundle.
- Any tamper test asserting a broad exception.
- Any bundle export reachable without the read credential.
- Any claim not in the mapping.
- Any assertion weakened.
- Any item met by live evidence alone with no test enforcing it.

## Report

`docs/reports/phase-3a.md`. Verdict per item, demonstration, enforcing test, mutation result, the byte-sweep table from P3a-4, the mapping, individual confirmation of each negative, could-not-verify, CI run id.
