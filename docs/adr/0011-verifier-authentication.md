# ADR 0011: Verifier Authentication

## Status

Accepted

## Context

`verifier/main.py`'s `/write` and `/verify` endpoints carried no `Depends(...)`
of any kind from Phase 1 through Phase 3a. This was a stated residual limit
(`readME.md` Residual Limits, "tamper-evidence is not forgery-resistance"),
not an oversight, and the reasoning for deferring it was explicit at the
time: Phase 2 (`docs/adr/0008-decision-service-boundary.md`) was about to
remove the agent's own network path to this service entirely, and a Phase 3
that reshaped what the record sink looked like might change the shape any
authorization would need to take. Fixing it before either of those landed
risked building the wrong thing.

Phase 2 did remove the agent's path - `langgraph-demo` is `edge`-only,
`verifier` is `backend`-only, and no route between them exists at all
(`tests/test_decision_service_network_isolation.py`). Phase 3a did not
reshape the record sink. Instead, D18 (`docs/adr/0010-portable-evidence-
bundles.md`) made `/verify` return exportable proof material - the exact
input a portable evidence bundle is built from - which the Phase 3a
red-team's X5 finding showed matters a great deal here: `GET /audit/bundle`
computes its authorization story entirely at the control-plane layer
(`Depends(_require_read_key)`), but the material it exports is one
unauthenticated `POST /verify` away for anyone who can already reach the
verifier's network position. An attacker who cannot pass the control
plane's read-key gate at all can bypass it completely by going straight to
the endpoint the gated route itself calls, and assemble an equivalent
bundle by hand. The two deferral conditions no longer hold, and the
consequence of not fixing it is now concrete rather than theoretical.

## Decision

### D21: the verifier authenticates, with its own credential pair

`POST /verify` requires `VERIFIER_READ_KEY`. `POST /write` requires
`VERIFIER_WRITE_KEY`. `GET /health` remains open, matching every other
service's health check in this project.

This is the same two-tier shape `docs/adr/0007-two-tier-authorization.md`
established for the control plane and the dashboard, applied a third time -
`_require_read_key`/`_require_write_key` in `verifier/main.py` are the same
pattern as `control_plane/main.py`'s functions of the same name: a required
`X-API-Key` header, checked against an environment-sourced value, 503 when
that value is unset or empty (fail-closed - the route it gates never
silently operates unauthenticated), 403 on a mismatch.

**The keys are independent secrets, not shared with `CONTROL_PLANE_READ_KEY`/
`WRITE_KEY`.** `VERIFIER_READ_KEY` and `VERIFIER_WRITE_KEY` are distinct
values. A compromise of the control-plane pair does not hand out the
verifier pair, and vice versa - the same reasoning ADR-0007 gives for why
the dashboard and control-plane layers are independent checks rather than
one credential implying the other.

### Provisioning

Credentials reach each service the same way `CONTROL_PLANE_READ_KEY`/
`WRITE_KEY` already do - environment variables set in `docker-compose.yml`/
`docker-compose.test.yml` from `.env` - not a new delivery mechanism.

- **`ail-control-plane` holds both.** It calls `POST /verify` from three
  places (`get_audit`'s per-entry verification, `get_audit_bundle`'s export,
  `_has_tombstone`'s erasure-conflict check) and `POST /write` from one
  (`_write_tombstone`).
- **`decision-service` holds `VERIFIER_WRITE_KEY` only.** `D12` (Phase 2)
  moved the ledger write here - `ledger/immudb_ledger.py`'s `log_tool_call`
  and `log_tool_intent` are this service's only callers of the verifier, and
  both only ever write. It is never provisioned with `VERIFIER_READ_KEY`;
  there is no code path here that would use it.
- **`langgraph-demo` (the agent) holds neither.** It already has no network
  route to the verifier at all (`backend`-only vs. its own `edge`-only
  membership) - provisioning either credential here would be a key with
  nowhere to be used, not a capability. `tests/test_decision_service_
  network_isolation.py` asserts the agent's environment names neither key.

## Why this closes X5 without widening anything

`GET /audit/bundle`'s own authorization is unchanged - still
`Depends(_require_read_key)` on the control plane, still the same credential
`GET /audit` requires (ADR-0007, ADR-0010's D19). What changes is that the
verifier itself, the endpoint the bundle route's own material comes from,
no longer answers an unauthenticated caller either. The X5 bypass depended
entirely on the verifier being reachable and open at the same time; closing
either one closes the bypass, and P2-1 already closed reachability for the
agent specifically. D21 closes it for every caller, not just the agent, so
the fix does not depend on network position at all - a caller who compromises
`ail-control-plane` or `decision-service` still holds valid verifier
credentials (this is unchanged; see Residual Limits, "tamper-evidence is not
forgery-resistance"), but no other caller can reach `/write` or `/verify`,
credentialed or not.

## Consequences

**Gained:**

- An unauthenticated `POST /verify` or `POST /write` against the verifier is
  refused (422 for a missing header, 403 for a wrong key), closing red-team
  X5 and the general "verifier has no auth" residual limit that predated it
  (Phase 1.2's U5, restated in `readME.md`'s Residual Limits since).
- The verifier's own credentials are independent of the control plane's -
  the cross-tier refusals (`tests/test_verifier_auth.py`) confirm the read
  key does not open `/write` and the write key does not open `/verify`, the
  same discipline ADR-0007 already established for the control plane's own
  two keys.

**Unchanged:**

- **Reach, not just credentials, still matters.** `ail-control-plane` and
  `decision-service` are the only two services provisioned with any verifier
  credential, and they are also the only two services with a network route
  to it (`backend`). A compromise of either one still carries full forgery
  reach against the ledger - D21 adds a credential check to a service that
  was previously open to anyone who could reach it, it does not change who
  can reach it. This is the same limit `readME.md`'s "tamper-evidence is not
  forgery-resistance" bullet already states for Phase 2's own boundary, and
  D21 does not narrow it.
- The agent's isolation from the verifier was already structural (P2-1,
  `docs/adr/0008-decision-service-boundary.md`) - D21 adds a second,
  independent reason the same bypass would fail even if the network
  boundary were somehow crossed, rather than replacing the network boundary
  with a credential check.

**Constraints:**

- Two more credential pairs now exist where two existed before
  (`CONTROL_PLANE_READ/WRITE_KEY`, `DASHBOARD_READ/WRITE_USER/PASSWORD`) -
  `VERIFIER_READ_KEY`/`WRITE_KEY` extend the same rotation and provisioning
  surface ADR-0007 already tracks across `docker-compose.yml`,
  `docker-compose.test.yml`, `Makefile`, and `.github/workflows/ci.yml`
  together.
- Every direct-to-verifier test helper in this repository's test suite
  (`tests/test_verification.py`, `tests/test_evidence_bundle.py`,
  `tests/test_record_profile.py`, `tests/test_content_states.py`,
  `tests/test_intent_completion_visibility.py`) now attaches the
  appropriate credential - a test that forges a record directly against the
  verifier (simulating red-team U4/U5's own position) still can, since these
  tests hold the write key themselves, but the forgery is no longer
  "bypassing... any auth entirely", only the control plane's higher-level
  checks layered on top of a bare write.

## References

- `verifier/main.py::_require_read_key`, `_require_write_key`
- `docs/adr/0007-two-tier-authorization.md` - the two-tier pattern this extends to a third service
- `docs/adr/0008-decision-service-boundary.md` - the network boundary this is independent of, not a substitute for
- `docs/adr/0010-portable-evidence-bundles.md` - D18/D19, the feature whose export path X5 found unauthenticated at the source
- `docs/reports/phase-3a-redteam.md`, X5 - the finding this closes
- `docs/reports/phase-3a-completion.md` - demonstration, enforcing tests, and mutation result
- `tests/test_verifier_auth.py`
