# ail-gateway Helm chart

> **Unsupported. Do not deploy.**
>
> This chart predates the ADR-001 verifier-isolation migration (see
> `docs/adr/0001-immudb-rest-migration.md`) and was never updated when the
> ledger client moved from talking to ImmuDB directly to talking through an
> isolated `verifier` service. As a result:
>
> - `templates/agent-deployment.yaml` injects `IMMUDB_URL`, `IMMUDB_USER`,
>   and `IMMUDB_PASSWORD` directly into the agent pod - the pre-ADR-001
>   design.
> - There is no `verifier` Deployment or Service anywhere in this chart.
> - `ledger/immudb_ledger.py`, the code that actually runs in the agent pod,
>   only ever calls `VERIFIER_URL` - it does not read the `IMMUDB_*`
>   variables this chart sets, and there is no `verifier` service for it to
>   reach even if it did.
>
> A cluster deployed from this chart will fail closed on every tool call
> (`DENIED: Audit ledger unavailable`), not run successfully in a degraded
> mode. This was confirmed by rendering the chart with `helm template` and
> checking the result against the actual ledger client code - see
> `docs/audit/2026-08-16-verification.md`, item V1.
>
> The same root cause reaches the control-plane pod too:
> `templates/control-plane-deployment.yaml` sets no `VERIFIER_URL`
> anywhere, and `control_plane/main.py`'s `/audit` handler calls
> `VERIFIER_URL` for its per-entry proof check on every request. A
> control-plane pod deployed from this chart would report every audit
> entry `verified: false` from the first request, for the same reason the
> agent pod fails closed - see `docs/reports/phase-0-redteam.md`, C7, and
> `docs/reports/phase-0-1.md`, P01-6.
>
> Porting the verifier architecture into this chart is deliberately out of
> scope here: the hosted-deployment direction for this project may retire
> the chart entirely, and porting a design that might be thrown away is not
> useful work. If a Kubernetes deployment path is needed before that
> direction is settled, treat this chart as a reference for the sidecar
> pattern (SPIFFE/SPIRE workload identity, the agent/envoy/opa pod
> topology) rather than as something to run as-is.

## What is accurate here

- The sidecar pattern in `templates/agent-deployment.yaml` (agent + envoy +
  OPA sharing a pod network namespace, SPIRE workload attestation via an
  init container) reflects the current zero-trust interception design and
  is a reasonable reference even though the ledger wiring is stale.
- `templates/control-plane-deployment.yaml` **is now confirmed** to share
  the same root cause (no `VERIFIER_URL`, see above) - not merely "not
  known to have the defect."
- `templates/dashboard-deployment.yaml` and `templates/immudb-statefulset.yaml`
  are not known to have the same defect - they were not in scope for this
  check.
