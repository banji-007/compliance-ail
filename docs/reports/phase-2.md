# Phase 2 Report: Move the boundary

**Run id:** `p2-boundary`. **Working directory:** `C:\Users\banji\OneDrive\Documents\p2-boundary-scratch` (scratch clone, not the primary working directory). **Branch:** `phase-2-boundary`, base `main` head `6dd56b6`.

Status: IN PROGRESS - this report is being filled in as work completes, per the project's own convention of writing the report alongside the work rather than only at the end. Sections below are placeholders until their item's demonstrate/enforce/mutation cycle is actually done.

## 1. Verdict per item

| Item | Verdict | Notes |
| :--- | :--- | :--- |
| P2-1 | pending | decision service + network segmentation built; live U1/U5/U8 re-reproduction and mutation testing pending |
| P2-2 | pending | exclusivity verification built and unit-tested; live decision-service confirmation pending |
| P2-3 | pending | per-tool profile/exclusivity built and tested; mutation testing pending |
| P2-4 | pending | vault tool, credential boundary, and bypass tests built; live bypass run against the full production stack pending |
| P2-5 | pending | SPIRE-absent guard built and tested; mutation testing pending |
| P2-6 | pending | ADR-0008 and README written; final mapping-table pass pending |

## 2. Evidence

(Filled in per item as each completes its demonstrate/fix/demonstrate-after/test/mutation cycle.)

## 3. Mapping table

(Section 9 format, per `docs/reports/phase-1-3-complete.md`.)

## 4. Pre-registered negatives, individually confirmed

- [ ] Any failure path returning something other than DENY.
- [ ] Any credential reachable from the agent's principal that the gateway relies on for exclusivity.
- [ ] Any record with `exclusivity: demonstrated` that the gateway cannot verify.
- [ ] Any record missing profile or exclusivity kind.
- [ ] Any claim not in the mapping.
- [ ] Any assertion weakened.
- [ ] Any item met by live evidence alone with no test enforcing it.

## 5. Could not verify

(Filled in at the end.)

## 6. CI run id

(Filled in once pushed.)
