# Review protocol

Durable process document. Applies to every phase. Lives in the repo because neither reviewer carries reliable context between sessions.

---

## 1. The loop

1. Architect writes the phase instruction with pre-registered acceptance criteria.
2. **Build session.** CC implements. If a criterion cannot be met without a design change, it stops and escalates.
3. CC writes the phase report: verdict table, could not verify, worked around, cumulative gate, discovered outside scope.
4. **Red-team session.** A separate CC invocation with a clean context attacks named claims from the phase.
5. Architect reviews conformance and plan impact.
6. Arbitration by the project owner where the disagreement is a judgment call. Factual disputes are settled by running a command, not by argument.
7. Criteria become permanent tests. The gate is cumulative.

Steps 2 and 4 must not share a session. The value of the red-team slot comes from having the tree without having the memory of building it.

Work is committed to a branch and pushed before step 4, so CI runs and the diff is reviewable. A phase that ends with start SHA equal to end SHA has not finished.

Every instruction carries a unique run id. A session's first reported action states the run id, its working directory, and its branch. A session that finds another branch for the same run id, or a dirty primary directory, stops and reports rather than proceeding. Sessions never run in the primary working directory.

Before deleting a branch, enumerate what is unique to it and confirm each item either exists on the target branch or is intentionally discarded. Use git diff --stat against the target, not a recollection of what was ported.

---

## 2. Writing acceptance criteria

Most of the gaps found in Phase 0 review traced back to criteria written loosely enough that a reasonable implementation could satisfy the words without satisfying the intent. The rules below exist to close that.

**State the property, not the activity.** "The digest comes from OPA" describes where a value was fetched. "The digest equals the SHA-256 of the bundle content OPA evaluated, obtained in the same evaluation that produced the verdict" describes what must be true of it. Only the second can be refuted.

**Name the falsifier.** Every criterion states the observation that would disprove it. If no observation would, it is not a criterion, it is a preference.

**No bare counts.** "Collected item count rises to 34" is satisfiable by collecting anything. "Count of tests containing at least one assertion rises to N, listed by name" is not. Any metric that can rise without the underlying property improving is banned.

**Every criterion is a command.** State the command and what its output must show. If a criterion cannot be reduced to something whose output pastes into a report, rewrite it.

**When alternative routes are permitted, state the invariant both must preserve.** Phase 0 offered two implementation routes for the policy digest and specified the preference but not the property, so the weaker route was available and conformant. If route B is acceptable, say what route B must still guarantee.

**Pre-register the negatives.** What must not be true at the end. No new placeholder values, no widened assertions, no collector narrowed to satisfy a count, no new fail-open path.

**Distinguish what is measured from what it stands for.** If a number is a proxy for a property, the criterion is on the property.

---

## 3. Standing rules for build sessions

- No design changes. If a criterion cannot be met without altering architecture, adding a dependency, or changing a schema: stop and escalate. Escalation is a successful outcome. A criterion met by quietly redesigning is a failure even if tests pass.
- Never widen or weaken an assertion to make a test pass. If collecting or narrowing a test reveals it fails, report it and leave it failing.
- Report format is fixed. "Could not verify" and "worked around" are mandatory and are not optional if empty; state that they are empty only if true.
- Comments explain why, not what. No change-history narration. No em dashes, code or prose.

---

## 4. Red-team sessions

**The brief is a list of named claims, each phrased as a falsifiable assertion.** Not "review the phase." A claim the red team cannot disprove is information; an open invitation to review produces paraphrase.

**Rules:**

- A refuted claim is a successful outcome for the session and for the project. There is no credit for confirming.
- Attempt actual disproof. Run something. A claim marked HOLDS on the basis of reading code is marked HOLDS WITH READING ONLY, which is a distinct and weaker verdict.
- Do not fix anything. Do not propose fixes. Findings only.
- Do not restate the build report's own disclosures as findings. Material the report volunteered is not a discovery. If a disclosure is worse than the report characterises it, that is a finding, and say why.
- Report attacks that were attempted and failed. A red team that lists only hits gives no information about coverage.
- State what could not be tested and what blocked it.

**Verdicts:** `HOLDS`, `HOLDS WITH READING ONLY`, `REFUTED`, `UNTESTABLE`. One per claim, with evidence as a command and its output or a `path:line`.
