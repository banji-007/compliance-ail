# Phase 3c-3d: Fault records, route refusals, and the 3c-3c red-team set

**Run id:** `p3c3d-fix`. State run id, working directory, branch first. Not the primary working directory. Explicit Compose project name on every invocation. Remove your scratch directory before reporting and say what you removed or could not remove.

**Base:** `p3c3b-order` at its current head, continuing PR #14. No rebase, no second PR, no merge. The branch history is the evidence trail for phase 3c and stays intact.

## Objective

Everything Phase 3c-3c claimed is true, or is scoped down to what it can support.

The red-team pass (`p3c3c-red`) refuted nine of ten claims. A key-shape probe (`p3c3d-keyprobe`) then established that the decision I made in response, D38 as originally written, was a rename that closed nothing.

## Reading

Both are in this repository, landed in the same commit as this instruction, and both are required reading.

- `docs/reports/phase-3c3c-redteam.md` is `p3c3c-red`'s report, transcribed rather than authored by the session that committed it.
- `docs/reports/phase-3c3d-keyprobe.md` is the key-shape probe. Every measurement cited below is in it.

An earlier draft of this instruction cited both before either existed, which is itself the failure this phase is about: `aaa0edd` is titled "docs: do not forward-reference the report the brief asks for", and it was the third instance. They exist now. **Read them; do not take this instruction's summaries as the evidence.** Where an item below restates a reproduction, the restatement is a pointer, and the report is what you reproduce against.

You are expected to challenge any item that does not serve the objective, or whose Claim cell would describe a goal rather than a behaviour. Raise it before building.

**Two decisions on this exact question have now been locked off probes that answered the question asked rather than the question that mattered.** First: prior versions are readable, so keep the single key; nobody asked what a second version does to a page. Second: composite keys de-shadow; nobody asked whether the chosen component varies between two faults about one record. If an item below rests on a premise you can check and it does not hold, that is the finding, not an inconvenience.

## Standing rules

Escalate rather than substitute. Never widen or weaken an assertion. No em dashes. Each item has a **demonstrate** half, an **enforce** half, and a named **mutation** that must fail the suite. Reproduce each defect before fixing it.

---

## Sequencing

**P3c3d-1 lands first and separately, before anything else in this phase.** It is a few lines, it closes two paths that are live right now, and it is the control the shadowing story actually calls for. The key change is then argued on what it fixes rather than on an attacker story the refusal already answers. Nothing else here depends the other way round.

---

## Decisions

### D39. The ordered route carries the refusals, and a record key is written once

`_refuse_reason_for_plain_write` is wired into `POST /write` (`verifier/main.py:724`) and is not called by `write_ordered` (`:1146`). Every bound Phase 3c-3c claimed sits on the plain route. `/write-ordered` refuses nothing, which is why A7's twelve shapes were a true statement about a route that no longer carries decisions.

Two live consequences, both measured by the probe (keyprobe report section 12): a caller holding only `VERIFIER_WRITE_KEY` writes a `ledger_fault:` key that the page renders as the ledger's own account of a record's standing, with attacker-chosen `fault_class`, `committed_tx_id` and timestamp; and the same write is allocated a position, so arbitrary rows with `outcome_type: null` become page entries and `entries` exceeds `total`.

The ordered route applies the same refusals. Separately, a record key is written under `KeyMustNotExist`: re-writing an existing record key silently gives it a second index entry at a second position, both resolving to the key's current transaction, which the order check reads as a disagreement at every limit. Two ordinary well-formed writes, no corruption and no privileged access, deny the whole audit page permanently.

`_REFUSED_KEY_PREFIXES` matches on `b"ledger_fault:"`, which is still a prefix of the composite shape below, so this refusal covers both key shapes with no change. D39 and D38 are independent.

### D38 (revised). Fault key carries a transaction and a nonce

Original D38 was `ledger_fault:{call_id}:{tx_id}`. Measured, that is a rename: the transaction available at key-construction time is `committed_tx_id`, the qualified record's own transaction, which is fixed per record, so two faults about one record produce the same key and the second is a new version of the first exactly as today (`revision=2`, range read returns one key; keyprobe report section 8).

```
ledger_fault:{committed_tx_id:020d}:{call_id or "key:" + sha256(record_key)[:32]}:{nonce}
```

`nonce` is `uuid4().hex[:16]`, generated in `_write_fault_record`.

**The transaction separates faults about different records; the nonce separates faults about the same record. Neither substitutes for the other.** Both halves of that sentence belong in the decision text.

The transaction is not merely a page-bound component. `tool_call_intent:` and `tool_call:` for one call carry the same `call_id` and both take the ordered route; the erasure tombstone takes `POST /write` with that same `call_id`. All three can fault. Under `ledger_fault:{call_id}` an intent fault, a decision fault and a tombstone fault for one call collide and silently replace each other, non-adversarially, with no second writer involved and D39 doing nothing about it. A scheme keyed on `{call_id}:{nonce}` would re-merge them and would also drop the bounded page read.

`020d` because uint64 max is 20 digits and the ledger is append-only, so a narrower pad is a bet that cannot be un-made. The probe measured both silent failure modes past a short pad: over-width keys pulled into a window that should exclude them, and a window whose bound is over-width returning empty, both at HTTP 200.

**Ordering between two faults about one record** comes from the `scan` entry's own `tx`, which the read that already ran returns. It costs nothing and no timestamp component is needed to get it.

**The fault key is no longer derivable from a page row.** That derivability is what is being given up, deliberately, and it is what D38's original form preserved by closing nothing. Anything that needs to name a specific fault key gets it from the write response's `fault_record`, which already carries it.

### D40. `committed` is a fact about the ledger

`verifier/main.py:792` calls `currentState()` inside the same `try` as `verifiedSet`, under a broad `except Exception` that returns `committed: false`. Measured: a write that committed, proved, and advanced the verifier's persisted anchor to tx 153 was reported as never having happened, because the client's next RPC failed.

The proof call and the state call are separated. `except Exception` never produces `committed: false`. Committed describes what is in the ledger, not whether a subsequent call succeeded.

### D41. A fault is verified before it is rendered as a record's standing

Nothing on the read path checks `writer_signature` or `writer_key_fingerprint` before `/audit` renders a fault. D39 closes the write path; D41 means a fault that arrived some other way is not presented as the ledger's account of anything.

**State the asymmetry, do not leave it to be inferred.** D41 adds a D22 writer-signature check on the read path **for faults only**. `/audit` renders decision records without checking their writer signature, and at the default `verify=false` without checking their inclusion proof either. That is deliberate and defensible: a fault is presented as authoritative metadata about *another* record, whereas a record's own state is explicitly reported as `asserted` and is never self-certified (D2, ADR-0006). Written down, it is a considered boundary. Unwritten, it reads as an inconsistency and invites someone to extend the check to every row on the default page, which is the per-record round trip D29 removed. **Do not extend it.**

State the ceiling with it: every service mounts `./keys:/keys:ro`, so a fingerprint names a key and not a component (ADR-0012, corrected in 3c-3c). D41 is worth having and its ceiling is the D22 split.

### D42. A bounded read asserts on what came back

An unrecognised or misspelled parameter is silently dropped by the REST route, so a bounded read degrades to an unbounded one at HTTP 200 with nothing in the response saying so. `endkey` for `endKey` is the whole distance between a correct read and a wrong one.

**Key-range scans:** every bounded read asserts that every returned key falls within `[seek, end)`. That is the assertion that bites, because a dropped bound only shows up when something out-of-window comes back.

**Score-bounded reads are a separate case and need their own form.** The view-index reads are `zscan` bounded by `minScore`, not by keys, so the key-range assertion does not apply to them and must not be bolted on. Their equivalent is that every returned row's score falls within the requested score bound, read from the row's own `score` field with `.get("score", 0.0)` because protobuf omits a zero score (`docs/reports/phase-3c3c-probe.md` section 1). Implement both forms; do not skip the `zscan` reads and do not invent a third thing.

---

## Items

### P3c3d-1. The ordered route refuses what the plain route refuses

Implement D39. **Lands first, separately, before the rest of this phase.**

**Demonstrate:** a caller-authored `ledger_fault:` write refused on `/write-ordered`. A forged fault no longer replacing a genuine one on the page. An injected row with `outcome_type: null` refused, and `entries` no longer exceeding `total`. A re-write of an existing record key refused under `KeyMustNotExist`, and the audit page surviving it.

**Enforce:** a test for each of the four.

**Mutation:** remove the refusal from the ordered route. Named test must fail. Second mutation: drop `KeyMustNotExist`. Named test must fail.

State in the report that `_REFUSED_KEY_PREFIXES` covers both key shapes unchanged, so this item and P3c3d-2 are independent.

### P3c3d-2. Two faults about one record both survive, and three record kinds do not collide

Implement D38 as revised.

**Demonstrate:** three faults on one record, all three readable, none shadowed, ordered by the `scan` entry's own `tx`. Then the non-adversarial case: an intent fault, a decision fault and a tombstone fault for one `call_id`, all three surviving, which under the old shape is one row and two hidden.

**Enforce:** a test for each.

**Mutation:** remove the nonce. The three-faults-one-record test must fail. Second mutation: key on `{call_id}:{nonce}`. The three-record-kinds test must fail.

### P3c3d-3. The page read is bounded by the page

One paginated, half-open range scan over the page's own tx window:

```
seekKey = f"ledger_fault:{min_tx:020d}"      inclusiveSeek = True
endKey  = f"ledger_fault:{max_tx + 1:020d}"  inclusiveEnd  = False
limit   = 2500, cursor on seekKey, stop when len(entries) < limit
```

`min_tx`/`max_tx` over both zscans, decision and intent, not the decision page alone, since synthesized intent rows carry their own transactions. Filtering back to the page is client-side membership; the range is a superset, never a subset.

**Take the window from the rows the response will render, after the `limit+1` truncation, not from the fetched set.** Both are safe, because a window taken from the wider set is a superset and a superset cannot exclude a page row. Pick the rendered set anyway and say so, because "bounded by the page" is the property under test and a reader must not have to work out which set was meant.

**An empty page has no window.** Zero rows means `min_tx` and `max_tx` are undefined, and the range read is **skipped**, not run with a degenerate or invented bound. A page with rows but no faults is a different case and runs the read normally.

Half-open `hi + 1` with `inclusiveEnd=False` is required: a bare padded `hi` sorts before that transaction's own faults and silently drops the last row of the page.

**Demonstrate:** a page whose faults are all returned in one bounded read, against a ledger with faults outside the window. The single-tx window case (`lo == hi`). A window needing more than one page, terminating correctly. An empty page, with no range read issued.

**Enforce:** a test for each, plus D42's range assertion on the read.

**Mutation:** make the end bound inclusive on a bare `hi`. Named test must fail. Second mutation: misspell the bound parameter. The D42 assertion must fail rather than the read silently widening. Third mutation: take the window from the fetched rather than the rendered set. This one must **pass**, and the report says so: it is the check that the property is superset-safety and not an arbitrary preference.

### P3c3d-4. Legacy faults still render

Every `ledger_fault:{call_id}` already committed keeps that shape permanently. The existing exact `getall` is kept and stays fused with the tombstone join; the range read is added beside it.

**What this costs, stated correctly.** The `getall` keeps **exactly today's keys, unchanged**. No keys are added to it, because under the nonce the new-shape key is not derivable from a page row and cannot go into a `getall` at all. The whole added cost is the range read: **two round trips per page against one today.**

The keyprobe report's section 11 table carries a `BOTH` row at 300 keys and +5.7 ms. **That row measures the exact-derivable variant D38 abandoned and does not describe this item.** Do not reproduce it and do not report a figure as matching it. The headroom figure in that section does stand on its own: a 3000-key `getall` is one round trip at 162 ms, so the legacy half has ample room.

No README limit is needed.

**Demonstrate:** a page carrying both an old-shape and a new-shape fault, both rendered.

**Enforce:** a test asserting both.

**Mutation:** drop the legacy read. Named test must fail.

### P3c3d-5. A fault is verified before it is rendered

Implement D41.

**Demonstrate:** a fault with a bad or absent writer signature not rendered as a record's standing.

**Enforce:** a test for it.

**Mutation:** skip the check. Named test must fail.

Residual Limits carries the ceiling: the fingerprint names a key, not a component, until the D22 mount split. The report states the read-path asymmetry D41 names, as a considered boundary rather than an oversight.

### P3c3d-6. `committed` is a fact about the ledger

Implement D40.

**Demonstrate:** the probe's cut case on the plain route. The write reported with its real transaction and `committed: true` while the state call fails. The persisted anchor and the response agreeing.

**Enforce:** a test on the response under a failing state call.

**Mutation:** return the state call to the proof call's `try`. Named test must fail.

### P3c3d-7. The GDPR erasure path

A1 lands here. `_write_tombstone` raises on not-committed and `erase_content` turns that into a 503 without deleting, so a tombstone that commits while the response says `committed: false` produces exactly the `erasure_conflict` P3c3c-12 claimed to remove: 503 to the caller, tombstone in the ledger, payload still in the store, content writes frozen at 409, the subject's data unerasable through the documented route and unwritable.

D40 fixes the cause. This item proves the path.

**Demonstrate:** the probe's attack sequence, with the erasure completing.

**Enforce:** a test for it.

**Mutation:** revert D40. Named test must fail.

Separately: `_tombstone_present_in_ledger` reads the head and asks only whether a tombstone exists, never whether it is the one this call just wrote, so a pre-existing tombstone satisfies a later confirmation. Narrow, real, and it is a correctness question on the GDPR path. Fix it or state why not.

### P3c3d-8. A fault for a record with no `call_id`

Two findings, neither of which was the probe's question. Both are in keyprobe report section 7.

`verifier/main.py:597` justifies the fallback with "a record with no `call_id` never reaches a page". Measured false: such a record reaches a page, and the row's `ledger_key` is the base64 raw key, so `sha256(record_key)[:32]` is derivable from a page row today. Correct the comment.

Separately, `_tombstones_and_faults` is only ever handed `page_call_ids`, built at `control_plane/main.py:1571-1577` with `if log_entry.get("call_id")`, and its decode loop drops rows at `:1221`. A fault for a no-`call_id` record is therefore never joined onto a page under any key shape, including today's. This predates D38 and closes for free under the tx-window read, which selects on the window rather than on an identity the row may not have.

**Demonstrate:** a fault for a no-`call_id` record joined onto its page row.

**Enforce:** a test for it.

**Mutation:** restore the `call_id` filter on the join. Named test must fail.

### P3c3d-9. The red-team blocking set

Each of these is a defect the red team reproduced. No decision needed; reproduce, fix, enforce, mutate. The bullets below are pointers into `docs/reports/phase-3c3c-redteam.md` sections A5, A6, A9, A10, A7 and the keep-alive diagnosis; read the section before working the bullet, and reproduce each one yourself before fixing it.

- **Reserve upper bound.** `validate_reserve` bounds below only. A reserve at or above 2^53 makes positions unrepresentable as distinct float64 zscan scores: six writes produced four scores, a response named a position the index does not hold, and `/audit` was dead at every limit from the sixth write on a virgin ledger. All four readers agreed on a number that cannot work.
- **Below-reserve duplicates.** Any score below the reserve is assumed to be history and is never checked against live positions, so an already-indexed record given a second position under the reserve reconciles `clean` while the page shows the row twice. C2's duplication wearing history's clothes, and the fault body points operators at this reconciliation.
- **The fifth vocabulary module.** `tools/ail_ordering_cost_probe.py:52` defines `VIEW_DECISION` as a named constant and is not compared; `_modules()` loads four while the completion report's own table counts five. Fix both, and note that under D38 what has to agree is the whole key format, not the prefix constant.
- **Image contents by content, not filename.** `test_image_contents.py` matches `*.key` and `vault_api_token` with directory prunes. Three live P-256 private keys in an image passed it. Detect key material by content. The static second line flags a `COPY` only if the line contains `keys/` or `secrets`, which `COPY decision_service/ ./` does not.
- **Non-string `record_type`.** An unhashable value against `_REFUSED_ON_PLAIN_WRITE` raises `TypeError` and returns 500 on a route whose job is to refuse deliberately. Fail-closed, but unhandled.
- **`--timeout-keep-alive`.** The intermittent failure that survived three passes is an HTTP keep-alive race: a module-level pooled `httpx.Client` against uvicorn's 5s default, demonstrated causally by moving the setting and watching the window move with it. Set it explicitly and record the diagnosis.

### P3c3d-10. Prose and tests that become false

Budgeted as work, not treated as fallout.

Prose asserting the old key shape or the exact join:

- `control_plane/main.py:1189` claims `ledger_fault:{call_id}` is derivable from a page row exactly as a tombstone key is. False under a nonce; that derivability is what is being given up.
- `verifier/main.py:550-563` claims the join is the same exact `getall` the tombstone join uses. Half true after D38: legacy is, the new shape is not.
- `readME.md:533`, `docs/adr/0005-outcome-taxonomy.md:254`, `docs/adr/0014-ordered-audit-view-index.md:222` all spell the key as `ledger_fault:{call_id}`.

Tests constructing the old key string: `tests/test_ledger_faults.py:311` asserts `body["fault_record"] == f"ledger_fault:{call_id}"` exactly; `:313`, `:340`, `:517` build the same string.

Sweep for others rather than fixing only these. Correct each at its source: the README bullets cite the ADRs, and fixing only the README is the citing-document-and-cited-source shape already documented twice in this phase.

### P3c3d-11. The fault count is a count of faults

Lands with P3c3d-3, because that is where the number now comes from.

`control_plane/main.py` sets `"count": int(raw.get("revision", 1) or 1)` on the `/audit` row's `ledger_fault`. That was D35's free count and it was correct only because the single key was rewritten in place. Under D38 each fault is its own key written once, so `revision` is permanently 1 and the field reports one fault where three exist. **That is the failure D38 exists to fix, surviving inside the field that describes it.**

The count is now the number of range hits for that record. Take it from there.

The same edit answers the shape question, which is an `/audit` contract change either way and must not be left implicit: with multiple faults per record, does `ledger_fault` stay one object (the most recent fault, with a real count) or become a list of them? Either is defensible. Choose, state the choice and its reason, and record it as a contract change in the report.

There is no consumer to break: `ledger_fault` appears nowhere in `dashboard/`, and no test asserts `count`. Verify both rather than taking this sentence for it.

**Demonstrate:** a record with three faults whose row reports three.

**Enforce:** a test asserting the count and the chosen shape.

**Mutation:** return the count to `revision`. Named test must fail.

### P3c3d-12. The unverified-write path is bounded by something that holds

A3 in the red-team report. Both of the bounds Phase 3c-3c claimed were defeated, and neither was on the earlier draft of this instruction. It is here because the objective is that everything 3c-3c claimed is true or is scoped down, and A3 is claimed.

**The runtime guard checks a different object from the one it writes.** `_set_without_verification` inspects the `record` dict while the bytes committed are `value`; nothing requires them to agree. Driven live, a `record` argument claiming `ledger_fault` with a decision record as `value` wrote `tool_call:a3probe001` at tx 159 with `record_type=decision, outcome=policy_allow`, through the one path in this system that requires no proof, with no position and no index entry.

**The static parse is defeated by a binding.** The test counts lines containing `_set_without_verification(` with the paren. `_unverified_write = _set_without_verification` has none, so a second caller through the alias is invisible: the parse found one caller where the file had two.

No external caller reaches this today. That is not what was claimed. The guard and the parse were claimed to make it a property rather than a coincidence, and neither does.

**Demonstrate:** both defeats reproduced, then closed. The guard deriving its check from the bytes it is about to write rather than from a parallel argument. The parse seeing an aliased caller.

**Enforce:** a test for each.

**Mutation:** pass a `record` that disagrees with `value`. Named test must fail. Second mutation: add an aliased second caller. The parse test must fail.

If closing the parse properly means replacing it with something that is not a line count, say so and do that; a parse that can be defeated by removing a paren is the second line in name only.

---

## Pre-registered negatives

All false at the end, each confirmed individually and derived per row.

- Any caller-authored record accepted on `/write-ordered` that the plain route would refuse.
- Any record key writable twice through the ordered route.
- Any two faults about one record where the second replaces the first.
- Any two faults about different records sharing a `call_id` that collide.
- Any page-side fault read whose bound is not derived from the page.
- Any range read issued for a page with no rows.
- Any bounded read that does not assert on what came back, in the form its bound takes.
- Any response reporting `committed: false` for a write that committed.
- Any erasure refused to the caller while its tombstone is in the ledger.
- Any rendered fault count that is not the number of faults.
- Any record reaching the unverified-write path whose committed bytes were never the bytes the guard checked.
- Any caller of the unverified-write path invisible to the check that counts them.
- Any prose or test still asserting the old key shape.
- Any figure reported as matching the keyprobe report's abandoned `BOTH` row.
- Any Claim cell describing a goal rather than a behaviour.
- Any assertion weakened, or any refutation closed by narrowing the claim without saying so.

## Report

`docs/reports/phase-3c3d.md`. Verdict per item, the reproduction before the fix, demonstration, enforcing test, mutation result, mapping, could-not-verify, CI run id. State explicitly which of A1 through A10 are now true and which were scoped down instead, naming them by the red-team report's own labels so the two documents can be read side by side. A7 was not refuted and needs no item; say so rather than leaving it unmentioned.
