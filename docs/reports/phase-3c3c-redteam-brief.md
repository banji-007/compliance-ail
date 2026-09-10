# Red-team brief: Phase 3c-3c (ordering remediation)

**Run id:** `p3c3c-red`. Fresh session, clean context. Scratch clone, not the primary working directory. Explicit Compose project name on every invocation. Remove the scratch directory before reporting and say what you removed or could not remove.

**Target:** PR #14 at the branch head of `p3c3b-order`. Do not merge. Do not fix anything you find; report it.

## What you are doing

The build session made the claims below. Each is stated as a behaviour that could be false. Your job is to make one of them false, not to confirm them. A refutation is a command and its output. "I could not refute this" is a valid and useful verdict; a confirmation you did not test is not.

**This phase remediates one that failed eight of ten claims.** Its own reports are `docs/reports/phase-3c3c.md` and `docs/reports/phase-3c3c-complete.md`, and the pass it remediates is `docs/reports/phase-3c3b-redteam.md`. Reading the previous refutations first is worth the time: several of the mechanisms below exist because the previous claim about the same code was false, so the interesting question is usually whether the replacement is narrower than it reads.

Four standing cautions from this project's history, all of which have cost a session:

- **Controls here have repeatedly reported success while not running.** For any check you exercise, first establish that it can fail.
- **A ledger poisoned by one attack changes the arithmetic of the next.** `/audit` faults permanently once a position far above the counter is indexed, and `reconcile_once` reports every finding any earlier attempt left. Wipe between attempts, and note that the phase's own suite leaves a deliberate hole, a wrong-view record and a zero-scored row behind.
- **Set `COMPOSE_PROJECT_NAME` to whatever `-p` you brought the stack up under.** Several tests shell out to `docker compose` and will otherwise address a project that does not exist. The fallback rule keeps hyphens.
- **The local suite does not pass on this host** and never has: around 50 failures from `sigstore` being uninstallable in the host Python and from in-process tests that cannot resolve compose service names. Do not read a local failure count as a regression. CI is the authority.

## Claims

**C1. A committed write is always reported as committed, on both routes.** A proof failure after a commit returns the real transaction, the real position and `committed: true`; a write that did not commit returns `committed: false`. Attack the boundary between the two: a failure between the commit and the read-back, a read-back that answers about a different key, a `verifiedSet` whose commit is ambiguous. Establish whether any input produces `committed: false` for a record that is in the ledger, or `committed: true` for one that is not.

**C2. The fault record is written, joined, and never lost.** `ledger_fault:{call_id}` is claimed to be written for every committed-unverified write, joined to its page row by an exact `getall`, and preserved as a prior version when a second fault lands for the same `call_id`. Attack all three. In particular: a record whose value carries no `call_id` is keyed by a digest instead, and nothing on a page can join that - establish whether such a record can reach a page, which the build session argued it cannot and did not test.

**C3. The decision path cannot reach the one write that needs no proof.** `_set_without_verification` is bounded by a `record_type` guard, by having exactly one caller, and by `POST /write` refusing a `ledger_fault` from outside. **Two of those three are asserted by parsing source rather than by driving the system.** Find any input, route, or record shape that puts a non-fault record through an unverified write, or that gets a caller-supplied fault record into the ledger.

**C4. `POST /write` refuses a decision, an intent, or a fault record.** Two independent conditions, key prefix and `record_type`, either of which refuses. Defeat both: a decision record under a key shape neither names, a record whose `record_type` is absent or renamed, a value that is not JSON, a value that is JSON but not an object, a key that differs from the refused prefixes by encoding.

**C5. The reserve cannot be raised after allocation, and every reader refuses on disagreement.** The value is bound under `KeyMustNotExist` in the allocating `ExecAll`. Attack the binding itself rather than the readers: a ledger that was already allocating before this phase (where the binding attaches to the *next* allocation, which the build session reasoned about and never ran), two writers racing the first bind, a reserve key written directly, a reserve key deleted or shadowed. Establish whether a deployment can end up bound to a value it never allocated against.

**C6. Reconciliation finds a record absent from every page.** Three clauses: view membership, the allocated range in both directions, and no position in two views. Find a corruption none of them covers. The third clause is scoped to live positions and the second treats non-integer positions above the reserve as unallocated; establish what a position *at* the reserve boundary, or a position shared between a view and the backfilled range, contributes.

**C7. The ordering fault response claims nothing the page check cannot observe.** `transient` is gone and `scope`, `on_retry` and `authoritative_check` replaced it. Read those three strings as a caller would and establish whether any of them is still a claim about persistence, or about a check that does not run.

**C8. The reconcile-only anchor service cannot anchor.** It holds no anchoring key, reads no `/state`, submits nothing, and a whitelist over its settings and mounts is claimed to make that durable. The whitelist is itself a list. Find a way to anchor from that stack, or to make the service reach a public log, that the whitelist does not constrain.

**C9. No image built from the repository root carries key material.** Checked by searching inside four images for `*.key` and the vault token. Defeat the search rather than the claim: material under a name it does not match, material in a layer the search does not walk, material reachable to the running container by another route.

**C10. Every copy of a ledger name, key or ceiling agrees.** `tests/test_ledger_vocabulary.py` compares named constants across five modules. It cannot see a module that hardcodes a string and defines no constant, and the build session said so. Find a sixth reader, or an inline literal in one of the five, that disagrees with the others.

## Also

Two things the build session flagged as its own weakest points, listed so you do not have to find them first: C3's parse-based bounds, and C2's digest-keyed fallback.

Two claims that are **not** this phase's and are out of scope except as context: `fault_class: verifier_unreachable` covering two outcomes (deferred, `TODO.md`), and every service mounting every writer's key (deferred, `TODO.md`). Both are recorded as known. Refuting something *else* about them is in scope; restating them is not.

## Report

Inline, and as a report in `docs/reports/` named for this pass the way `phase-3c3b-redteam.md` is named for the last one. (Not written as a path here: `tests/test_docs_references_resolve.py` refuses a reference to a document that does not exist yet, correctly, and a brief naming its own unwritten output is exactly that.) Per claim: refuted, not refuted, or could not test, with the command and output. Name anything you found that is not on this list.
