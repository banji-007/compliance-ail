# Red-team brief: Phase 3c-3e (enumerated guarantees)

**Run id:** `p3c3e-red`. Fresh session, clean context. Scratch clone, not the primary working directory. Explicit Compose project name on every invocation.

**Target:** PR #14 at `bfb87fd`, branch `p3c3b-order`. Do not merge. Do not fix anything you find; report it.

**Read first:** `docs/reports/phase-3c3d-redteam.md` (the six refutations this phase answers), `docs/reports/phase-3c3d-order-sweep.md` (the order-dependence data D44 rests on), and `docs/reports/phase-3c3e.md` (what this phase claims to have closed).

**Your report is committed before this session closes.** Write it beside the other red-team reports in `docs/reports/`, named for this run, and commit it yourself.

## What you are doing

The claims below are behaviours that could be false. Make one false. A refutation is a command and its output. "I could not refute this" is a valid verdict; a confirmation you did not test is not. For every check you exercise, establish first that it can fail.

**This phase's subject is enumeration, so the highest-value attack is a site the enumeration cannot see.** Every previous pass found a rule that held at one place and was claimed everywhere. This phase's answer is to derive the site list from the code: write routes from `app.routes` filtered by their `_require_write_key` dependency, bounded reads from the scan and zscan call sites carrying a selective bound. **A derivation is only as good as its discriminator.** Find a write route the route walk does not produce, a bounded read the AST walk does not attribute, an encoding outside the table, a surface outside the table. That is worth more than any single property below.

**Four enumerations are hand-listed and say so.** Key encodings, inspection surfaces, the deliberate-violation registry, and the property list in the parity matrix. Each is argued for in its own module. Attack the argument, not only the list: an entry that exempts more than it claims, or a list whose omission is not the one it admits to.

**Two things you should not spend time on, because they are already stated.** `/write-ordered` still accepts a key of any shape into a view; `ledger_fault:` is refused and nothing else is, and the blast radius was measured last pass. And nothing bounds how many callers the no-proof write path has: the source parse that counted them is retired, deliberately, with nothing replacing it. Do not report either as a new finding. Do establish whether anything else changed under them.

**Known noise on the development host, so you do not chase it.** Roughly fifty tests fail here before and after any change, from `sigstore` being uninstallable and from the in-process tests that cannot resolve compose service names; part of that set moves with collection order because `tests/test_evidence_bundle.py` sets an environment override at import. CI is the signal: `33665124730` is green at 495 passed. Two tests are recorded as observed flakes on this host, both pre-dating this phase: `test_a_write_that_committed_is_reported_as_committed_when_the_state_call_fails` and `test_the_sequence_is_gapless_under_concurrent_writes`. If you can turn either into a reproducible defect, that is a finding.

## Claims

**B1. The write-route enumeration produces every route that writes.** `tests/test_route_parity.py` derives the list from `app.routes` and selects on the `_require_write_key` dependency, then requires each of four properties to be recorded as holding, or as not applying with a reason. Attack the discriminator. A route that writes without that dependency, a router mounted after the walk runs, a dependency attached by any means the walk does not read. Establish whether a write reachable from outside is covered by the matrix at all.

**B2. `committed` is a fact about the ledger on both routes, and `null` means only what it says.** D45 added a fourth response state: `true`, `false`, `null`. `false` is now supposed to be reachable only where nothing was written. Find a cut where a write committed and the response still says `false`, on either route. Then attack the other direction: a response saying `true` for a record that is not in the ledger, or `null` where the answer was in fact known. The relay fixture is in the tree with four modes; use it and extend it.

**B3. No legitimate retry is permanently denied, and no caller is told to make an impossible one.** D39's `KeyMustNotExist` and D40 interact. Establish what a caller sees across the whole sequence when the write commits and the confirming read cannot run, and whether any state exists from which a caller can neither retry nor learn what happened. The control plane asks the ledger itself when told `null`, through `require_transaction=False`; attack that narrowing on the GDPR path specifically.

**B4. Every bounded read in the repository asserts its bound, and the enumeration finds every bounded read.** A selective bound is `prefix`, `seekKey`, `endKey`, `minScore` or `maxScore`. The module admits one blind spot: a read issued through a helper that takes its bound as an argument. Find a second. Then attack the assertions themselves: a bound that cannot be violated in the direction asserted, or a read whose refusal leaves the pass in a worse state than proceeding would.

**B5. No image carries key material, in any enumerated encoding, on either surface.** Seven encodings and two surfaces, both lists hand-listed. Binary material is required to start at offset zero of a file or of a base64 body, and only the first 16 KiB of a file is read. Both are stated limits; turn one into a key that ships. An encrypted PEM, a key inside an archive, a key past the head bound, a surface that is neither the running filesystem nor a `docker save` layer.

**B6. A fault key is bounded, and a fault that cannot be written fails loudly.** `call_id` is refused as a key component past a measured budget and the digest fallback is used, so the fault is still written. Attack the budget arithmetic and the fallback: a `call_id` that fits but produces an unwritable key by some other route, a record whose key is itself long enough to matter, a fault that fails to write for a reason the response does not carry.

**B7. A fault key's transaction is derived from the committed record and cannot be caller-supplied.** The writer reads it back and refuses on disagreement; the page refuses a fault whose key and body name different transactions. The report states what the reading half cannot catch. Establish whether the writer's derivation can be made to derive the wrong number, and whether any path still reaches `_write_fault_record` with a transaction nothing checked.

**B8. Deleting the legacy fault read lost nothing and closed A7.** `ledger_fault:{call_id}` is no longer read by `/audit`. The justification is that no ledger outside CI has ever held a fault record, half of which is asserted (`tests/test_ledger_state_does_not_survive_teardown.py`) and half of which is recorded rather than derived. Attack the asserted half: a way for ledger state to survive `down -v` that the compose parse does not see. Then establish whether the count on a page row can still be made to exceed the faults that exist, by any route.

**B9. The runtime guard on the no-proof write path still holds.** It reads the bytes it is about to commit and refuses anything that is not a fault record; `tests/test_route_parity.py` asserts over every derived write route that a failed proof makes exactly one unverified write, whose bytes are a fault record about the record just committed. The previous pass could not get a non-fault record past the guard but did write a well-formed fault record under the sequence counter's key. Establish whether that is still reachable, and what it now costs.

**B10. No test this phase owns is order-dependent, and the ledger-wide invariants are enforced against everything the suite did not deliberately break.** The four previously order-dependent tests are scoped; the ledger-wide statements moved to `tests/test_view_invariants.py` with a registry checked in both directions. Attack the registry: a violation its fragments accidentally cover, an entry that exempts an ordinary row, a ledger-wide invariant that can be made false without any entry explaining it. Then permute the order yourself and find a fifth.

## Also

**The fixture retry is a legitimate target.** `cut_until_it_lands` retries the relay up to four times when the cut missed, and the report argues it retries the fixture and never the assertion. Establish whether it can mask a real defect: a code path that intermittently reports the wrong thing would be retried past, and the test would go green on the attempt that happened to behave.

**And one thing the report itself flags.** Three defects in this phase's own work were found by CI and by the order sweep rather than by review. Read what they were and ask what else of the same shape is in there.

## Report

Committed before you close, beside the other red-team reports in `docs/reports/`. Per claim: refuted, not refuted, or could not test, with the command and output. Name anything you found that is not on this list. Say which of your own checks you established could fail before trusting them. Enumerate anything you could not remove from the machine, by name, with the commands.
