# Red-team brief: Phase 3c-3f (selectors and the trust anchor)

**Run id:** `p3c3f-red`. Fresh session, clean context. Scratch clone, not the primary working directory. Explicit Compose project name on every invocation.

**Target:** PR #14 at `cc06ed4`, branch `p3c3b-order`. Do not merge. Do not fix anything you find; report it.

**Read first:** `docs/reports/phase-3c3e-redteam.md` (the six refutations plus the Also item this phase answers), `docs/reports/phase-3c3f.md` (what this phase claims to have closed, and its section 2, which records six places the delivered fix differs from what was asked for), and the erratum now at the end of `docs/reports/phase-3c3e.md`.

**Your report is committed before this session closes.** Write it beside the other red-team reports in `docs/reports/`, named for this run, and commit it yourself.

**This pass decides the merge.** PR #14 merges on this verdict if what you find needs no new mechanism. Two things follow from that. A clean verdict is worth less than it looks: one earlier pass in this sequence came back clean and was wrong, and the counts since are eight, nine, six, six, which is a plateau rather than a convergence. And the distinction that matters in your report is not severity but **whether a finding is an application of the phase's mechanism or a gap in it** - say which, per finding, because that is the question the merge turns on.

## What you are doing

The claims below are behaviours that could be false. Make one false. A refutation is a command and its output. "I could not refute this" is a valid verdict; a confirmation you did not test is not. For every check you exercise, establish first that it can fail.

**This phase's subject is the selector, so the highest-value attack is a selector with no falsifier.** Last pass found two enumerations built on selectors narrower than the property they claimed, and neither file said which set it meant. D46's answer: the property is written down first, in the module, in its own words; the selector is then a claim about covering it; and the selector is falsified in **both** directions - a case that satisfies the property and not the selector, and a case that satisfies the selector and not the property. Where a direction has no instance, the test says so rather than omitting it.

Every previous pass in this sequence found the same shape one level up from where the last one looked. Constants, then guarantees, then selectors. **Look one level up again: a selector underneath a selector, a check about a check, an exemption whose criterion is not an argument.** Three specific ones are named below because I know where I made judgement calls; they are a floor, not a ceiling.

**Start here.** `tests/test_route_parity.py::_service_routes` is the selector underneath `write_routes()`. It discriminates on `route.endpoint.__module__ == verifier.__name__`, to exclude the four routes FastAPI adds to every app. It is derived rather than hand-listed, which is why it was chosen - and **it carries no falsifier in either direction**, in the file that implements D46. Establish what it cannot see. A handler defined in another module and imported; a router included from elsewhere; anything that makes a write route's endpoint report a different `__module__`. If that lands, it is not a bug in a test, it is D46 not applying to itself, and it is the kind of finding that needs new mechanism.

## Claims

**C1. The write-route enumeration produces every route that durably changes what this service holds.** `WRITE_ROUTE_PROPERTY` is stated in `tests/test_route_parity.py` before anything selects for it, and it includes the persisted trust anchor deliberately, not only ledger records. The selector is the `_require_write_key` dependency under any verb. Attack the property and the selector separately: a route that changes durable state and is not selected, and the selector underneath the selector named above. `test_every_selected_route_durably_changes_state` records that direction two has no instance in the tree; find one.

**C2. The bounded-read enumeration finds every bounded read, over both transports and including `tests/`.** REST sites by route literal through `url=`, concatenation and one level of name resolution; gRPC sites by `scan`/`zScan`/`zscan` carrying an SDK bound keyword. Three limits are stated in the module: a read behind an argument-taking helper, a gRPC bound passed positionally, and name resolution stopping at one hop. Stating a limit is not checking it. Turn one into a bounded read that decides something and is not enumerated.

**C3. The bound assertions are not vacuous.** Nine reads in `tests/` route their check through `tests/bounded_read_checks.py`. Each passes the bound it asked for, and **nothing enforces that it passes the right one.** In `_view_rows` the check runs before `min_score` is updated; move the update above the call and every one of those assertions passes against any answer, with no test failing. Establish whether that is reachable, and whether any of the nine already passes an argument that makes its check weaker than it reads. This is the phase's own defect class one step further along and it is the second place I would look.

**C4. The third state is a recorded decision rather than an omission.** `does_not_apply` in `COVERAGE`, `UNGATED_BY_DESIGN` in the parity file, and `tests/ledger_pollution.py`'s registry all admit an exemption on the strength of a reason. **The criterion enforcing that reason is `len(reason) >= 80`.** A word count standing in for an argument. Write an eighty-character sentence that reads like a decision and exempts a read, a route or a row that genuinely needs the check, and establish what it then hides. The registry's `explains()` is still a substring match on a caller-controllable key segment and its "only exemptions in use" test still computes `breaks_something` as an `any` over all matching rows - recorded by the last pass, never driven.

**C5. The persisted trust anchor is never written or seeded from a state nothing verified.** D47. `verifier/main.py::head_state` reports the head without persisting it at three call sites; `_VerifiedRootService` covers `init`'s seed, `get`'s seed and `set`, checking the ImmuDB signature and refusing a backwards move. Attack all three entry points and the two things the class deliberately does not do: **the state file itself is read unchecked** (that is intentional, so that corrupting it stays the ADR-0006 tamper vector - establish whether that leaves a way to install an anchor), and **a state at `txId == 0` is accepted unsigned** so an empty ledger can boot. Get a server to report `txId 0` on a non-empty ledger and the seed is unchecked on a live one.

**C6. `POST /verify`'s new failure mode is the right one.** `head_state` verifies the head's signature inside the route's `try`, so a head whose signature does not check out now turns a **sound record proof** into `verified: false, signature_failure`. That is a behaviour change this phase introduced, it is not tested, and the report does not state it. Establish what a caller sees, whether `/audit` renders it as tamper evidence, and whether a transient signing-key problem can therefore mark good records as failed across a whole page.

**C7. A position is read from what came back, and both of `scan_all`'s bounds are driven.** `_committed_position_for` compares `entry.score` against the score it asked for and answers `None` on disagreement; `scan_all` refuses a page whose keys do not sort above the key it seeked from. `COVERAGE` is keyed per bound now and compares driven bounds against derived bounds in both directions. Attack the comparison: a bound the derivation attributes that no client can violate, a disagreement path that reports `None` where the truth was available, a third bound on either read that neither table names.

**C8. The detector's closed shapes stay closed, and the bounds it keeps are the only ones.** base64-of-a-PEM, gzip and the twenty-run cap are closed; the 16 KiB head bound is kept, with its cost measured at 3.1x and a second reason - a whole-file walk hits a published test key in `ecdsa`'s bytecode. Both surfaces and every encoding are still hand-listed and still say so. Ship a key. Nested compression, a compressed member past the head, an encoding outside the table, base64 of base64, a surface that is neither the running filesystem nor a `docker save` layer. The `_b64_candidates` re-padding added this phase is new code on the hot path: make it decode something it should not, or miss something it should.

**C9. A fault identity is judged on whether it can be written, not on its length alone.** Lone surrogates now take the digest fallback. Attack the judgement: an identity that passes both checks and still cannot be written, a record value that makes `_fault_identity` raise rather than fall back, a `call_id` whose fallback collides with another record's.

**C10. Every ledger-wide invariant holds over every view, and none of them asserts nothing.** Four invariants times two views; `VIEWS` is checked against the verifier's own `_VIEW_SETS`; the seam test seeds both sides rather than skipping. **Read that test's docstring before attacking it:** this phase found its ledger-wide assertion was a tautology over the partition it made, and moved the falsifiable content to where each writer places its position. Establish whether the replacement can fail, whether any of the other three can be made to assert over zero rows, and whether a violation exists in either view that no registry entry explains.

## Also

**Four claims from last pass were never refuted and are open targets, not settled ground.** Nothing in this phase touches them and the report says so:

- **B2.** A cut where a write committed and the response says `committed: false`, on either route. The relay fixture has four modes; the last pass could not aim it at `Get` while leaving `ExecAll` answering.
- **B3.** The `require_transaction=False` narrowing on the GDPR path. Its safety rests on `_has_tombstone`'s 409 in a different module with nothing tying the two together.
- **B7.** A path to `_write_fault_record` with a transaction nothing checked.
- **B9.** The no-proof write path's runtime guard. A well-formed fault record under the sequence counter's key is still writable and costs one call.

**Two unchecked surfaces in the teardown check, recorded last pass and never demonstrated.** `COMPOSE_FILES` is hand-listed and does not include `docker-compose.override.yml`, which `docker compose` loads by default when present. `STATEFUL_CONTAINER_PATHS` is an exact-match hand list, so a service writing to any other container path is skipped rather than reported. Both are ways a ledger survives `down -v`, which is the whole subject of that module. Drive them.

**And the phase's own record of what it got wrong.** Section 2 of `docs/reports/phase-3c3f.md` lists six corrections raised against the instruction, four of which changed what an item delivers - including a stated fix that was backwards and a stated mutation that cannot fail. Section 11.5 lists two more found by CI rather than by review. Read both and ask what else of the same shape is in there.

## Not worth your time, because they are already stated

Do not report these as new findings. Do establish whether anything else changed under them.

- `/write-ordered` accepts a key of any shape into a view.
- Nothing bounds how many callers reach the no-proof write path; the parse that counted them is retired, deliberately, with nothing replacing it.
- 35 test modules were never isolated, and isolation was per module rather than per test.
- An evidence bundle does not name a record's ledger fault.

## Known noise on the development host

Roughly fifty tests fail here before and after any change, from `sigstore` being uninstallable and from in-process tests that cannot resolve compose service names; part of that set moves with collection order because `tests/test_evidence_bundle.py` sets an environment override at import. **CI is the signal:** `33814949380` and `33817540597` are both green.

`test_a_write_that_committed_is_reported_as_committed_when_the_state_call_fails` is a standing flake on this host. Its only named candidate mechanism was tested and eliminated this phase - see the erratum on `docs/reports/phase-3c3e.md`. Do not re-derive the `_has_tombstone` path. Turning it into a reproducible defect is still a finding.

## Report

Committed before you close, beside the other red-team reports in `docs/reports/`. Per claim: refuted, not refuted, or could not test, with the command and output. **Per finding, say whether it is an application of D46/D47 or a gap in them**, because the merge turns on that. Name anything you found that is not on this list. Say which of your own checks you established could fail before trusting them. Enumerate anything you could not remove from the machine, by name, with the commands.
