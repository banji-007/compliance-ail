# Red-team brief: Phase 3c-3d (fault records, route refusals, red-team set)

**Run id:** `p3c3d-red`. Fresh session, clean context. Scratch clone, not the primary working directory. Explicit Compose project name on every invocation.

**Target:** PR #14 at `2595a9c`, branch `p3c3b-order`. Do not merge. Do not fix anything you find; report it.

**Read first:** `docs/reports/phase-3c3c-redteam.md` (nine refutations), `docs/reports/phase-3c3d-keyprobe.md` (why the first fault-key shape was a rename), and `docs/reports/phase-3c3d.md` (what this phase claims to have closed).

**Your report is committed before this session closes.** Write it to `docs/reports/phase-3c3d-redteam.md` and commit it yourself. The previous pass reported inline, the session was closed, and its findings had to be transcribed from a conversation two sessions later.

## What you are doing

The claims below are behaviours that could be false. Make one false. A refutation is a command and its output. "I could not refute this" is a valid verdict; a confirmation you did not test is not. For every check you exercise, establish first that it can fail.

**This is the third remediation of one phase.** The two previous passes refuted eight of ten and nine of ten. This one reports all ten claims true. Weight that accordingly: either the mechanisms are now sound, or the claims have moved closer to what the code does. Read the report's "scoped down" statements against the red-team reports they answer.

**One class is already known to hide defects here.** Two failures reached CI green-to-red because a targeted run builds a small ledger and the full suite does not. Look for other properties that hold only at the ledger size the test happens to create.

**Known and deliberately not taken:** `/write-ordered` still accepts a key of any shape into a view. `ledger_fault:` is refused; nothing else is. Do not report the general case as a finding, but do establish what it still permits.

## Claims

**A1. A fault key identifies exactly one fault about exactly one record.** The shape is `ledger_fault:{committed_tx_id:020d}:{identity}:{nonce}`, identity being `call_id` or `key:{sha256(record_key)[:32]}`. Attack the identity component. A `call_id` containing a colon, a padded number, or the literal `key:`. Establish whether one record's fault can be made to parse or join as another's, and whether anything validates `call_id` shape at the point the key is built.

**A2. Every fault belonging to a page row is returned by the page's bounded read.** The window is `min_tx`/`max_tx` over the fetched rows, and `committed_tx_id` is supplied by the fault writer. Establish what happens when a fault's `committed_tx_id` does not match the transaction the record actually occupies: written wrong, written for a record on a different page, or written before the record commits. A fault outside the window is invisible with no error.

**A3. The paginated range read terminates correctly and loses nothing.** Termination is `len(entries) < limit`. Attack the boundary: exactly `limit` entries, exactly `limit + 1`, a window whose faults exceed 2500 across a cursor advance, and a fault written concurrently with a page read that spans two cursor pages.

**A4. `committed` is a fact about the ledger under every cut.** The fix needed a second step beyond the instruction, because a cut inside `verifiedSet`'s own completion reached the generic handler. Find a third: cut during the ledger confirmation itself, cut with the value readable but different, cut with ImmuDB reachable but the key absent. The committed test fixture is in the tree; use it and extend it.

**A5. `KeyMustNotExist` does not deny a legitimate write.** D39 and D40 interact. A write that commits while the caller is told it did not, followed by the caller's retry, is now a rejected precondition on a key that exists. Establish what the caller sees and whether any legitimate retry path is now permanently denied.

**A6. `/audit` renders every fault that should render.** D41 verifies `writer_signature` before rendering. Establish what happens to faults written before D41 existed, and to legacy `ledger_fault:{call_id}` faults. A check that silently drops old records is C3's class, and it would look identical to a clean page.

**A7. The `ledger_fault` list is complete and correctly ordered.** It is an `/audit` contract change: a list, newest first, ordered by the `scan` entry's own `tx`, with a count from the range hits. Attack the count, the ordering under equal transactions, and a row carrying more faults than one page of the range read returns.

**A8. The no-proof write path cannot commit a non-fault record.** A3 in the previous pass defeated both the guard (it inspected `record` while committing `value`) and the parse (a line count, defeated by dropping a paren). Establish that the new guard compares what is actually written, and defeat the parse again by whatever means it now permits.

**A9. Every bounded read asserts on what came back.** D42. Find a bounded read, key-range or score-bounded, that does not assert its bound, or an assertion that cannot fail. A dropped bound only shows up when something out-of-window returns.

**A10. No image carries key material.** The test was rewritten to detect by content after three live P-256 keys passed a filename blacklist. Attack the content detector: DER rather than PEM, PKCS8, an OpenSSH key, base64 with no header, a key inside an archive or a layer that a later layer deletes.

## Also

Establish what `/write-ordered` still permits into a view now that `ledger_fault:` is refused: tombstone keys, intent keys into the decision view, arbitrary prefixes. Report what each does to a page, `total`, and reconciliation. This is the raised-not-taken item; the question is its blast radius, not whether it exists.

## Report

`docs/reports/phase-3c3d-redteam.md`, committed before you close. Per claim: refuted, not refuted, or could not test, with the command and output. Name anything you found that is not on this list. Say which of your own checks you established could fail before trusting them. Enumerate anything you could not remove from the machine, by name, with the commands.
