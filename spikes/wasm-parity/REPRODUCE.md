# Reproducing the WASM parity result (P13-6, Phase 1.3)

`docs/reports/phase-1-2.md` (P12-4) cites a 42/42 WASM-vs-server parity
result. It could not be reproduced from any single commit: the harness
that produces it lived only on `spike-wasm-parity-report`, and that
branch's own `policy/` tree was frozen before the P12-4 message-formatting
fix it was supposed to be evidence for (`docs/reports/phase-1-2-redteam.md`,
U6). This directory moves the harness itself into the main tree; it
evaluates whatever `policy/core/` and `policy/packs/` currently contain, so
the result is reproducible from whichever commit is checked out, not tied
to a policy snapshot frozen at spike time.

Two pieces are intentionally not committed (`.gitignore`): the `opa` CLI
binary (`tools/`) and the build output (`build/`). Both are cheap to
regenerate and neither is project-specific state.

## Steps

From this directory (`spikes/wasm-parity/`):

```bash
# 1. Get the opa CLI (matches the version this was last verified against).
mkdir -p tools
curl -sL -o tools/opa.exe https://openpolicyagent.org/downloads/v1.19.0/opa_windows_amd64.exe
# macOS/Linux: swap the asset name (opa_darwin_amd64 / opa_linux_amd64), drop .exe.
chmod +x tools/opa.exe  # not needed on Windows

# 2. Compile the current policy tree to WASM.
mkdir -p build
./tools/opa.exe build -t wasm -e ail/main/compliance_summary \
  ../../policy/core/main.rego \
  ../../policy/packs/gdpr/gdpr.rego \
  ../../policy/packs/hipaa/hipaa.rego \
  ../../policy/packs/soc2/soc2.rego \
  ../../policy/packs/finops/finops.rego \
  -o build/bundle.tar.gz

# 3. Extract the module.
mkdir -p build/extracted
tar -xzf build/bundle.tar.gz -C build/extracted policy.wasm .manifest data.json

# 4. Install the JS harness deps and run.
npm install
node scratch/run_parity.mjs
```

Expected output:

```
Total cases: 42
Matches: 42
Mismatches: 0
```

Live-confirmed against this repository's own `phase-1-3-work` head
(built and run in a scratch clone, `opa` v1.19.0, Node v24.14.0) - see
`docs/reports/phase-1-3.md`, P13-6, for the transcript and commit id this
was run against.

## What this does and does not establish

`run_parity.mjs` evaluates `data.ail.main.compliance_summary` both through
`opa eval` (server-side Rego) and through the compiled WASM module, over
the 42-case corpus in `scratch/corpus.json`, and diffs the verdict and the
sorted reason set for each case. It does not evaluate `data.ail.main.evaluation`
(the interceptor's actual per-call entrypoint, which additionally reads
`data.system.bundles[...].manifest.revision` - a construct the OPA bundle
manager provides and a bare compiled WASM module does not) - see
`docs/reports/spike-wasm-parity.md` (W2) for that finding, which this
harness does not re-litigate.
