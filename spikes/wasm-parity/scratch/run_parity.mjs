// W3: run every corpus case against OPA server-side evaluation (via `opa eval`)
// and against the compiled WASM module (via @open-policy-agent/opa-wasm),
// and diff verdict + reason set.
import { loadPolicy } from "@open-policy-agent/opa-wasm";
import { execFileSync } from "node:child_process";
import fs from "node:fs";
import path from "node:path";
import os from "node:os";

const corpus = JSON.parse(fs.readFileSync("scratch/corpus.json", "utf8"));
const OPA = path.resolve("tools/opa.exe");
const REGO_FILES = [
  "../../policy/core/main.rego",
  "../../policy/packs/gdpr/gdpr.rego",
  "../../policy/packs/hipaa/hipaa.rego",
  "../../policy/packs/soc2/soc2.rego",
  "../../policy/packs/finops/finops.rego",
].map((p) => path.resolve(p));

const wasmBytes = fs.readFileSync("build/extracted/policy.wasm");

// IMPORTANT (documented in the report as a methodology note): `opa eval -d`
// with an ABSOLUTE path to a loose (non-bundle) JSON data file silently
// fails to merge it at the root implied by its own JSON structure - the
// data document ends up unreachable and every data.* read against it comes
// back empty, with no error or warning. A RELATIVE path (relative to the
// process cwd) works correctly. This was discovered empirically while
// building this harness (see scratch/debug_single.mjs and
// scratch/debug_single2.mjs) and is an OPA CLI loose-file-loading quirk on
// this platform, not a WASM-vs-server parity issue - so the data/input
// files below are written under scratch/ and referenced by relative path.
const TMP_DIR = path.resolve("scratch/.opa_eval_tmp");
fs.mkdirSync(TMP_DIR, { recursive: true });
const REGO_FILES_REL = [
  "../../policy/core/main.rego",
  "../../policy/packs/gdpr/gdpr.rego",
  "../../policy/packs/hipaa/hipaa.rego",
  "../../policy/packs/soc2/soc2.rego",
  "../../policy/packs/finops/finops.rego",
];

function opaEval(dataVariant, input) {
  const dataPath = "scratch/.opa_eval_tmp/data.json";
  const inputPath = "scratch/.opa_eval_tmp/input.json";
  fs.writeFileSync(path.resolve(dataPath), JSON.stringify(dataVariant));
  fs.writeFileSync(path.resolve(inputPath), JSON.stringify(input));
  const args = [
    "eval",
    ...REGO_FILES_REL.flatMap((f) => ["-d", f]),
    "-d", dataPath,
    "-i", inputPath,
    "--format", "json",
    "data.ail.main.compliance_summary",
  ];
  const out = execFileSync(OPA, args, { encoding: "utf8" });
  const parsed = JSON.parse(out);
  const value = parsed.result?.[0]?.expressions?.[0]?.value;
  if (value === undefined) return { compliant: null, violations: null, undefined: true };
  return {
    compliant: value.compliant,
    violations: [...value.violations].sort(),
    undefined: false,
  };
}

async function wasmEval(dataVariant, input) {
  const policy = await loadPolicy(wasmBytes);
  policy.setData(dataVariant);
  const rs = policy.evaluate(input, "ail/main/compliance_summary");
  if (!rs || rs.length === 0) return { compliant: null, violations: null, undefined: true };
  const value = rs[0].result;
  return {
    compliant: value.compliant,
    violations: [...value.violations].sort(),
    undefined: false,
  };
}

function setsEqual(a, b) {
  if (a === null || b === null) return a === b;
  if (a.length !== b.length) return false;
  return a.every((v, i) => v === b[i]);
}

const results = [];
for (const c of corpus.cases) {
  const dataVariant = corpus.data_variants[c.data_variant];
  const opaResult = opaEval(dataVariant, c.input);
  const wasmResult = await wasmEval(dataVariant, c.input);

  const verdictMatch = opaResult.compliant === wasmResult.compliant && opaResult.undefined === wasmResult.undefined;
  const reasonMatch = setsEqual(opaResult.violations, wasmResult.violations);
  const match = verdictMatch && reasonMatch;

  results.push({
    id: c.id,
    rule: c.rule,
    description: c.description,
    data_variant: c.data_variant,
    opa: opaResult,
    wasm: wasmResult,
    match,
  });
}

fs.writeFileSync("scratch/parity_results.json", JSON.stringify(results, null, 2));

const mismatches = results.filter((r) => !r.match);
console.log(`Total cases: ${results.length}`);
console.log(`Matches: ${results.length - mismatches.length}`);
console.log(`Mismatches: ${mismatches.length}`);
if (mismatches.length > 0) {
  console.log("\n--- MISMATCHES ---");
  for (const m of mismatches) {
    console.log(`\n${m.id}: ${m.description}`);
    console.log("  OPA: ", JSON.stringify(m.opa));
    console.log("  WASM:", JSON.stringify(m.wasm));
  }
}
