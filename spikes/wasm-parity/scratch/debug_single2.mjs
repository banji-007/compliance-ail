import { execFileSync } from "node:child_process";
import fs from "node:fs";
import path from "node:path";

const REGO_FILES = [
  "../../policy/core/main.rego",
  "../../policy/packs/gdpr/gdpr.rego",
  "../../policy/packs/hipaa/hipaa.rego",
  "../../policy/packs/soc2/soc2.rego",
  "../../policy/packs/finops/finops.rego",
].map((p) => path.resolve(p));

const OPA = path.resolve("tools/opa.exe");
const dataVariant = { ail: { config: { approved_regions: ["ap-southeast-1"], approved_purposes: ["research"], allowed_cost_centers: ["rnd"] } } };

// This time: write into scratch/ (inside the project tree) instead of os temp dir.
const dataPath = path.resolve("scratch/debug2_data.json");
const inputPath = path.resolve("scratch/debug2_input.json");
fs.writeFileSync(dataPath, JSON.stringify(dataVariant));
fs.writeFileSync(inputPath, JSON.stringify({}));

console.log("dataPath:", dataPath);

const args = [
  "eval",
  ...REGO_FILES.flatMap((f) => ["-d", f]),
  "-d", dataPath,
  "-i", inputPath,
  "--format", "json",
  "data.ail.config",
];
const out = execFileSync(OPA, args, { encoding: "utf8" });
console.log("output (scratch dir, absolute path):", out);

// Now also try relative path form (relative to cwd), matching the working bash script.
const args2 = [
  "eval",
  ...REGO_FILES.flatMap((f) => ["-d", f]),
  "-d", "scratch/debug2_data.json",
  "-i", "scratch/debug2_input.json",
  "--format", "json",
  "data.ail.config",
];
const out2 = execFileSync(OPA, args2, { encoding: "utf8" });
console.log("output (relative path):", out2);
