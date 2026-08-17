import { execFileSync } from "node:child_process";
import fs from "node:fs";
import path from "node:path";
import os from "node:os";

const REGO_FILES = [
  "../../policy/core/main.rego",
  "../../policy/packs/gdpr/gdpr.rego",
  "../../policy/packs/hipaa/hipaa.rego",
  "../../policy/packs/soc2/soc2.rego",
  "../../policy/packs/finops/finops.rego",
].map((p) => path.resolve(p));

const OPA = path.resolve("tools/opa.exe");
const dataVariant = { ail: { config: { approved_regions: ["ap-southeast-1"], approved_purposes: ["research"], allowed_cost_centers: ["rnd"] } } };

const tmp = fs.mkdtempSync(path.join(os.tmpdir(), "opaeval-"));
console.log("tmp dir:", tmp);
const dataPath = path.join(tmp, "data.json");
const inputPath = path.join(tmp, "input.json");
fs.writeFileSync(dataPath, JSON.stringify(dataVariant));
fs.writeFileSync(inputPath, JSON.stringify({}));

console.log("dataPath contents:", fs.readFileSync(dataPath, "utf8"));

const args = [
  "eval",
  ...REGO_FILES.flatMap((f) => ["-d", f]),
  "-d", dataPath,
  "-i", inputPath,
  "--format", "json",
  "data.ail.config",
];
console.log("args:", args);
const out = execFileSync(OPA, args, { encoding: "utf8" });
console.log("output:", out);
