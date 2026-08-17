// W2 (corrected): test the REAL `evaluation` rule in policy/core/main.rego
// (added in Phase 1, commit 3e86a9b) directly, not just the standalone
// probe analog. This is the actual per-request entrypoint
// interceptor/middleware.py queries in production
// (data.ail.main.evaluation, via _OPA_EVAL_URL).
import { loadPolicy } from "@open-policy-agent/opa-wasm";
import fs from "node:fs";

const wasmBytes = fs.readFileSync("build/extracted/policy.wasm");
const policy = await loadPolicy(wasmBytes);

const APPROVED_INPUT = {
  bundle_name: "ail-policies",
  tool_name: "provision_cloud_server",
  tool_args: {
    instance_type: "t3.micro",
    region: "us-east-1",
    tags: { environment: "dev", data_classification: "internal", cost_center: "engineering", project: "webapp" },
  },
};

function run(label) {
  console.log(`--- ${label} ---`);
  const result = policy.evaluate(APPROVED_INPUT, "ail/main/evaluation");
  console.log("  result:", JSON.stringify(result));
  console.log("  undefined (empty result set)?", !result || result.length === 0);
}

// Case 1: no setData() at all - closest to a bare instantiation.
run("no setData() called");

// Case 2: setData({}) - the same {} that build/extracted/data.json itself
// contains for this bundle (opa build never populates data.system.bundles).
policy.setData({});
run("setData({})");

// Case 3: setData with a realistic tenant config document but STILL no
// system.bundles - this is what a hosted Worker would naturally supply
// (its own per-tenant config), which is exactly the gap: it has no reason
// to know to synthesize an OPA-internal bundle-manager structure.
policy.setData({ ail: { config: { approved_regions: ["us-east-1"] } } });
run("setData with realistic tenant config, still no system.bundles");

// Case 4: setData with system.bundles manually constructed to match
// bundle_name "ail-policies" - proves the rule DOES resolve once the shape
// is supplied, confirming the gap is purely "nothing supplies it automatically".
policy.setData({
  ail: { config: { approved_regions: ["us-east-1"] } },
  system: { bundles: { "ail-policies": { manifest: { revision: "manually-injected-rev" } } } },
});
run("setData with hand-rolled system.bundles matching bundle_name");

// Case 5: same as case 4 but bundle_name in input doesn't match the key
// supplied - proves the lookup is exact-match, not "any bundle present".
policy.setData({
  system: { bundles: { "some-other-bundle": { manifest: { revision: "x" } } } },
});
run("setData with system.bundles present but WRONG bundle_name key");
