// W2: does data.system.bundles resolve inside a WASM-instantiated policy?
import { loadPolicy } from "@open-policy-agent/opa-wasm";
import fs from "node:fs";

const wasmBytes = fs.readFileSync("build_probe/extracted/policy.wasm");
const policy = await loadPolicy(wasmBytes);

console.log("entrypoints:", JSON.stringify(policy.entrypoints));

function probeAll(label) {
  console.log(`--- ${label} ---`);
  for (const ep of ["ail/probe/revision", "ail/probe/bundles_present", "ail/probe/bundles_keys"]) {
    try {
      const result = policy.evaluate({}, ep);
      console.log(`  ${ep}:`, JSON.stringify(result));
    } catch (e) {
      console.log(`  ${ep}: THREW`, e.toString());
    }
  }
}

// No setData() call at all - simulates a bare instantiation with nothing
// supplied, closest to "absent" per the spike's framing.
probeAll("No data set at all");

// Try setting data.json exactly as produced by opa build (which is just {}
// for this bundle - opa build does not itself populate data.system.bundles
// even for the real four-pack bundle; see build/extracted/data.json).
policy.setData({});
probeAll("setData({})");

// Try manually constructing what an OPA-server-shaped data document would
// contain if someone tried to hand-roll the system.bundles shape into the
// WASM data document themselves.
policy.setData({
  system: {
    bundles: {
      "ail-policies": { manifest: { revision: "manually-injected-rev" } },
    },
  },
});
probeAll("setData with hand-rolled system.bundles");
