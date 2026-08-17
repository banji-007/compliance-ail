// Does opa-wasm's loadPolicy() auto-load the bundle's data.json (the
// document baked in next to policy.wasm inside the bundle tarball) into
// the WASM module, or does the JS host have to explicitly setData() it?
import { loadPolicy } from "@open-policy-agent/opa-wasm";
import fs from "node:fs";

const wasmBytes = fs.readFileSync("build_embed/extracted/policy.wasm");
const bundledDataJson = JSON.parse(fs.readFileSync("build_embed/extracted/data.json", "utf8"));

const policy = await loadPolicy(wasmBytes);
console.log("--- fresh instantiation, no setData() called ---");
console.log("baked_value:", JSON.stringify(policy.evaluate({}, "ail/probe2/baked_value")));

console.log("--- after explicit setData(bundledDataJson) ---");
policy.setData(bundledDataJson);
console.log("baked_value:", JSON.stringify(policy.evaluate({}, "ail/probe2/baked_value")));

// Also try passing the bundle data.json as a second arg to loadPolicy,
// since some opa-wasm versions accept (wasm, memoryPages, data).
const policy2 = await loadPolicy(wasmBytes, undefined, bundledDataJson);
console.log("--- loadPolicy(wasm, undefined, bundledDataJson) ---");
console.log("baked_value:", JSON.stringify(policy2.evaluate({}, "ail/probe2/baked_value")));
