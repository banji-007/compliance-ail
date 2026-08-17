// W5: does the compiled AIL policy module instantiate under
// @open-policy-agent/opa-wasm inside a Workers-compatible runtime, and how
// fast is instantiation vs a single evaluation.
import { loadPolicy } from "@open-policy-agent/opa-wasm";
import policyWasmModule from "./policy.wasm";

const APPROVED_INPUT = {
  tool_name: "provision_cloud_server",
  tool_args: {
    instance_type: "t3.micro",
    region: "us-east-1",
    tags: {
      environment: "prod",
      data_classification: "internal",
      cost_center: "engineering",
      encryption_at_rest: "true",
      project: "webapp",
    },
  },
};

const DENY_INPUT = {
  tool_name: "provision_cloud_server",
  tool_args: {
    instance_type: "t3.micro",
    region: "ap-south-1",
    tags: { environment: "dev", data_classification: "pci-dss", cost_center: "engineering", project: "webapp" },
  },
};

export default {
  async fetch(request) {
    const timings = {};

    const t0 = performance.now();
    const policy = await loadPolicy(policyWasmModule);
    const t1 = performance.now();
    timings.instantiate_ms = t1 - t0;

    policy.setData({});
    const t2 = performance.now();
    timings.setData_ms = t2 - t1;

    const approvedResult = policy.evaluate(APPROVED_INPUT, "ail/main/compliance_summary");
    const t3 = performance.now();
    timings.first_eval_ms = t3 - t2;

    const denyResult = policy.evaluate(DENY_INPUT, "ail/main/compliance_summary");
    const t4 = performance.now();
    timings.second_eval_ms = t4 - t3;

    // Ten more evaluations against the already-instantiated policy, to see
    // steady-state per-decision cost once the module is warm and cached
    // across requests (the realistic hosted shape: one instantiation,
    // many evaluations).
    const warmTimes = [];
    for (let i = 0; i < 10; i++) {
      const s = performance.now();
      policy.evaluate(i % 2 === 0 ? APPROVED_INPUT : DENY_INPUT, "ail/main/compliance_summary");
      warmTimes.push(performance.now() - s);
    }
    timings.warm_eval_ms_samples = warmTimes;
    timings.warm_eval_ms_avg = warmTimes.reduce((a, b) => a + b, 0) / warmTimes.length;

    return new Response(
      JSON.stringify(
        {
          runtime: "workerd (wrangler dev)",
          timings,
          approvedResult,
          denyResult,
        },
        null,
        2
      ),
      { headers: { "content-type": "application/json" } }
    );
  },
};
