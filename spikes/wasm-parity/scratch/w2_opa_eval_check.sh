#!/bin/bash
cd "$(dirname "$0")/.."
echo "{\"bundle_name\":\"ail-policies\",\"tool_name\":\"provision_cloud_server\",\"tool_args\":{\"instance_type\":\"t3.micro\",\"region\":\"us-east-1\",\"tags\":{\"environment\":\"dev\",\"data_classification\":\"internal\",\"cost_center\":\"engineering\",\"project\":\"webapp\"}}}" > scratch/.opa_eval_tmp/w2_input.json
echo '{}' > scratch/.opa_eval_tmp/w2_data.json

echo "=== opa eval (no server, no bundle manager) against ail.main.evaluation, empty data ==="
./tools/opa.exe eval \
  -d ../../policy/core/main.rego \
  -d ../../policy/packs/gdpr/gdpr.rego \
  -d ../../policy/packs/hipaa/hipaa.rego \
  -d ../../policy/packs/soc2/soc2.rego \
  -d ../../policy/packs/finops/finops.rego \
  -d scratch/.opa_eval_tmp/w2_data.json \
  -i scratch/.opa_eval_tmp/w2_input.json \
  --format json \
  "data.ail.main.evaluation"
