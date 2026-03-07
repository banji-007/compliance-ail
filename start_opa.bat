@echo off
echo Starting OPA with cloud policy...
echo Policy file: policy/cloud_policy.rego
echo OPA will be available at http://localhost:8181

docker run -p 8181:8181 -v "%cd%/policy:/policy" openpolicyagent/opa:latest run --server /policy

echo OPA started. Use 'docker ps' to check the container.
echo Test with: curl http://localhost:8181/v1/data/compliance/cloud/decision
