#!/bin/bash
cd "$(dirname "$0")/.."
./tools/opa.exe eval \
  -d ../../policy/core/main.rego \
  -d ../../policy/packs/gdpr/gdpr.rego \
  -d ../../policy/packs/hipaa/hipaa.rego \
  -d ../../policy/packs/soc2/soc2.rego \
  -d ../../policy/packs/finops/finops.rego \
  -d scratch/tenant_data.json \
  --format pretty \
  "data.ail.config"
