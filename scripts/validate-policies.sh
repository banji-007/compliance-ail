#!/bin/sh
# Policy Validation Script
# Runs OPA syntax and compilation checks against all Rego policies before
# the agent stack starts. Exits non-zero if any policy fails to compile,
# which causes the token-generator (or CI pipeline) to abort — preventing
# a silent fail-open state where OPA returns null for /allow.
#
# Usage:
#   ./scripts/validate-policies.sh                  (local, requires opa CLI)
#   docker run --rm -v $(pwd)/policy:/policy openpolicyagent/opa check /policy

set -e

POLICY_DIR="${1:-/policy}"

echo "=== AIL Policy Validation ==="
echo "Checking policies in: $POLICY_DIR"

# opa check performs full compilation, catching:
#   - Syntax errors
#   - Unknown imports
#   - Type errors (with --strict)
#   - Undefined references
opa check --strict "$POLICY_DIR"

echo ""
echo "All policies compiled successfully. System is safe to start."
