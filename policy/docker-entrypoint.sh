#!/bin/sh
# AIL Policy Bootstrapper
#
# Runs as an alpine init container before OPA starts. Stages the core policy
# and any enabled compliance packs into the shared /policy/active volume.
# OPA watches /policy/active and will only evaluate what lands here.
#
# Environment variables (set in docker-compose.yml, sourced from .env):
#   ENABLE_GDPR   — load GDPR data-residency pack
#   ENABLE_SOC2   — load SOC2 security controls pack
#   ENABLE_FINOPS — load FinOps cost-control pack
#   ENABLE_HIPAA  — load HIPAA PHI-protection pack

set -e

SOURCE_DIR="/policy/source"
CORE_DIR="${SOURCE_DIR}/core"
PACKS_DIR="${SOURCE_DIR}/packs"
ACTIVE_DIR="/policy/active"

echo "=== AIL Policy Bootstrapper ==="
echo "Clearing active policy directory..."
rm -f "${ACTIVE_DIR}"/*.rego

echo "Loading core policy (always active)..."
cp "${CORE_DIR}"/*.rego "${ACTIVE_DIR}/"

ENABLED=0

if [ "${ENABLE_GDPR}" = "true" ]; then
    echo "  [+] GDPR pack enabled"
    cp "${PACKS_DIR}/gdpr/"*.rego "${ACTIVE_DIR}/"
    ENABLED=$((ENABLED + 1))
else
    echo "  [-] GDPR pack disabled"
fi

if [ "${ENABLE_SOC2}" = "true" ]; then
    echo "  [+] SOC2 pack enabled"
    cp "${PACKS_DIR}/soc2/"*.rego "${ACTIVE_DIR}/"
    ENABLED=$((ENABLED + 1))
else
    echo "  [-] SOC2 pack disabled"
fi

if [ "${ENABLE_FINOPS}" = "true" ]; then
    echo "  [+] FinOps pack enabled"
    cp "${PACKS_DIR}/finops/"*.rego "${ACTIVE_DIR}/"
    ENABLED=$((ENABLED + 1))
else
    echo "  [-] FinOps pack disabled"
fi

if [ "${ENABLE_HIPAA}" = "true" ]; then
    echo "  [+] HIPAA pack enabled"
    cp "${PACKS_DIR}/hipaa/"*.rego "${ACTIVE_DIR}/"
    ENABLED=$((ENABLED + 1))
else
    echo "  [-] HIPAA pack disabled"
fi

if [ "${ENABLED}" -eq 0 ]; then
    echo ""
    echo "ERROR: No compliance packs enabled. At least one ENABLE_* variable"
    echo "       must be set to 'true'. Refusing to start with zero active"
    echo "       rules — this would silently allow all tool calls."
    exit 1
fi

echo ""
echo "Bootstrap complete: ${ENABLED} pack(s) staged into ${ACTIVE_DIR}"
echo "Active files:"
ls "${ACTIVE_DIR}"/*.rego
echo "=== Handing off to OPA ==="
