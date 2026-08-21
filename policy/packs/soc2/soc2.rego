# VERSION: 2.0.0
# SOC2 Compliance Framework - Security Rules

package ail.frameworks.soc2

# --- provision_cloud_server rules ---

# SOC2 CC6.1: Enforce encryption on all production assets.
deny contains msg if {
    input.tool_name == "provision_cloud_server"
    payload := input.tool_args
    payload.tags.environment == "prod"
    # object.get returns "" as default so both missing key and empty string are caught
    object.get(payload.tags, "encryption_at_rest", "") != "true"
    msg := "DENIED: SOC2 Violation. Production environments must have 'encryption_at_rest' set to 'true'."
}

# --- query_database rules ---

# SOC2 CC6.1: Unmasked queries on PII or user tables are prohibited.
# Fail-closed: masking_enabled missing or any value other than true is a violation.
deny contains msg if {
    input.tool_name == "query_database"
    payload := input.tool_args
    sensitive_table(payload.target_table)
    object.get(payload, "masking_enabled", false) != true
    msg := sprintf("DENIED: SOC2 Violation. Unmasked queries on PII tables are prohibited. Table: '%v'", [payload.target_table])
}

sensitive_table(name) if contains(name, "pii")
sensitive_table(name) if contains(name, "users")

# --- deploy_to_production rules ---

# SOC2 CC8.1: Production deployments require a valid approval ticket.
deny contains msg if {
    input.tool_name == "deploy_to_production"
    payload := input.tool_args
    payload.environment == "production"
    payload.approval_ticket == ""
    msg := "SOC2 CC8.1 Violation: Production deployments require a valid approval ticket reference."
}

# SOC2 CC8.1: Bypassing CI/CD pipeline checks is strictly prohibited.
deny contains msg if {
    input.tool_name == "deploy_to_production"
    payload := input.tool_args
    payload.bypass_ci == true
    msg := "SOC2 CC8.1 Violation: Bypassing CI/CD pipeline checks is strictly prohibited."
}

# --- read_vault_secret rules (Phase 2, D14 demonstration tool) ---

# SOC2 CC6.1: least-privilege secret access - only a fixed allowlist of
# operational secrets may be read through this tool, regardless of who is
# asking. Genuine policy evaluation, not a rubber stamp: this is what lets
# the Phase 2 demonstration show both an APPROVED and a DENIED mediated
# call in the same session (docs/reports/phase-2.md, P2-3).
_approved_vault_secrets := {"db_master_password", "payment_gateway_key"}

deny contains msg if {
    input.tool_name == "read_vault_secret"
    payload := input.tool_args
    not _approved_vault_secrets[payload.secret_name]
    msg := sprintf("DENIED: SOC2 Least-Privilege Violation. Secret '%v' is not in the approved vault-access allowlist.", [object.get(payload, "secret_name", "")])
}
