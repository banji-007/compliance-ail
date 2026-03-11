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
