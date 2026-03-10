# VERSION: 1.0.0
# SOC2 Compliance Framework - Security Rules

package ail.frameworks.soc2

deny contains msg if {
    payload := input.tool_args
    payload.tags.environment == "prod"
    # object.get returns "" as default so both missing key and empty string are caught
    object.get(payload.tags, "encryption_at_rest", "") != "true"
    msg := "DENIED: SOC2 Violation. Production environments must have 'encryption_at_rest' set to 'true'."
}

# Additional SOC2 rules could be added here
# Examples: access controls, audit logging, change management, etc.
