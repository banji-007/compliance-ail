# VERSION: 2.0.0
# HIPAA Compliance Framework - PHI Protection Rules
#
# Enforces baseline HIPAA Technical Safeguard requirements for workloads
# that process Protected Health Information (PHI). Requires explicit PHI
# classification, isolated (dedicated-tenancy) compute, and encryption at rest.

package ail.frameworks.hipaa

# PHI workloads must run on isolated instances (dedicated tenancy).
# Shared multi-tenant compute is not permissible for PHI under HIPAA
# Technical Safeguards (45 CFR §164.312).
deny contains msg if {
    input.tool_name == "provision_cloud_server"  # scope guard
    payload := input.tool_args
    payload.tags.data_classification == "phi"
    object.get(payload.tags, "isolated_instance", "") != "true"
    msg := "DENIED: HIPAA Violation. PHI-classified workloads must have 'isolated_instance' set to 'true' (dedicated tenancy required)."
}

# PHI workloads must have encryption at rest enabled.
# Satisfies HIPAA encryption standard (45 CFR §164.312(a)(2)(iv)).
deny contains msg if {
    input.tool_name == "provision_cloud_server"  # scope guard
    payload := input.tool_args
    payload.tags.data_classification == "phi"
    object.get(payload.tags, "encryption_at_rest", "") != "true"
    msg := "DENIED: HIPAA Violation. PHI-classified workloads must have 'encryption_at_rest' set to 'true'."
}

# Any workload flagged as HIPAA-scoped must carry an explicit data_classification.
# Fail-closed: absence of classification on a HIPAA workload is itself a violation.
deny contains msg if {
    input.tool_name == "provision_cloud_server"  # scope guard
    payload := input.tool_args
    object.get(payload.tags, "hipaa_scope", "") == "true"
    object.get(payload.tags, "data_classification", "") == ""
    msg := "DENIED: HIPAA Violation. HIPAA-scoped workloads must carry an explicit 'data_classification' tag."
}

# Additional HIPAA rules could be added here
# Examples: audit controls, transmission security, access management, etc.
