# VERSION: 2.0.0
# GDPR Compliance Framework - Data Residency & Purpose Limitation Rules

package ail.frameworks.gdpr

# Approved regions for data residency enforcement.
# Reads from bundle data.json (injected by the control plane per tenant).
# Falls back to hardcoded default when running outside the bundle API
# (e.g. local dev, policy-validator CI check).
approved_regions := {r | r := data.ail.config.approved_regions[_]} if {
    count(data.ail.config.approved_regions) > 0
} else := {"eu-central-1", "us-east-1"}

# Approved processing purposes for PII query enforcement (GDPR Article 5(1)(b)).
# Reads from bundle data.json; falls back to safe defaults for local dev.
approved_purposes := {p | p := data.ail.config.approved_purposes[_]} if {
    count(data.ail.config.approved_purposes) > 0
} else := {"customer_support", "billing"}

# --- provision_cloud_server rules ---

# GDPR Article 44-49: PCI-DSS classified workloads must run in an approved region.
deny contains msg if {
    input.tool_name == "provision_cloud_server"
    payload := input.tool_args
    payload.tags.data_classification == "pci-dss"
    not approved_regions[payload.region]
    msg := sprintf("DENIED: GDPR Data Residency Violation. 'pci-dss' workloads must run in an approved region. Approved: %v", [approved_regions])
}

# Fail-closed: unclassified data is treated as highly sensitive.
deny contains msg if {
    input.tool_name == "provision_cloud_server"
    payload := input.tool_args
    dc := object.get(payload.tags, "data_classification", "")
    unclassified := {"", "unspecified"}
    unclassified[dc]
    not approved_regions[payload.region]
    msg := sprintf("DENIED: GDPR Data Residency Violation. Unclassified data defaults to highly sensitive and must run in an approved region. Approved: %v", [approved_regions])
}

# --- query_database rules ---

# GDPR Article 5(1)(b) - Purpose Limitation: queries on PII tables must declare
# an approved processing purpose.
deny contains msg if {
    input.tool_name == "query_database"
    payload := input.tool_args
    contains(payload.target_table, "pii")
    not approved_purposes[payload.processing_purpose]
    msg := sprintf("DENIED: GDPR Violation. Unauthorized processing purpose '%v' for PII table. Approved purposes: %v", [object.get(payload, "processing_purpose", ""), approved_purposes])
}
