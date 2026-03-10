# VERSION: 1.1.0
# GDPR Compliance Framework - Data Residency Rules

package ail.frameworks.gdpr

deny contains msg if {
    payload := input.tool_args
    payload.tags.data_classification == "pci-dss"
    not payload.region == "eu-central-1"
    msg := "DENIED: Data Residency Violation. 'pci-dss' workloads must run in 'eu-central-1'."
}

# Fail-closed default: missing, blank, or 'unspecified' data_classification is
# treated as highly sensitive and subject to the same eu-central-1 restriction.
deny contains msg if {
    payload := input.tool_args
    dc := object.get(payload.tags, "data_classification", "")
    unclassified := {"", "unspecified"}
    unclassified[dc]
    not payload.region == "eu-central-1"
    msg := "DENIED: Data Residency Violation. Unclassified data defaults to highly sensitive and must run in 'eu-central-1'."
}

# Additional GDPR rules could be added here
# Examples: data retention, consent management, right to be forgotten, etc.
