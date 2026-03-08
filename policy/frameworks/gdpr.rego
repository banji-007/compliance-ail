# VERSION: 1.0.0
# GDPR Compliance Framework - Data Residency Rules

package ail.frameworks.gdpr

import rego.v1

deny contains msg if {
    payload := input.tool_args
    payload.tags.data_classification == "pci-dss"
    not payload.region == "eu-central-1"
    msg := "DENIED: Data Residency Violation. 'pci-dss' workloads must run in 'eu-central-1'."
}

# Additional GDPR rules could be added here
# Examples: data retention, consent management, right to be forgotten, etc.
