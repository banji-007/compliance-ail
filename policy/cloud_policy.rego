# VERSION: 1.0.0

package ail.policy

import rego.v1

deny contains msg if {
    payload := input.tool_args
    payload.tags.environment == "prod"
    not payload.tags.cost_center
    msg := "DENIED: Production environments must include a 'cost_center' tag."
}

deny contains msg if {
    payload := input.tool_args
    blocked_instances := {"p4d.24xlarge", "p5.48xlarge"}
    blocked_instances[payload.instance_type]
    # Must have project tag set to "ml-training" for restricted instances
    # 'not' handles both missing project tag and wrong value cases safely
    not payload.tags.project == "ml-training"
    msg := sprintf("DENIED: Instance type %v is restricted. 'project' tag must be 'ml-training'.", [payload.instance_type])
}

deny contains msg if {
    payload := input.tool_args
    payload.tags.data_classification == "pci-dss"
    not payload.region == "eu-central-1"
    msg := "DENIED: Data Residency Violation. 'pci-dss' workloads must run in 'eu-central-1'."
}
