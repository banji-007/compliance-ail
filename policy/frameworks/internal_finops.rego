# VERSION: 1.0.0
# Internal FinOps Framework - Cost Control Rules

package ail.frameworks.finops

deny contains msg if {
    payload := input.tool_args
    payload.tags.environment == "prod"
    # object.get returns "" as default so both missing key and empty string are caught
    object.get(payload.tags, "cost_center", "") == ""
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

# Additional FinOps rules could be added here
# Examples: budget enforcement, resource tagging, cost allocation, etc.
