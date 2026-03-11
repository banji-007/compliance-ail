# VERSION: 2.0.0
# Internal FinOps Framework - Cost Control Rules

package ail.frameworks.finops

# Approved cost center values.
# Reads from bundle data.json (injected by the control plane per tenant).
# Falls back to hardcoded defaults when running outside the bundle API
# (e.g. local dev, policy-validator CI check).
approved_cost_centers := {x | x := data.ail.config.allowed_cost_centers[_]} if {
    count(data.ail.config.allowed_cost_centers) > 0
} else := {"engineering", "marketing", "finance", "operations"}

deny contains msg if {
    input.tool_name == "provision_cloud_server"  # scope guard
    payload := input.tool_args
    payload.tags.environment == "prod"
    cc := object.get(payload.tags, "cost_center", "")
    not approved_cost_centers[cc]
    msg := "DENIED: Production environments must include a valid 'cost_center' tag. Approved values: engineering, marketing, finance, operations."
}

deny contains msg if {
    input.tool_name == "provision_cloud_server"  # scope guard
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
