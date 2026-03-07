package compliance.cloud

default allow := false

allow if {
    input.action == "provision_cloud_server"
    input.cost_per_hour < 10
    input.region == "us-east-1"
}

decision := {
    "allowed": allow,
    "reason": reason_message,
}

reason_message := "Action approved by policy" if {
    allow
} else := "Action denied: cost_per_hour must be less than 10 AND region must be us-east-1"
