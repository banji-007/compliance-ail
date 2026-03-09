# VERSION: 1.1.0
# AIL Main Policy Aggregator
# Imports and aggregates all compliance frameworks

package ail.main

# Import all framework policies
import data.ail.frameworks.gdpr
import data.ail.frameworks.soc2
import data.ail.frameworks.finops

# Aggregate all deny messages from all frameworks
deny contains msg if {
    gdpr.deny[msg]
}

deny contains msg if {
    soc2.deny[msg]
}

deny contains msg if {
    finops.deny[msg]
}

# Explicit allow gate — default is DENY.
# This rule must be the affirmative result checked by the middleware.
# If this package fails to compile, OPA returns null for /allow → middleware
# treats null as DENIED (fail-closed). An empty deny set is NOT sufficient;
# allow must be explicitly true.
default allow := false

allow if {
    count(deny) == 0
}

# Helper rule to get all violations for debugging/audit purposes
all_violations := {msg | deny[msg]}

# Compliance status summary
compliance_summary := {
    "total_violations": count(all_violations),
    "violations": all_violations,
    "compliant": count(all_violations) == 0
}
