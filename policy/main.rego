# VERSION: 1.0.0
# AIL Main Policy Aggregator
# Imports and aggregates all compliance frameworks

package ail.main

import rego.v1

# Import all framework policies
import data.ail.frameworks.gdpr
import data.ail.frameworks.soc2
import data.ail.frameworks.finops

# Aggregate all deny messages from all frameworks
deny contains msg if {
    # Collect violations from GDPR framework
    gdpr.deny[msg]
}

deny contains msg if {
    # Collect violations from SOC2 framework
    soc2.deny[msg]
}

deny contains msg if {
    # Collect violations from FinOps framework
    finops.deny[msg]
}

# Helper rule to get all violations for debugging/audit purposes
all_violations := {msg | deny[msg]}

# Compliance status summary
compliance_summary := {
    "total_violations": count(all_violations),
    "violations": all_violations,
    "compliant": count(all_violations) == 0
}
