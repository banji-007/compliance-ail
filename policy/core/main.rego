# VERSION: 2.0.0
# AIL Core Policy Aggregator — Dynamic Pack Routing
#
# Always active. Aggregates deny rules from whichever compliance packs
# the policy-bootstrapper staged into /policy/active/ at boot time.
#
# Design: uses full data.* references without import statements.
# OPA treats a reference to an undefined package as undefined — the rule
# body does not fire and contributes nothing to the deny set. This is
# what makes packs truly optional: if a pack's .rego was not copied into
# /policy/active/, its deny rules simply do not exist at eval time.
# No compile errors, no fail-open — the allow gate still requires
# count(deny) == 0 to be true.

package ail.main

# --- Pack deny aggregation ---
# Each block forwards violations from one optional pack.
# Remove an import statement hazard by referencing data.* directly.

deny contains msg if {
    data.ail.frameworks.gdpr.deny[msg]
}

deny contains msg if {
    data.ail.frameworks.soc2.deny[msg]
}

deny contains msg if {
    data.ail.frameworks.finops.deny[msg]
}

deny contains msg if {
    data.ail.frameworks.hipaa.deny[msg]
}

# --- Allow gate ---
# Explicit fail-closed default. allow is only true when zero deny
# messages exist across all loaded packs. If OPA fails to load this
# package (e.g. compile error), it returns null for /allow and the
# middleware treats null as DENIED.
default allow := false

allow if {
    count(deny) == 0
}

# --- Audit helpers ---
all_violations := {msg | deny[msg]}

compliance_summary := {
    "total_violations": count(all_violations),
    "violations": all_violations,
    "compliant": count(all_violations) == 0,
}
