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

# --- Bundle revision attribution (Phase 1.2, D9) ---
# data.system.bundles[input.bundle_name].manifest.revision trusted a
# caller-supplied key with no relationship to whichever bundle actually
# populated data.ail.* - red-team T7 (docs/reports/phase-1-1-redteam.md)
# reproduced S2 byte-for-byte against e7e9607 by naming an unrelated decoy
# bundle directly. input.bundle_name no longer exists in the input document
# at all; the revision is derived from OPA's own bundle map by finding
# whichever loaded bundle's manifest actually claims the `ail` root.
#
# This runs on every evaluation, not once at boot, which also closes T7's
# second point: a bundle added to a running OPA is rechecked on the very
# next call, not left unchecked until the next process restart.
_ail_root_owners contains name if {
    some name, info in data.system.bundles
    "ail" in object.get(info.manifest, "roots", [])
}

# Undefined unless exactly one bundle claims the `ail` root - a caller
# cannot influence this by supplying any input. Zero claimants and two-or-
# more claimants both fall through to "undefined" here, not to an error,
# so evaluation below is undefined the same way for either case.
_ail_bundle_name := name if {
    count(_ail_root_owners) == 1
    some name in _ail_root_owners
}

# --- Combined evaluation (Phase 1, P1-1) ---
# One query returns the verdict, the deny reasons, and the bundle revision
# that produced them together, over the same channel. allow always has a
# default and all_violations is a partial set (always at least empty), so
# neither can be undefined - the only way this whole rule is undefined is
# if the revision lookup is, e.g. no bundle (or more than one) claims the
# `ail` root. That makes "no result" an unambiguous signal: the decision
# cannot be attributed to a known policy revision, not that something else
# went wrong.
evaluation := {
    "allow": allow,
    "reasons": all_violations,
    "revision": data.system.bundles[_ail_bundle_name].manifest.revision,
}
