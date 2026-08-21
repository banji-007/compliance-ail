"""
tests/test_deny_message_formatting.py - P12-4, Phase 1.2.

Attack to reproduce (docs/reports/spike-wasm-parity.md, W3, verbatim): the
OPA server and the WASM evaluator render sprintf("%v", [set]) differently -
braces/quotes/sorted under the server, no braces/no quotes/unsorted under
WASM. 10 of the spike's 42 corpus cases differed on exactly the four rules
that interpolate a set into a deny message: GDPR's pci-dss region rule,
GDPR's unclassified-data region rule, GDPR's purpose-limitation rule, and
FinOps's cost-center rule. Verdicts and reason counts matched in every
case; only the literal string differed - which matters here because
`reasons` is hashed into the ledger record (D5), so a record whose content
depends on which evaluator produced it is not reproducible offline.

The fix (policy/packs/gdpr/gdpr.rego, policy/packs/finops/finops.rego)
replaces sprintf("%v", [set]) with sprintf("%v", [concat(", ", sort(set))])
in all four rules - a plain string that both evaluators format identically
by construction, since only the string's *construction* (sort + concat) is
evaluator-visible, not any evaluator-internal set-stringification default.

These four tests assert the exact expected string against the real, live
OPA server (docker-compose.test.yml) - the evaluator this project actually
runs today. spikes/wasm-parity's own harness is the parity check against
the WASM evaluator (out of tree, not part of this suite); the fix here
makes both evaluators agree because the rendering is now fully specified
by the policy, not by either evaluator's default.

Requires the docker-compose.test.yml stack. SPIRE_DISABLED=true bypasses
mTLS, matching Makefile:45-53. Assumes tenant_default's seeded config
(control_plane/main.py's lifespan seeding): approved_regions =
"eu-central-1,us-east-1", approved_purposes = "customer_support,billing",
allowed_cost_centers = "engineering,marketing,finance,operations".

Migrated in Phase 2 (P2-1): query_opa_policy moved from
interceptor/middleware.py to decision_service/main.py (D12). The exact
denial strings asserted here come from the Rego policy itself, unaffected
by which process calls OPA, so only the import target changes.
"""

import importlib.util as _importlib_util
import os
import sys

import httpx
import pytest

# decision_service/main.py's own `from schemas import ...` needs this
# directory on sys.path - loading main.py itself via spec_from_file_location
# below (to dodge the module-name collision, see _load_decision_service_main)
# does not add its own directory to sys.path automatically the way a normal
# package-relative import would.
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "decision_service"))


def _load_decision_service_main():
    """decision_service/main.py and control_plane/main.py are both named
    main.py - a bare `import main` clobbers sys.modules["main"] for every
    other test file in the same pytest session regardless of which
    sys.path entry was active when the import ran. Loading this one under
    its own explicit module name sidesteps the collision."""
    spec = _importlib_util.spec_from_file_location(
        "decision_service_main",
        os.path.join(os.path.dirname(__file__), "..", "decision_service", "main.py"),
    )
    module = _importlib_util.module_from_spec(spec)
    sys.modules["decision_service_main"] = module
    spec.loader.exec_module(module)
    return module


os.environ.setdefault("SPIRE_DISABLED", "true")
os.environ.setdefault("OPA_URL", "http://localhost:8181/v1/data/ail/main/evaluation")

query_opa_policy = _load_decision_service_main().query_opa_policy


def _opa_reachable() -> bool:
    try:
        httpx.get("http://localhost:8181/health", timeout=2)
        return True
    except Exception:
        return False


requires_opa = pytest.mark.skipif(not _opa_reachable(), reason="OPA not reachable at localhost:8181")


@requires_opa
def test_gdpr_pci_dss_region_message_is_sorted_concat_not_set_format():
    args = {
        "instance_type": "t3.micro",
        "region": "us-west-2",  # not approved
        "cost_per_hour": 5.0,
        "tags": {
            "environment": "dev",
            "data_classification": "pci-dss",
            "cost_center": "engineering",
            "project": "webapp",
        },
    }
    result = query_opa_policy("provision_cloud_server", args)
    assert result["outcome_type"] == "policy_deny", f"Expected policy_deny, got: {result}"
    expected = (
        "DENIED: GDPR Data Residency Violation. 'pci-dss' workloads must run in "
        "an approved region. Approved: eu-central-1, us-east-1"
    )
    assert expected in result["reasons"], f"Expected exact message in {result['reasons']}"


@requires_opa
def test_gdpr_unclassified_region_message_is_sorted_concat_not_set_format():
    args = {
        "instance_type": "t3.micro",
        "region": "us-west-2",  # not approved
        "cost_per_hour": 5.0,
        "tags": {
            "environment": "dev",
            "cost_center": "engineering",
            "project": "webapp",
            # data_classification omitted -> object.get default "" -> unclassified
        },
    }
    result = query_opa_policy("provision_cloud_server", args)
    assert result["outcome_type"] == "policy_deny", f"Expected policy_deny, got: {result}"
    expected = (
        "DENIED: GDPR Data Residency Violation. Unclassified data defaults to "
        "highly sensitive and must run in an approved region. Approved: eu-central-1, us-east-1"
    )
    assert expected in result["reasons"], f"Expected exact message in {result['reasons']}"


@requires_opa
def test_gdpr_purpose_limitation_message_is_sorted_concat_not_set_format():
    args = {
        "target_table": "pii_records",
        "query": "SELECT * FROM pii_records",
        "processing_purpose": "analytics",  # not approved
        "masking_enabled": True,
    }
    result = query_opa_policy("query_database", args)
    assert result["outcome_type"] == "policy_deny", f"Expected policy_deny, got: {result}"
    expected = (
        "DENIED: GDPR Violation. Unauthorized processing purpose 'analytics' "
        "for PII table. Approved purposes: billing, customer_support"
    )
    assert expected in result["reasons"], f"Expected exact message in {result['reasons']}"


@requires_opa
def test_finops_cost_center_message_is_sorted_concat_not_set_format():
    args = {
        "instance_type": "t3.micro",
        "region": "us-east-1",
        "cost_per_hour": 5.0,
        "tags": {
            "environment": "prod",
            "data_classification": "internal",
            "encryption_at_rest": "true",  # avoid also tripping SOC2's encryption rule
            "cost_center": "not-a-real-center",  # not approved
            "project": "webapp",
        },
    }
    result = query_opa_policy("provision_cloud_server", args)
    assert result["outcome_type"] == "policy_deny", f"Expected policy_deny, got: {result}"
    expected = (
        "DENIED: Production environments must include a valid 'cost_center' tag. "
        "Approved values: engineering, finance, marketing, operations."
    )
    assert expected in result["reasons"], f"Expected exact message in {result['reasons']}"
