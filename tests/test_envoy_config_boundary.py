"""
tests/test_envoy_config_boundary.py - P2-9 (Phase 2 completion pass B).

W2 (docs/reports/phase-2-redteam.md): retargeting Envoy's cluster straight
at OPA passes 29/29 of the committed no-stack-required test suite while
live-reproducing a full OPA-management-API bypass through the agent's real
mTLS channel (GET /v1/data/system/bundles/ail-policies/manifest/revision ->
200, the exact surface P2-1 exists to close) - because no committed test
ever inspected envoy/envoy.yaml's content. Static YAML parse, no stack
required, same convention tests/test_host_port_bindings.py already
established for asserting a security property against a config file's
content rather than merely its presence.
"""

from pathlib import Path

import yaml

REPO_ROOT = Path(__file__).resolve().parents[1]
ENVOY_YAML = REPO_ROOT / "envoy" / "envoy.yaml"

_ALLOWED_UPSTREAM_HOST = "decision-service"
_ALLOWED_UPSTREAM_PORT = 8010
_ALLOWED_AGENT_SAN = "spiffe://ail.internal/workload/agent"
_DISALLOWED_BACKEND_HOSTS = {"opa", "verifier", "ail-control-plane", "immudb"}


def _load():
    return yaml.safe_load(ENVOY_YAML.read_text(encoding="utf-8"))


def _clusters(config):
    return config["static_resources"]["clusters"]


def _socket_address_endpoints(cluster):
    """Only endpoints reachable over the network. The SPIRE Workload API
    cluster resolves over a unix pipe (it is the SDS certificate source, not
    a decision-making backend) and has no socket_address to check here."""
    for ep in cluster.get("load_assignment", {}).get("endpoints", []):
        for lb in ep.get("lb_endpoints", []):
            addr = lb.get("endpoint", {}).get("address", {})
            if "socket_address" in addr:
                yield cluster["name"], addr["socket_address"]


def test_every_network_cluster_targets_only_the_decision_service():
    """Mutation (red-team W2, mutation 4, applied verbatim): retarget
    decision_service_cluster's endpoint from decision-service:8010 to
    opa:8181. This test must fail."""
    config = _load()
    checked_any = False
    for cluster in _clusters(config):
        for name, sockaddr in _socket_address_endpoints(cluster):
            checked_any = True
            assert sockaddr["address"] == _ALLOWED_UPSTREAM_HOST, (
                f"Cluster {name!r} targets host {sockaddr['address']!r} - "
                f"only {_ALLOWED_UPSTREAM_HOST!r} may receive traffic Envoy "
                f"forwards from the agent's authenticated mTLS channel"
            )
            assert sockaddr["port_value"] == _ALLOWED_UPSTREAM_PORT, (
                f"Cluster {name!r} targets port {sockaddr['port_value']}, "
                f"expected {_ALLOWED_UPSTREAM_PORT}"
            )
    assert checked_any, "No socket_address-backed cluster found - test itself is broken"


def test_no_cluster_targets_a_backend_service_other_than_decision_service():
    """Independent of the host/port pairing above: names every backend
    service this project defines and asserts none of them ever appear as a
    cluster target, so a retarget to a different port on the same
    disallowed host is caught too."""
    config = _load()
    for cluster in _clusters(config):
        for name, sockaddr in _socket_address_endpoints(cluster):
            assert sockaddr["address"] not in _DISALLOWED_BACKEND_HOSTS, (
                f"Cluster {name!r} targets disallowed backend host {sockaddr['address']!r} directly"
            )


def _virtual_hosts(config):
    hcm = config["static_resources"]["listeners"][0]["filter_chains"][0]["filters"][0]["typed_config"]
    return hcm["route_config"]["virtual_hosts"]


def test_route_table_sends_every_path_to_the_decision_service_cluster():
    """Mutation: add a second route (any path) whose destination cluster is
    not decision_service_cluster. This test must fail."""
    config = _load()
    vhosts = _virtual_hosts(config)
    assert len(vhosts) >= 1, "No virtual host defined - test itself is broken"
    checked_any = False
    for vhost in vhosts:
        for route in vhost["routes"]:
            checked_any = True
            cluster = route["route"]["cluster"]
            assert cluster == "decision_service_cluster", (
                f"Route {route.get('match')} in virtual host {vhost.get('name')} "
                f"targets {cluster!r}, not decision_service_cluster"
            )
    assert checked_any, "No route found - test itself is broken"


def _validation_context_sans(config):
    listener = config["static_resources"]["listeners"][0]
    transport_socket = listener["filter_chains"][0]["transport_socket"]
    ctx = transport_socket["typed_config"]["common_tls_context"]["combined_validation_context"]
    sans = ctx["default_validation_context"]["match_typed_subject_alt_names"]
    return [m["matcher"]["exact"] for m in sans]


def test_validation_context_admits_only_the_agent_identity():
    """envoy.yaml's own comment states the root identity
    (spiffe://ail.internal/workload/test) must never be a valid mTLS client
    in production - cited by docs/reports/phase-2.md as defense in depth,
    and confirmed live in docs/reports/phase-2-redteam.md W1 (Envoy rejects
    that handshake outright, SSLV3_ALERT_CERTIFICATE_UNKNOWN). Nothing
    before this test enforced it as a config property.

    Mutation: add spiffe://ail.internal/workload/test back to
    match_typed_subject_alt_names. This test must fail.
    """
    sans = _validation_context_sans(_load())
    assert sans == [_ALLOWED_AGENT_SAN], (
        f"Envoy's mTLS validation context admits {sans}, expected exactly "
        f"[{_ALLOWED_AGENT_SAN!r}] - a widened or additional identity here "
        f"reopens exactly the boundary P2-1 exists to close"
    )
