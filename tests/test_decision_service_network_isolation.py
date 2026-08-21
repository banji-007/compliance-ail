"""
tests/test_decision_service_network_isolation.py - P2-1 (Phase 2, D12).

The agent process used to share one flat compose network with opa,
verifier, ail-control-plane, and immudb - the exact network position
red-team U1 (OPA bundle-manifest forgery), U5 (forged erasure tombstone via
the verifier's unauthenticated /write), and U8 (unauthenticated policy
replacement, a full allow bypass) all used
(docs/reports/phase-1-2-redteam.md). docker-compose.yml now declares two
networks, edge and backend, and this file asserts the assignment statically:
langgraph-demo (the agent) is edge-only, decision-service and everything it
alone may reach are backend-only, and envoy is the sole bridge.

Static config check - no running stack required, same pattern
tests/test_host_port_bindings.py already established for port bindings.
Complements (does not replace) the live reproduction of U1/U5/U8 from
inside a running agent container, captured in docs/reports/phase-2.md.
"""

import os

import pytest
import yaml

REPO_ROOT = os.path.join(os.path.dirname(__file__), "..")
_DEPLOYMENT_COMPOSE = "docker-compose.yml"

# Everything U1/U5/U8 reached from the agent's old network position.
_AGENT_MUST_NOT_REACH = {"opa", "verifier", "ail-control-plane", "immudb"}


def _load_compose(filename: str) -> dict:
    path = os.path.join(REPO_ROOT, filename)
    with open(path, "r", encoding="utf-8") as f:
        return yaml.safe_load(f)


def _networks_for(compose: dict, service: str) -> set[str]:
    service_def = compose["services"].get(service, {})
    nets = service_def.get("networks", [])
    # Compose allows both list and mapping form for a service's `networks:`;
    # this project only ever uses the list form, but handle both so this
    # test reads the same field Compose itself would.
    if isinstance(nets, dict):
        return set(nets.keys())
    return set(nets)


def test_agent_is_edge_only():
    """
    Mutation: add "backend" to langgraph-demo's networks: list in
    docker-compose.yml. This test must fail against that mutation.
    """
    compose = _load_compose(_DEPLOYMENT_COMPOSE)
    agent_networks = _networks_for(compose, "langgraph-demo")
    assert agent_networks == {"edge"}, (
        f"langgraph-demo must be edge-only, found networks: {sorted(agent_networks)}. "
        f"Any backend membership restores the agent's old direct network position to "
        f"opa/verifier/ail-control-plane/immudb - the exact reach U1/U5/U8 used."
    )


@pytest.mark.parametrize("service", sorted(_AGENT_MUST_NOT_REACH))
def test_backend_services_are_never_on_edge(service):
    """
    The converse of test_agent_is_edge_only: opa, verifier,
    ail-control-plane, and immudb must never be reachable from edge either -
    checking only the agent's own membership would miss a mutation that
    instead widens one of these services onto edge.

    Mutation: add "edge" to any of opa/verifier/ail-control-plane/immudb's
    networks: list. This test must fail against that mutation.
    """
    compose = _load_compose(_DEPLOYMENT_COMPOSE)
    networks = _networks_for(compose, service)
    assert "edge" not in networks, (
        f"{service} must not be on the edge network - found: {sorted(networks)}. "
        f"This is the surface U1/U5/U8 used when the agent shared this network."
    )


def test_decision_service_is_backend_only():
    """
    decision-service is the sole intended caller of opa/verifier/
    ail-control-plane on this network. It must never carry edge membership -
    that would give it (and, transitively via any future flaw in Envoy's
    routing, potentially the agent) a second identity on the agent's own
    network rather than being reached exclusively through Envoy's
    retargeted mTLS listener.

    Mutation: add "edge" to decision-service's networks: list. This test
    must fail against that mutation.
    """
    compose = _load_compose(_DEPLOYMENT_COMPOSE)
    networks = _networks_for(compose, "decision-service")
    assert networks == {"backend"}, (
        f"decision-service must be backend-only, found: {sorted(networks)}"
    )


def test_envoy_is_the_only_dual_homed_service():
    """
    Envoy is deliberately the one bridge between edge and backend (the same
    segmented topology docs/reports/spike-mcp-mediation.md confirmed safe:
    a client on the agent's segment alone cannot resolve or route to
    anything on the other segment except through this one proxy). No other
    service should carry both networks - that would open a second,
    unintended bridge.

    Mutation: add both "edge" and "backend" to any other service's
    networks: list. This test must fail against that mutation.
    """
    compose = _load_compose(_DEPLOYMENT_COMPOSE)
    dual_homed = []
    for service in compose["services"]:
        nets = _networks_for(compose, service)
        if "edge" in nets and "backend" in nets:
            dual_homed.append(service)
    assert dual_homed == ["envoy"], (
        f"Expected exactly one dual-homed service (envoy), found: {sorted(dual_homed)}"
    )
