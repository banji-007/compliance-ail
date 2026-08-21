"""
tests/test_host_port_bindings.py - P13-1, P13-2 (Phase 1.3), extended by R1
(Phase 1.3 completion pass).

Red-team U1/U8 (docs/reports/phase-1-2-redteam.md): OPA's management API
(`/v1/data/system/bundles/*`, `/v1/policies/*`) was reachable, unauthenticated,
wherever OPA's host port was published - "8181:8181" binds to 0.0.0.0 by
Docker's own default, i.e. every interface on the host, not just loopback.
Red-team U5/finding 6.1: the verifier's `/write` and `/verify` had no
authentication at all, and the same unrestricted publish pattern applied to
its port. P13-1/P13-2 fixed this by binding both to 127.0.0.1 explicitly.

R1 (docs/reports/phase-1-3-redteam.md, V2): the loopback bind does not hold.
`host.docker.internal` reaches a 127.0.0.1-published port from any container
on the Docker host, including one on a network sharing nothing with the
compose project - live-demonstrated against both OPA and the verifier, from
a container on a freshly created, unrelated network. Binding cannot close
that, so the fix in the deployment compose (docker-compose.yml) is to not
publish these ports to the host at all, for the full set of surfaces that
can change policy or write a record: opa (8181), verifier (8003), immudb
(3322, 8080), envoy's admin API (9901), spire-server (8081), and the control
plane (8002, which V2 separately showed was never loopback-bound in the
first place).

docker-compose.test.yml keeps publishing what the integration suite needs
to reach from the host - see that file's own header comment - and is
deliberately more permissive. It is never a deployment target.

Static config check - no running stack required. Parses the actual YAML
(not a text/regex match) so a port mapping's meaning is read the same way
Docker Compose itself reads it.
"""

import os

import pytest
import yaml

REPO_ROOT = os.path.join(os.path.dirname(__file__), "..")

_GUARDED = {
    "opa": "8181",               # P13-1: OPA's Data + management API, same listener
    "verifier": "8003",          # P13-2: the verifier's /write and /verify
    "decision-service": "8010",  # P2-1 (Phase 2): schema/OPA/ledger, moved out of the agent
}

# R1: every surface that can change policy or write a record, across every
# service that has one. Not just opa/verifier - immudb's own ports are a
# direct ledger read/write surface independent of the verifier, envoy's
# admin API is a management surface, spire-server's port is SPIRE's own
# management API, and the control plane's 8002 is where PUT /tenants and
# POST/DELETE /content live.
_MANAGEMENT_OR_RECORD_PORTS = {
    "ail-control-plane": ["8002"],
    "opa": ["8181"],
    "immudb": ["3322", "8080"],
    "verifier": ["8003"],
    "spire-server": ["8081"],
    "envoy": ["9901"],
    # P2-1 (Phase 2): decision-service holds the same reach opa/verifier/
    # ail-control-plane do (it is the only thing that talks to all three) -
    # never published to the host in the deployment compose either.
    "decision-service": ["8010"],
}

_DEPLOYMENT_COMPOSE = "docker-compose.yml"
_TEST_COMPOSE = "docker-compose.test.yml"


def _load_compose(filename: str) -> dict:
    path = os.path.join(REPO_ROOT, filename)
    with open(path, "r", encoding="utf-8") as f:
        return yaml.safe_load(f)


def _host_bindings_for(compose: dict, service: str, container_port: str) -> list[str]:
    """
    Return every raw port-mapping string (Compose "short syntax") for the
    given service whose container-side port matches. Docker Compose's own
    short-syntax host-binding rule: "8181:8181" binds every host interface
    (0.0.0.0) because no IP was given; only an explicit IP prefix
    ("127.0.0.1:8181:8181") restricts the bind address. This test reads the
    same field Compose does, not a derived summary of it.
    """
    service_def = compose["services"].get(service, {})
    raw_ports = service_def.get("ports", [])
    matches = []
    for entry in raw_ports:
        spec = str(entry)
        parts = spec.split(":")
        if parts[-1].split("/")[0] == container_port:
            matches.append(spec)
    return matches


@pytest.mark.parametrize("service,container_port", sorted(_GUARDED.items()))
def test_management_port_not_bound_to_a_non_loopback_address_on_test_compose(service, container_port):
    """
    P13-1 (opa/8181) and P13-2 (verifier/8003): on docker-compose.test.yml,
    which still publishes these ports for the integration suite to reach
    from the host, the host-side publish must carry an explicit 127.0.0.1
    bind address. A bare "PORT:PORT" mapping is Docker's own default for
    "every interface" - the exact shape both U1/U8 and U5 exploited from
    off-host reachability.

    Not asserted against docker-compose.yml (the deployment compose): R1
    removed these ports from that file entirely, so there is no binding
    left to check there - see
    test_deployment_compose_publishes_no_management_or_record_port below.

    Mutation named in docs/reports/phase-1-3.md: restore the previous
    binding (drop the "127.0.0.1:" prefix). This test must fail against
    that mutation.
    """
    compose = _load_compose(_TEST_COMPOSE)
    bindings = _host_bindings_for(compose, service, container_port)
    assert bindings, (
        f"{_TEST_COMPOSE}: expected a host port mapping for {service}:{container_port}, found none"
    )
    for binding in bindings:
        assert binding.startswith("127.0.0.1:"), (
            f"{_TEST_COMPOSE}: {service}'s port mapping {binding!r} is not loopback-bound - "
            f"a bare host port (no IP prefix) binds every host interface by Docker's own "
            f"default, reachable from any machine on the same network as the host"
        )


@pytest.mark.parametrize(
    "service,container_port",
    sorted((s, p) for s, ports in _MANAGEMENT_OR_RECORD_PORTS.items() for p in ports),
)
def test_deployment_compose_publishes_no_management_or_record_port(service, container_port):
    """
    R1 (Phase 1.3 completion pass, red-team V2): the deployment compose
    (docker-compose.yml) must publish no host port at all for any surface
    that can change policy or write a record. A loopback bind is not
    sufficient - host.docker.internal reaches a 127.0.0.1-published port
    from any container on the Docker host, on any network, live-confirmed
    against both OPA and the verifier from a container with no relationship
    to this compose project at all. The only fix that closes this is to not
    publish the port to the host in the first place.

    Mutation: add back any "ports:" entry for one of these service/port
    pairs in docker-compose.yml (loopback-bound or not). This test must
    fail against that mutation, because it checks for absence, not for a
    particular binding shape.
    """
    compose = _load_compose(_DEPLOYMENT_COMPOSE)
    bindings = _host_bindings_for(compose, service, container_port)
    assert not bindings, (
        f"{_DEPLOYMENT_COMPOSE}: {service}:{container_port} must not be published to the host "
        f"at all (a management or record-writing surface) - found: {bindings}"
    )
