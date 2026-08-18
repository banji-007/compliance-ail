"""
tests/test_host_port_bindings.py - P13-1, P13-2 (Phase 1.3).

Red-team U1/U8 (docs/reports/phase-1-2-redteam.md): OPA's management API
(`/v1/data/system/bundles/*`, `/v1/policies/*`) was reachable, unauthenticated,
wherever OPA's host port was published - "8181:8181" binds to 0.0.0.0 by
Docker's own default, i.e. every interface on the host, not just loopback.
Red-team U5/finding 6.1: the verifier's `/write` and `/verify` had no
authentication at all, and the same unrestricted publish pattern applied to
its port.

This does not make either API safe - see the residual limits in
docs/reports/phase-1-3.md (P13-1, P13-2): anything on the host, and anything
inside the compose network including the agent container, still reaches
both APIs unauthenticated. It closes exactly one thing: a second machine on
the same network as the Docker host can no longer reach either port merely
because the host published it.

Static config check - no running stack required. Parses the actual YAML
(not a text/regex match) so a port mapping's meaning is read the same way
Docker Compose itself reads it.
"""

import os

import pytest
import yaml

REPO_ROOT = os.path.join(os.path.dirname(__file__), "..")

_GUARDED = {
    "opa": "8181",       # P13-1: OPA's Data + management API, same listener
    "verifier": "8003",  # P13-2: the verifier's /write and /verify
}

_COMPOSE_FILES = ["docker-compose.yml", "docker-compose.test.yml"]


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
    service_def = compose["services"][service]
    raw_ports = service_def.get("ports", [])
    matches = []
    for entry in raw_ports:
        spec = str(entry)
        parts = spec.split(":")
        if parts[-1].split("/")[0] == container_port:
            matches.append(spec)
    return matches


@pytest.mark.parametrize("compose_file", _COMPOSE_FILES)
@pytest.mark.parametrize("service,container_port", sorted(_GUARDED.items()))
def test_management_port_not_bound_to_a_non_loopback_address(compose_file, service, container_port):
    """
    P13-1 (opa/8181) and P13-2 (verifier/8003): the host-side publish for
    each of these ports must carry an explicit 127.0.0.1 bind address, in
    every compose file that starts the service. A bare "PORT:PORT" mapping
    is Docker's own default for "every interface" - the exact shape both
    U1/U8 and U5 exploited from off-host reachability.

    Mutation named in docs/reports/phase-1-3.md: restore the previous
    binding (drop the "127.0.0.1:" prefix). This test must fail against
    that mutation.
    """
    compose = _load_compose(compose_file)
    bindings = _host_bindings_for(compose, service, container_port)
    assert bindings, (
        f"{compose_file}: expected a host port mapping for {service}:{container_port}, found none"
    )
    for binding in bindings:
        assert binding.startswith("127.0.0.1:"), (
            f"{compose_file}: {service}'s port mapping {binding!r} is not loopback-bound - "
            f"a bare host port (no IP prefix) binds every host interface by Docker's own "
            f"default, reachable from any machine on the same network as the host"
        )
