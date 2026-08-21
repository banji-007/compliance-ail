# ADR 0008: The Decision Service Boundary and Per-Tool Authority Exclusivity

## Status

Accepted

## Context

Every phase through 1.3 hardened the interceptor's own authorization checks
while leaving one fact unchanged: `intercept_tool_call` ran inside the
agent's own process, on the agent's own network position, holding every
credential the ledger and policy engine needed. ADR-0005 already stated the
consequence architecturally - this gateway, as built, was `observed`, and a
compromised container evaded it entirely, not by defeating a check but by
never calling it.

Phase 1.2's red-team made this concrete. U1 forged an OPA bundle manifest's
revision field by writing directly to `data.system.bundles` - reachable
because the agent shared a network with OPA. U5 forged a `content_erasure`
tombstone by writing directly to the verifier's `/write`, which carried no
authentication at all, from the same network position. U8 combined the two:
deleting the bundle's manifest entry disabled OPA's root-ownership
protection for the entire `ail.*` tree, then an unauthenticated
`PUT /v1/policies/evil-eval` redefined `ail.main.evaluation` to
`{"allow": true}` directly - confirmed end-to-end through the real
interceptor code path. All three attacks used the same thing: the agent's
network position and the credentials sitting in its own environment.

The go/no-go spike (`docs/reports/spike-mcp-mediation.md`) answered the
question this raised for what would replace it: is mediation ever
unbypassable against a compromised (not just prompt-injected) agent? The
answer was conditional, not absolute. Under stdio, network bypass is
structurally impossible, but an agent that can independently reach a tool's
authority (a shared mount, the server binary itself) bypasses any proxy
sitting in front of it by running its own copy. Under HTTP, bypass is
purely a function of network reachability. In both cases, mediation holds
only where the gateway holds the tool's authority *exclusively* - a
property of the tool and its deployment, not of any proxy's own logic.

## Decision

### D12: the decision service owns evaluation and record writing

Schema validation, the OPA policy query, the ledger write, and the content
store write all move out of the agent process into a new service,
`decision_service/` (`decision_service/main.py`). The agent sends one
request - `POST /decide` with `{tool_name, tool_args, agent_id}` - and
receives a verdict. `interceptor/middleware.py::intercept_tool_call` is now
a thin HTTP client: it builds that request, presents the agent's own mTLS
identity to Envoy (retargeted from OPA to the decision service -
`envoy/envoy.yaml`), and returns the response unchanged. Its return
contract (`status`, `message`, `outcome_type`, `fault_class`,
`policy_revision`, `ledger_tx_id?`) is unchanged, so
`agent/base_agent.py` and `framework_integration/langgraph_demo.py` needed
no changes at all beyond adding the one new tool D14 introduces.

`docker-compose.yml` now declares two networks. `edge` holds the agent
(`langgraph-demo`) and Envoy; `backend` holds `decision-service`, `opa`,
`verifier`, `ail-control-plane`, and `immudb`. Envoy alone is dual-homed.
The agent cannot resolve or route to any backend service by name or
address - this is what makes U1's manifest forgery, U5's forged tombstone,
and U8's unauthenticated policy replacement unrepresentable from the
agent's network position, not patched against as attacks the agent's
position still reaches.

**This limit is explicit and does not go away:** moving the decision does
not stop an agent from sending one tool call to the decision service for
evaluation and then executing a *different* action, or the same action with
different parameters, on its own - for any tool whose authority the agent
independently holds. The three Python-function tools
(`provision_cloud_server`, `query_database`, `deploy_to_production`) are
exactly this case: their "execution" is a dummy function inside
`framework_integration/langgraph_demo.py` itself, callable directly,
decision service or not. D12 closes the class of attack that reached the
gateway's own infrastructure (OPA's management API, the verifier's write
endpoint); it does not, by itself, make any tool's authority exclusive.
D12 and D13 are two separate halves of this phase and neither is sufficient
alone.

### D13: the registry declares authority; the record distinguishes demonstrated from declared

`decision_service/schemas.py::TOOL_REGISTRY` replaces the old
`TOOL_VALIDATORS` (`Dict[str, Callable]`) with
`Dict[str, ToolRegistration]`, where `ToolRegistration` carries a
`validator`, an `authority_holder`, a `mechanism`, a `profile`
(`"observed"` | `"mediated"`), and a `claimed_exclusivity`
(`"demonstrated"` | `"declared"` | `None`).

The claimed value is never written to a record as-is. A separate, closed
set - `schemas._VERIFIABLE_MECHANISMS`, exactly one member today
(`"mcp_stdio_secret_mount"`) - names the mechanisms this gateway actually
knows how to check, and `schemas._MECHANISM_VERIFIED` is populated only by
`decision_service/main.py` actually running that mechanism's own startup
check (`_verify_mcp_stdio_secret_mount`), never by config.
`resolve_exclusivity_for` is the one function that decides what a record
carries: `"demonstrated"` only if the tool's mechanism is verifiable *and*
that check passed this boot; `"declared"` otherwise, regardless of what the
tool's own configuration claims. A tool configured `claimed_exclusivity:
"demonstrated"` with `mechanism: "shared_volume"` (the spike's A5b shape -
an ambient resource dressed up as exclusive) is recorded `"declared"`,
because `"shared_volume"` never enters `_VERIFIABLE_MECHANISMS` -
`tests/test_exclusivity_verification.py` plants exactly this case.

Without this, `mediated` becomes a claim anyone can make by editing a
config file - the self-certifying-record defect ADR-0005 already
identified, in a new location.

### D14: the demonstration tool - an MCP stdio server holding a credential delivered across an OS boundary

`read_vault_secret` is the one tool registered with `mechanism:
"mcp_stdio_secret_mount"`. Its authority is a token
(`decision_service/secrets/vault_api_token.txt`, generated by `make
keygen`, gitignored) delivered to the `decision-service` container alone as
a Docker Compose secret, mounted at `/run/secrets/vault_api_token`.
`decision_service/main.py::_verify_mcp_stdio_secret_mount` deliberately
does not check the mount's permission bits - plain (non-Swarm) `docker
compose` does not honor a secret's `mode:`/`uid:`/`gid:` fields at all
(Compose says so directly: "secrets `uid`, `gid` and `mode` are not
supported, they will be ignored"), and the as-mounted mode reflects host
filesystem translation this gateway does not control (777, observed live
on this project's own Windows/Docker Desktop dev environment). What it
checks instead is that the mount is read-only to the container itself,
including its own root user - confirmed live (a write attempt raises
`EROFS`) - which is a property of Docker's actual secrets mechanism, not
of any particular host's permission-bit translation. `decision_service/main.py::_execute_vault_tool` spawns
`decision_service/mcp_tools/vault_server.py` as its own child process, with
**no `env=` entry carrying the token** -
`tests/test_credential_boundary_static.py` asserts this directly by parsing
the spawn call itself. `vault_server.py` reads the token itself, from the
mounted file, at its own startup (`_load_token`); nothing that spawns it
ever hands it the value.

This is the spike's own M4 finding, closed rather than reproduced: under
normal stdio spawning, the spawning client sets the child's environment, so
a credential passed to a proxy by env var is readable by whatever spawned
it. Here, the agent never spawns anything MCP-related at all - it has no
client config naming this tool, no network route to `decision-service` or
the vault server, and the vault server binary is never copied into the
agent's Docker image (confirmed by `tests/test_vault_tool_bypass.py`'s A5
check). The credential crosses an OS boundary the agent's principal cannot
cross: a Compose secret mounted into a container the agent has no route
into, at all, under any mechanism this phase implements.

**This is a real deployment change, not a config edit.** It required a new
service, a new container image, a new network topology, and a new
credential-delivery mechanism - not a client pointed at a different URL.

### D15: the three Python-function tools stay, labelled Observed

`provision_cloud_server`, `query_database`, and `deploy_to_production`
remain exactly what they always were - dummy functions the agent calls
directly after a decision service approves the call, with no authority the
gateway holds exclusively. They are not pruned for uniformity; they are the
honest illustration that profile is a property of the tool, not the
deployment. `decision_service/schemas.py` registers each with
`authority_holder: "agent (ambient)"`, `mechanism: "in_process_function"`,
and no exclusivity claim at all - `resolve_exclusivity` returns `None` for
all three, and their records carry no `exclusivity` key
(`tests/test_record_profile.py::test_raw_decision_record_for_observed_tool_carries_no_exclusivity_key_at_all`).

## Consequences

**Gained:**

- U1, U5, and U8's exact mechanisms - unauthenticated writes to
  `data.system.bundles`, the verifier's unauthenticated `/write`, and
  unauthenticated policy installation - are unreachable from the agent's
  network position, not merely untested from it
  (`tests/test_decision_service_network_isolation.py`,
  `docs/reports/phase-2.md`'s live reproduction).
- One tool, `read_vault_secret`, is provably mediated: an agent with
  arbitrary code execution in its own container, attempting every bypass
  from the spike's M2 list, fails at every attempt, for lack of reach or
  credential (`tests/test_vault_tool_bypass.py`).
- Records now distinguish a verified exclusivity claim from an asserted
  one, closing the self-certifying-record gap for any future tool a
  config file might claim exclusivity for without the gateway being able
  to check it.

**Constraints:**

- The three Python-function tools are unaffected by any of this. A
  compromised agent container can still call
  `execute_provision_cloud_server`/`execute_query_database`/
  `execute_deploy_to_production` directly, or call
  `intercept_tool_call` with one set of arguments and act on a different
  decision entirely - the send-one-execute-another gap D12 states
  explicitly. Nothing in this phase closes that for these three tools; only
  authority exclusivity does, and only `read_vault_secret` has it.
- `_VERIFIABLE_MECHANISMS` has exactly one member. Any future tool claiming
  `demonstrated` exclusivity by a different mechanism (a different secret
  delivery method, a hardware-backed credential, a different OS-boundary
  primitive) needs its own startup check added here before it can ever be
  recorded as anything but `declared` - deliberately not something a config
  change alone can grant.
- Decision-service now holds the credentials the agent used to hold
  directly (`VERIFIER_URL`, `IMMUDB_USER`/`PASSWORD` via the verifier,
  `CONTROL_PLANE_WRITE_KEY`) - the blast radius of decision-service's own
  compromise is now everything the agent's compromise used to reach. This
  is the intended trade: one network-segmented, purpose-built service
  holding these credentials, instead of the general-purpose agent process
  an LLM's own tool-calling loop runs inside of.
- Envoy's mTLS terminator now fronts the decision service instead of OPA.
  This reuses Phase 0's existing SPIFFE/SPIRE mechanism, retargeted at the
  relocated boundary - not a new identity mechanism, and not itself
  hardened further by this phase.

## References

- `decision_service/main.py`, `decision_service/schemas.py`,
  `decision_service/mcp_tools/vault_server.py`
- `interceptor/middleware.py::intercept_tool_call` (now a client),
  `_spire_absent_exit` (P2-5)
- `docker-compose.yml`'s `edge`/`backend` networks and `decision-service`,
  `envoy` (retargeted), `langgraph-demo` (edge-only) service definitions
- `envoy/envoy.yaml`'s `decision_service_cluster`
- `docs/reports/spike-mcp-mediation.md` - the go/no-go spike this ADR's D13/
  D14 close the gap the spike identified (M2, M4, A5/A5b)
- `docs/reports/phase-1-2-redteam.md`, U1/U5/U8 - the attacks D12 makes
  unrepresentable
- `docs/adr/0005-outcome-taxonomy.md` - the profile vocabulary D13 extends
  with `exclusivity`; the "reaching mediated is not a proxy-placement
  exercise" section this ADR is the direct answer to
- `tests/test_decision_service_network_isolation.py` (P2-1),
  `tests/test_exclusivity_verification.py` (P2-2),
  `tests/test_record_profile.py` (P2-3),
  `tests/test_vault_tool_bypass.py` and
  `tests/test_credential_boundary_static.py` (P2-4),
  `tests/test_spire_absent_guard.py` (P2-5)
- `docs/reports/phase-2.md` - demonstration, enforcement, and mutation
  evidence per item
