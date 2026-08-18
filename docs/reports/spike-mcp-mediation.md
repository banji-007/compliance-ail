# Spike Report: MCP mediation (can a proxy sit unbypassably between a compromised agent and its tool)

Spike instructions: the MCP mediation go/no-go spec. All spike artifacts (proxy, agent client, attack scripts, Dockerfile, compose topology, captured ledgers) live under `spikes/mcp-mediation/`. This report is the one output file placed outside that directory, as directed.

The claim under test, verbatim: **a compromised agent, with arbitrary code execution in its own container, cannot invoke an MCP tool without the invocation being evaluated and recorded first.** Not "the agent is configured to use the proxy." The question is what the agent can reach when it stops cooperating.

## 1. Environment, versions, MCP server and client used

- OS host: Windows 11 Home 10.0.22631. Docker Engine 29.7.2 (Linux containers).
- Container base image: `node:24-alpine`, Node v24.14.0. Single image (`ail-spike-mcp:latest`) built `--no-cache`, reused for the agent, proxy, and upstream roles. The role is decided by the compose command, not the image.
- MCP server (off-the-shelf, not hand-rolled): `@modelcontextprotocol/server-everything` **2026.8.18** (the official protocol test server), run in both its `stdio` and `streamableHttp` modes. A second official server, `@modelcontextprotocol/server-filesystem` **2026.7.10**, was used for the stdio self-spawn authority test (M2/A5b).
- MCP client / SDK (off-the-shelf): `@modelcontextprotocol/sdk` **1.30.0** (official TypeScript SDK), used both for the agent client and for the proxy's own upstream client and server transports.
- Proxy HTTP front end: `express` 5.2.1.
- Package names and versions were verified live against npm at spike time (`npm view`), not from memory: `@modelcontextprotocol/sdk` latest 1.30.0, `server-everything` latest 2026.8.18, `server-filesystem` 2026.7.10.

The proxy under test (`spikes/mcp-mediation/proxy/core.mjs`) is a real MCP-to-MCP proxy: it exposes an MCP `Server` to the agent, holds an MCP `Client` to the upstream, evaluates every `tools/call` before forwarding (deny `get-env`; deny any call whose arguments contain the marker `AIL-FORBIDDEN`), appends every decision and every result to a JSONL ledger, and returns an MCP tool-error result on a deny. Policy is deliberately trivial; the spike is about whether the proxy is on the path at all.

## 2. Verdict

**The verdict differs by transport, as the spec anticipated.**

- **stdio: GO WITH CHANGES.** There is genuinely no network address to find and the proxy owns its subprocess, so the network bypasses are all structurally impossible (confirmed by trying, not by reasoning). But mediation is unbypassable *only for tools whose entire authority is a secret held exclusively by the proxy*. When the tool's authority is anything the agent independently holds (a local file tree, a shared volume, a reachable socket, the server binary itself), the compromised agent spawns its own unmediated copy of the same off-the-shelf server and exercises the same authority with no proxy in between. I demonstrated this live: the agent self-spawned `server-filesystem` on a volume the proxy also uses and wrote a file to it, unmediated.

- **HTTP: NO-GO as an application-layer guarantee; GO only if the adopter also owns the network.** Mediation holds if and only if the upstream sits on a network the agent's container cannot route to. That is not a property of the proxy or of MCP; it is a property of the deployment's network segmentation. I demonstrated both sides live: from the agent's container (segmented) the upstream did not even resolve and bypass was blocked; from a container sharing the upstream's network, the identical bypass reached the tool and ran `get-env` unmediated. The upstream `server-everything` accepted an unauthenticated `initialize`, so within a shared network nothing at the MCP layer stops the agent.

One sentence per transport: **stdio mediation is unbypassable only when the proxy is the sole holder of the tool's authority; HTTP mediation is unbypassable only when the network prevents the agent from routing to the upstream.** In both cases the guarantee rests on something outside MCP and outside the proxy.

## 3. Items M1 to M6 with evidence

### M1. Topology

Both transports were stood up with a real off-the-shelf server, the official SDK client, and the proxy between them.

**stdio.** The agent's MCP client spawns the proxy as a subprocess and speaks MCP over the proxy's stdin/stdout. The proxy in turn spawns `server-everything stdio` as *its* subprocess. Nothing listens on a socket anywhere in this chain.

```
agent client  --stdio-->  proxy  --stdio-->  @modelcontextprotocol/server-everything
```

The client is pointed at the proxy by its own config file (`spikes/mcp-mediation/agent/mcp-config.json`), entry `everything`: `{"transport":"stdio","command":"node","args":["/opt/ail/proxy/proxy-stdio.mjs"]}`. What the client knows about the upstream: **nothing.** Its config names only the proxy command. The upstream command and the upstream secret live in the proxy's process (`AIL_UPSTREAM_ARGS`, `AIL_UPSTREAM_SECRET`), which the proxy passes to its own child.

Happy path, run inside the `agent-stdio` container:

```
[client] server entry:     {"transport":"stdio","command":"node","args":["/opt/ail/proxy/proxy-stdio.mjs"]}
[client] connected to:     {"name":"ail-mediation-proxy","version":"0.0.1"}
[client] tools visible:    13 -> echo, get-annotated-message, get-env, ...
[client] call echo -> isError=false :: Echo: hello from cooperating agent
[client] call echo -> isError=true :: DENY: argument contains forbidden marker AIL-FORBIDDEN
[client] call get-env -> isError=true :: DENY: tool get-env is not permitted (exfiltration risk)
```

The client connects to `ail-mediation-proxy`, not to `server-everything`: it never sees the real server's identity, only the proxy's.

**HTTP (streamable).** The proxy is a network service on `:8080`. The agent points at `http://proxy:8080/mcp`. The proxy connects upstream to `server-everything streamableHttp` on `http://upstream:3001/mcp`.

```
agent client  --http-->  proxy :8080  --http-->  upstream :3001
```

The client is pointed at the proxy by config entry `everything-http`: `{"transport":"http","url":"http://proxy:8080/mcp"}`. What the client knows about the upstream: only the name `upstream:3001` if it guesses it (the compose file and env deliberately expose that name so the bypass scripts have a target); it does not know, and does not hold, the upstream bearer token. Happy path, run inside the `agent` container:

```
[client] server entry:     {"transport":"http","url":"http://proxy:8080/mcp"}
[client] connected to:     {"name":"ail-mediation-proxy","version":"0.0.1"}
[client] mcp session id:   426a829c-986a-4b0d-8095-469d6ad79af1
[client] tools visible:    13 -> echo, get-annotated-message, get-env, ...
[client] call echo -> isError=false :: Echo: hello from cooperating agent
[client] call echo -> isError=true :: DENY: argument contains forbidden marker AIL-FORBIDDEN
[client] call get-env -> isError=true :: DENY: tool get-env is not permitted (exfiltration risk)
```

Network attachments (the whole HTTP answer lives here), from `ip -o addr`:

- `agent`: `172.18.0.3/16` on `edge` only.
- `proxy`: `172.18.0.2/16` on `edge` **and** `172.22.0.4/16` on `internal` (dual-homed; the only bridge).
- `upstream`: `internal` only (`172.22.x`, `internal: true` network).
- `scanner-internal` (a control container placed deliberately on `internal`): `172.22.0.3/16`.

### M2. Bypass

This is the item that decides the spike. Every attempt below was run, not reasoned about. The full table is in section 4; the evidence is here.

**stdio, from the `agent-stdio` container (on an isolated `stdio-only` network, alone).**

- A1 read own config: the config names only `node /opt/ail/proxy/proxy-stdio.mjs`. There is no upstream address in it to connect to. `A1 RESULT: entry 'everything' names the PROXY, not the upstream: YES`.
- A2 network scan (`proxy`, `upstream`, `localhost`, `127.0.0.1` across ports 3001/8080/3000/80): every hostname timed out, every loopback port `ECONNREFUSED`. There is no server listening anywhere on the network, because under stdio nothing listens. Nothing to reach.
- A3 process/environ inspection: `/proc` shows only the container's own pid 1 (`sleep infinity`); no foreign process, and by container PID-namespace isolation no way to see the proxy or server of any *other* container. (When the client is actually running, the proxy and server it spawns are the client's own children, so they are visible to the client, but they are children the client already controls.)
- A4 rewrite config to `http://upstream:3001/mcp` and reconnect: `ENOTFOUND: fetch failed`. No route, no DNS. Bypass blocked.
- A5 spawn the server binary directly: **succeeded.** The `server-everything` binary is present in the agent's own container (`/opt/ail/node_modules/.../server-everything/dist/index.js`), and the agent spawned it and called `get-env` with no proxy in between:

```
A5 server binary present in agent container: true
A5 RESULT: self-spawned server, 13 tools, get-env -> RETURNED DATA
A5 RESULT: reached an UNMEDIATED server instance the agent started itself
```

- A5b, the sharpened version, to answer "is a self-spawned instance a *real* bypass or a throwaway": the agent self-spawned the off-the-shelf `server-filesystem` rooted at `/ledger`, a volume the proxy also uses, and wrote a file to it:

```
A5b fs tools count: 14
A5b write isError: false -> Successfully wrote to /ledger/UNMEDIATED-WRITE-BY-AGENT.txt
```

Confirmed from the proxy's side of the shared volume:

```
/ledger/UNMEDIATED-WRITE-BY-AGENT.txt
--- file content ---
agent self-spawned a filesystem server and wrote to the shared ledger volume with no proxy in between
```

So under stdio the network bypasses are genuinely impossible (A1-A4), but the agent reaching the tool's underlying authority by running its own copy of the tool server is not (A5, A5b). The proxy owning *its* subprocess does not stop the agent from starting *its own*.

**HTTP, from the `agent` container (on `edge` only).**

- A1 read own config: names `http://proxy:8080/mcp`, the proxy, not the upstream.
- A2 network scan: `proxy:8080 -> OPEN` and a raw unauth `initialize` to it returns the proxy's own serverInfo (`ail-mediation-proxy`). Every `upstream:*` probe **timed out** (the name resolves nowhere routable from `edge`), every `localhost/127.0.0.1` port refused. The only thing reachable is the proxy.
- A3 process/environ inspection: agent's own env holds no upstream URL and no secret (`AIL_UPSTREAM_SECRET = <unset>`, `UPSTREAM_API_KEY = <unset>`); `/proc` shows only its own pid 1. Nothing to steal.
- A4 rewrite config to `http://upstream:3001/mcp` and reconnect: `ENOTFOUND: fetch failed`. `A4 RESULT: BYPASS BLOCKED`.

**HTTP, the contrast, from `scanner-internal` (a container sharing the upstream's `internal` network).** Same scripts, same upstream, only the network attachment differs:

- A2: `upstream:3001 -> OPEN | initialize -> HTTP 200` returning the real `server-everything` capabilities (note `prompts` and `tools.listChanged`, which the proxy does not advertise, so this is unmistakably the upstream, not the proxy) with **no auth header sent**.
- A4: `connected DIRECT to upstream, 13 tools, get-env -> RETURNED DATA` / `A4 RESULT: BYPASS SUCCEEDED (reached tool without proxy)`.

So under HTTP the bypass is decided entirely by whether the agent's container can route to the upstream. Segmented: blocked. Same network: full unmediated access, and the upstream enforces nothing of its own.

### M3. What the proxy can see and do

Before execution, the proxy observes the tool name, the full arguments, and client context, and it can refuse. Evidence from the captured HTTP ledger (`spikes/mcp-mediation/scratch/evidence-ledger-http.jsonl`):

```json
{"event":"tools/call","decision":"ALLOW","tool":"echo","arguments":{"message":"hello from cooperating agent"},"attribution":{...}}
{"event":"tools/call","decision":"DENY","tool":"echo","arguments":{"message":"payload AIL-FORBIDDEN smuggled"},"reason":"DENY: argument contains forbidden marker AIL-FORBIDDEN","attribution":{...}}
{"event":"tools/call","decision":"DENY","tool":"get-env","arguments":{},"reason":"DENY: tool get-env is not permitted (exfiltration risk)","attribution":{...}}
```

- Tool name: yes (`echo`, `get-env`).
- Full arguments: yes, the entire argument object, before forwarding.
- Refusal: yes. On a deny the proxy returns an MCP tool-error result (`isError: true`, text = the deny reason), which the client receives as a normal tool result, not a transport error. The client output confirms the shape: `call get-env -> isError=true :: DENY: tool get-env is not permitted`. The call never reaches the upstream.

The harder question, tool **results / the return path**: **yes, the proxy observes results.** Every allowed call produced a `tools/result` ledger entry with the upstream's actual return value:

```json
{"event":"tools/result","tool":"echo","isError":false,"result_preview":"{\"content\":[{\"type\":\"text\",\"text\":\"Echo: hello from cooperating agent\"}]}"}
```

This holds on both transports (the stdio ledger has the identical `tools/result` line). Because the proxy is a full MCP client to the upstream, the response flows back through it and is fully inspectable and modifiable. The return path that later trajectory work needs is present, not absent, for `tools/call`. Caveat worth recording: streaming side-channels (server-to-client notifications, sampling, elicitation, resource subscriptions) were not individually exercised; the request/response tool path is confirmed, the asynchronous notification path was not.

### M4. Credentials

**HTTP: yes, the upstream credential can live in the proxy alone.** The bearer token was set only in the proxy's environment (`AIL_UPSTREAM_SECRET` on the `proxy` service). A3 from the agent confirmed the agent holds none of it (`AIL_UPSTREAM_SECRET = <unset>`, `UPSTREAM_API_KEY = <unset>`). The proxy attaches `authorization: Bearer ...` on the proxy-to-upstream leg only. The agent never holds it. (Separately, in this spike the upstream did not *enforce* the token, which is why network segmentation, not the token, is what actually blocks bypass here; but the credential-isolation property M4 asks about does hold.)

**stdio: no, not against a compromised agent, if the credential is passed the normal way.** Under stdio the client spawns the proxy, and the standard MCP stdio transport lets the spawning client set the child's environment and arguments. So anything the proxy needs via env or args is, by construction, chosen or at least visible at the spawn point the agent controls. In this spike the upstream secret sat in the `agent-stdio` container's environment (because the client inherits and forwards it to the proxy child), and A3 found it: `A3 RESULT: found upstream secret in any foreign environ: YES` and `A3 own-env AIL_UPSTREAM_SECRET = s3cr3t-upstream-key`. If the agent must hold anything for the stdio proxy to start, the agent can read it. The only way to keep a real downstream credential from a compromised stdio agent is to have the proxy read it from a source behind an OS boundary the agent cannot cross (a file owned by a different uid, a socket with restrictive perms), which means the proxy is no longer a plain subprocess the agent spawns, which changes the deployment model (see M6).

### M5. Attribution

MCP carries no workload identity, and the spike confirms what is actually attributable is thin and differs by transport.

- **HTTP:** the proxy can attribute a call to an MCP **session** (a UUID the proxy's own transport mints at initialize, `mcp_session_id: 426a829c-...`), a **JSON-RPC request id**, and the **TCP peer** captured at session init (`tcp_peer: 172.18.0.3:36166`, the agent's edge IP). It cannot attribute to any client-supplied identity: `auth_info: null`, `http_header_authorization: null`, `user-agent: node`. The default SDK client sends no credential and no stable identity of its own. (Implementation note: I injected the TCP peer as a synthetic header at the Express layer and it recorded at `session/init`; the per-call `requestInfo.headers` did not carry it through, so per-call attribution reduces to the session id, which maps back to the peer recorded at init. Honest bound: connection/session identity plus network address, nothing cryptographic.)
- **stdio:** even less. No session id (`mcp_session_id: null`). The only OS-level fact is the process relationship: the proxy's own pid and its parent pid (`os_pid: 21, os_ppid: 8`), where the parent *is* the client that spawned it. So the proxy can attribute a call to "the process that spawned me," a parent-child relationship, and nothing more.

Bound for the profile definitions: the Mediated profile can attribute a call to a connection/session (HTTP) or a spawning process (stdio), plus a network address on HTTP. It cannot attribute to a workload identity. An Attested profile that wants cryptographic attribution must add an identity layer (mTLS client certs, SPIFFE SVIDs, signed tokens) that MCP itself does not provide and that the proxy would have to demand and verify; none of that exists in MCP or the SDK out of the box.

### M6. Adoption cost

What an adopter changes to go from no AIL to Mediated:

**stdio:** it is close to a pure configuration change on the client side. The adopter edits **one file**, the client's MCP config, to replace each server's `command`/`args` with the proxy command, and moves the real server command and any secret into the proxy's launch config. **One process is added** per tool server (the proxy, spawned by the client). Nothing is rebuilt; nothing is redeployed. **But** the deployability argument only delivers *cooperating-agent* mediation this way, because (M2/A5) the agent can still self-spawn the real server, and (M4) it can read any secret the proxy is handed. Closing those requires the proxy to run as a different OS principal with sole access to the server binary and credentials, which is no longer "the client spawns a subprocess" and is a real deployment change (separate uid/container/mount namespace), not a config edit.

**HTTP:** it is a configuration change *plus a network change*, and the network change is the load-bearing part. The adopter edits the client config to point at the proxy URL (one file), **adds one process/service** (the proxy), and must **re-segment the network** so the upstream tool service is not routable from the agent's container and only the proxy bridges the two networks (in this spike: `internal: true` network for the upstream, proxy dual-homed). The first two are configuration; the third is infrastructure. Whether an adopter can apply it "by configuration" depends on their platform: in Docker Compose / Kubernetes NetworkPolicies it is declarative config, but it is config in the *orchestrator*, not in AIL, and an adopter on a flat network, or one who cannot change network topology, cannot achieve it at all. The roadmap's "just point the client at the proxy" framing is accurate for the client edit and false for the guarantee: without the network segmentation the client edit buys mediation of a cooperating client only.

## 4. Bypass table

Every attempt from M2, the transport, the container's network position, and whether it reached the tool unmediated. All rows are backed by a command actually run (section 3).

| # | Attempt | Transport | Attacker network position | Reached tool unmediated? | Evidence |
|---|---|---|---|---|---|
| A1 | Read own client config, connect to what it names | stdio | isolated (`stdio-only`) | No | Config names only the proxy command; no upstream address exists in it |
| A2 | Enumerate network for upstream, connect | stdio | isolated | No | All hosts timeout, all loopback ports `ECONNREFUSED`; nothing listens under stdio |
| A3 | Inspect process tree + environ for upstream addr/creds | stdio | isolated | No (addr); Yes (secret readable) | Only own pid 1 visible; but `AIL_UPSTREAM_SECRET` present in agent's own env (M4) |
| A4 | Rewrite config to upstream URL, reconnect | stdio | isolated | No | `ENOTFOUND: fetch failed`, no route/DNS |
| A5 | Spawn the server binary directly | stdio | isolated | **Yes** | Binary present in agent container; self-spawned `server-everything`, `get-env` returned data |
| A5b | Self-spawn `server-filesystem` on shared volume, write | stdio | isolated | **Yes** | `write_file` succeeded to `/ledger`, a volume the proxy also uses; file confirmed present |
| A1 | Read own client config, connect to what it names | HTTP | `edge` only (segmented) | No | Config names `http://proxy:8080/mcp`, the proxy |
| A2 | Enumerate network for upstream, connect | HTTP | `edge` only | No | Only `proxy:8080` OPEN; every `upstream:*` probe timed out |
| A3 | Inspect process tree + environ for upstream addr/creds | HTTP | `edge` only | No | No secret in agent env; only own pid 1 in `/proc` |
| A4 | Rewrite config to upstream URL, reconnect | HTTP | `edge` only | No | `ENOTFOUND: fetch failed` |
| A2 | Enumerate network for upstream, connect | HTTP | `internal` (shares upstream net) | **Yes** | `upstream:3001` OPEN, unauth `initialize` returned real server capabilities |
| A4 | Rewrite config to upstream URL, reconnect | HTTP | `internal` | **Yes** | `connected DIRECT to upstream, 13 tools, get-env -> RETURNED DATA` |

Reading the table: under stdio the only unmediated path is running your own copy of the tool server (A5/A5b), never the network (A1-A4). Under HTTP the unmediated path is purely a function of network reachability: blocked from `edge`, wide open from `internal`, with the same scripts.

## 5. What could not be determined and what blocked it

- **Whether the upstream would enforce its own credential.** `server-everything` accepted an unauthenticated `initialize` (A2/A4 from `internal`), so this spike could not observe the proxy-holds-token model actually *blocking* a direct call; the network blocked it instead. What a token-enforcing upstream does under a shared-network bypass (whether the agent could replay or steal the token) was not tested because the test server has no such enforcement. The M4 credential-isolation property (agent does not hold the token under HTTP) was confirmed; the credential's *effectiveness* as a second barrier was not.
- **Asynchronous / streaming MCP paths.** Only request/response `tools/call` (and its result) was exercised for M3. Server-initiated notifications, sampling requests, elicitation, and resource-subscription updates flow through the proxy in principle but were not individually captured, so the report claims result visibility for the tool call/response path only.
- **Per-request TCP peer under HTTP.** The TCP peer was captured at session initialization (Express layer) but the SDK's per-request `requestInfo.headers` did not surface the synthetic header I injected, so per-call attribution collapses to the session id. Whether a different SDK integration point exposes the peer per call was not pursued; it does not change the M5 bound (session + address, not identity).
- **PID-namespace sharing.** A3 was run with default container isolation (separate PID namespaces), where the agent sees only its own pid 1. A deployment that shares a PID namespace, or that runs the proxy and agent in the same container, would let the agent see the proxy's and server's cmdlines and environ directly. That configuration was not tested; it can only make attribution/credential leakage worse, not better, so it does not affect the verdict.
- **Non-Docker network controls.** The HTTP segmentation was demonstrated with Docker `internal` networks. Kubernetes NetworkPolicy, service meshes, or host firewalls were not tested; the finding is that *some* enforced network segmentation is required, and that it lives in the orchestrator, not in AIL.

## 6. If GO WITH CHANGES: what the roadmap or profile definitions would have to say instead

Describing only; not making the change.

1. **Invariant 1 ("mediation is unbypassable") must be conditioned, not asserted.** The honest statement is transport-specific and dependency-specific:
   - Under stdio, mediation is unbypassable *only for tools whose entire authority is a secret or handle held exclusively by the proxy and unreachable by the agent's OS principal.* For tools acting on resources the agent can independently reach (local files, shared volumes, reachable sockets) or whose server binary the agent can execute, the agent can run its own unmediated instance (demonstrated: A5, A5b). The profile cannot claim containment of a compromised agent for such tools.
   - Under HTTP, mediation is unbypassable *only when enforced network segmentation prevents the agent's workload from routing to the upstream, and the upstream refuses connections that did not transit the proxy.* Absent that, bypass is trivial (demonstrated: A2/A4 from a shared network).
2. **The Mediated profile's guarantee should be split into "cooperating / prompt-injection defense" (which the proxy delivers on both transports by configuration alone) and "compromised-agent containment" (which requires an out-of-MCP control: OS-principal isolation for stdio, network segmentation plus upstream ingress restriction for HTTP).** The roadmap's deployability argument ("point the client at the proxy") holds for the former and does not hold for the latter.
3. **Adoption cost for real containment is more than a config change** and the roadmap should say so: stdio needs the proxy to run as a distinct OS principal owning the tool's authority; HTTP needs orchestrator-level network policy plus an upstream that authenticates the proxy. Both are deployment/infrastructure changes outside AIL's own configuration surface.
4. **Attribution claims in the Mediated and Attested profiles must be capped at what M5 found:** connection/session identity plus network address (HTTP) or spawning-process identity (stdio). The Attested profile's cryptographic attribution requires an identity layer (mTLS/SVID/signed token) that MCP does not provide and that the proxy would have to introduce and enforce itself.

## 7. Repository hygiene check

Everything new is confined to `spikes/mcp-mediation/` and this single report file, as directed. No file under `interceptor/`, `policy/`, `control_plane/`, `ledger/`, or any other existing project code was touched. The Docker image, containers, networks, and volumes created for this spike were torn down (`docker compose down -v`, `docker rmi ail-spike-mcp:latest`) and confirmed gone. `git status --short` and `git diff --stat` at commit time show only the spike directory and this report as additions. See the commit on the worktree branch for the exact file list.
