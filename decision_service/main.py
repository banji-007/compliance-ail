"""
AIL Decision Service — FastAPI
===============================
Phase 2, D12: everything that used to run inside the agent's own process
(schema validation, OPA policy evaluation, the ledger write, and - for the
one D14 tool - the actual mediated execution) now runs here instead. The
agent sends a tool call to POST /decide and gets back a verdict; it holds no
verifier credential, no ledger path, and no OPA management reach. This
service is the only thing on the network that does.

D12's own stated limit, unchanged by this file: moving the decision here
does not stop an agent from sending one tool call for evaluation and then
executing a *different* one on its own, for any tool whose authority the
agent independently holds (the three "observed" tools below). Only D14's
per-tool authority exclusivity closes that gap, and only for the one tool
that has it.
"""

import base64
import errno
import hashlib
import json
import logging
import os
import sys
import uuid
from typing import Any
from contextlib import asynccontextmanager
from datetime import datetime

import httpx
from fastapi import FastAPI
from mcp import ClientSession, StdioServerParameters
from mcp.client.stdio import stdio_client
from prometheus_client import Counter, start_http_server, REGISTRY
from pydantic import BaseModel

# ledger/ is copied to ./ledger inside this service's own Docker image
# (decision_service/Dockerfile) - that path is what resolves in production.
# When pytest imports this module directly from a repo checkout to test it
# in-process (tests/test_outcome_types.py and others), ./ledger doesn't
# exist; ../ledger (the repo's actual ledger/ directory) does. Both
# candidates are added, harmlessly, so the same module works unmodified in
# either context - only whichever path actually exists is real, and Python
# import resolution just skips a candidate with nothing to find.
for _ledger_candidate in (
    os.path.join(os.path.dirname(__file__), "ledger"),
    os.path.join(os.path.dirname(__file__), "..", "ledger"),
):
    if os.path.isdir(_ledger_candidate):
        sys.path.append(_ledger_candidate)

from schemas import TOOL_REGISTRY, resolve_exclusivity, mark_mechanism_verified  # noqa: E402

logging.basicConfig(level=logging.INFO, format="%(asctime)s - %(levelname)s - %(message)s")

_OPA_URL = os.getenv("OPA_URL", "http://opa:8181/v1/data/ail/main/evaluation")
_BUNDLE_NAME = os.getenv("AIL_BUNDLE_NAME", "ail-policies")

# --- Closed sets, unchanged from Phase 1 (ADR-0005) ---
OUTCOME_POLICY_ALLOW = "policy_allow"
OUTCOME_POLICY_DENY = "policy_deny"
OUTCOME_SCHEMA_DENY = "schema_deny"
OUTCOME_FAULT = "fault"

FAULT_OPA_UNREACHABLE = "opa_unreachable"
FAULT_REVISION_UNAVAILABLE = "revision_unavailable"
FAULT_VERIFIER_UNREACHABLE = "verifier_unreachable"
FAULT_MALFORMED_POLICY_RESPONSE = "malformed_policy_response"
FAULT_CONTENT_STORE_UNREACHABLE = "content_store_unreachable"
FAULT_TOOL_EXECUTION_FAILED = "tool_execution_failed"

CONTENT_PRESENT = "present"
CONTENT_UNAVAILABLE = "unavailable"

_VAULT_SERVER_PATH = os.path.join(os.path.dirname(__file__), "mcp_tools", "vault_server.py")
_VAULT_TOKEN_PATH = os.environ.get("VAULT_TOKEN_PATH", "/run/secrets/vault_api_token")


def _verify_mcp_stdio_secret_mount() -> bool:
    """
    The one startup check backing the one entry in schemas._VERIFIABLE_MECHANISMS.
    Confirms the secret this gateway is about to hand exclusively to
    vault_server.py actually arrived via a genuine Docker secrets mount
    ("a secrets store the proxy's principal can reach and the agent's
    cannot", D14's third named mechanism) - not an ordinary bind mount or a
    file baked into the image, either of which a compromised agent's own
    build process could replicate.

    Deliberately does NOT check raw permission bits (mode 0400 and so on).
    Two things independently rule that out as a portable check: plain
    (non-Swarm) `docker compose` does not honor a secret's `mode:`/`uid:`/
    `gid:` fields at all (confirmed live: Compose prints "secrets `uid`,
    `gid` and `mode` are not supported, they will be ignored"), and this
    process cannot even chmod its way around that - a genuine Docker
    secrets mount is read-only to the container itself, confirmed live
    (`os.open(..., "a")` on the mounted path raises EROFS even as root).
    That read-only-to-root behavior is what this function actually tests:
    it is a property of the real secrets mechanism, not of host-filesystem
    permission-bit translation this gateway does not control. A file under
    /run/secrets/ that is writable is not a genuine secrets mount and does
    not verify. A missing file, an empty one, or a path outside
    /run/secrets/ also does not verify - resolve_exclusivity_for then
    records "declared" for read_vault_secret regardless of its config's
    claim - see schemas.py.
    """
    if not _VAULT_TOKEN_PATH.startswith("/run/secrets/"):
        logging.error(
            "mcp_stdio_secret_mount verification failed: %s is not under "
            "/run/secrets/ - not delivered via the Docker secrets convention",
            _VAULT_TOKEN_PATH,
        )
        return False
    try:
        with open(_VAULT_TOKEN_PATH, "r", encoding="utf-8") as f:
            content = f.read()
    except OSError as exc:
        logging.error("mcp_stdio_secret_mount verification failed: %s", exc)
        return False
    if not content.strip():
        logging.error("mcp_stdio_secret_mount verification failed: %s is empty", _VAULT_TOKEN_PATH)
        return False
    try:
        with open(_VAULT_TOKEN_PATH, "a", encoding="utf-8"):
            pass
    except OSError as exc:
        if exc.errno == errno.EROFS:
            return True
        logging.error(
            "mcp_stdio_secret_mount verification failed: unexpected error probing "
            "write-protection on %s: %s", _VAULT_TOKEN_PATH, exc,
        )
        return False
    logging.error(
        "mcp_stdio_secret_mount verification failed: %s is writable from this "
        "container - not delivered as a read-only Docker secret",
        _VAULT_TOKEN_PATH,
    )
    return False


def _fetch_opa_bundle_revision() -> str | None:
    url = _OPA_URL.replace(
        "/v1/data/ail/main/evaluation", f"/v1/data/system/bundles/{_BUNDLE_NAME}/manifest/revision"
    )
    try:
        with httpx.Client() as client:
            response = client.get(url, timeout=5)
        if response.status_code != 200:
            return None
        revision = response.json().get("result")
        return revision if isinstance(revision, str) and revision else None
    except Exception as e:
        logging.error("OPA bundle revision query failed: %s", e)
        return None


def _verify_bundle_loaded_at_startup(timeout_seconds: float = 30, poll_interval: float = 2) -> bool:
    """
    D12 (Phase 2): moved here from interceptor/middleware.py's old
    verify_bundle_at_startup - checking that the configured OPA bundle name
    actually resolves to a loaded bundle is now this service's concern, not
    the agent's (the agent has no route to OPA to check it directly any
    more). Polls because OPA's bundle plugin loads asynchronously after the
    container reports healthy (docs/reports/phase-0-redteam.md, C4).
    """
    import time as _time
    deadline = _time.monotonic() + timeout_seconds
    revision = None
    while _time.monotonic() < deadline:
        revision = _fetch_opa_bundle_revision()
        if revision:
            break
        _time.sleep(poll_interval)
    if not revision:
        logging.error(
            "STARTUP: bundle '%s' has no revision on OPA after %ss - opa-config.yaml's "
            "bundles: key and AIL_BUNDLE_NAME may not name the same bundle.",
            _BUNDLE_NAME, timeout_seconds,
        )
        return False
    logging.info("Startup check: OPA bundle '%s' loaded, revision=%s", _BUNDLE_NAME, revision)
    return True


@asynccontextmanager
async def lifespan(app: FastAPI):
    verified = _verify_mcp_stdio_secret_mount()
    mark_mechanism_verified("mcp_stdio_secret_mount", verified)
    logging.info("Startup check: mcp_stdio_secret_mount verified=%s", verified)
    # Raising here (rather than logging and continuing) stops uvicorn from
    # ever starting the ASGI app - the same severity as the old agent-side
    # sys.exit(1), just expressed through this process's own lifecycle
    # instead. The Docker healthcheck then never passes, and everything
    # depends_on: decision-service: condition: service_healthy stays down.
    if not _verify_bundle_loaded_at_startup():
        raise RuntimeError(
            f"OPA bundle '{_BUNDLE_NAME}' not loaded at startup - refusing to serve."
        )
    yield


app = FastAPI(title="AIL Decision Service", version="1.0.0", lifespan=lifespan)

try:
    _POLICY_DECISIONS = Counter(
        "ail_policy_decisions_total",
        "Total AIL policy decisions by status, outcome_type, fault_class, and tool",
        ["status", "outcome_type", "fault_class", "tool_name"],
    )
except ValueError:
    _POLICY_DECISIONS = REGISTRY._names_to_collectors["ail_policy_decisions_total"]

try:
    start_http_server(8000)
    logging.info("Prometheus metrics server started on 0.0.0.0:8000")
except OSError:
    pass


class DecideRequest(BaseModel):
    tool_name: str
    # P11-2 (Phase 1.1): deliberately NOT typed `dict`. An LLM can emit a
    # list/string/null/number for tool arguments - valid JSON that isn't a
    # dict - and query_opa_policy's own isinstance check is what classifies
    # that as schema_deny. Typing this field `dict` would make Pydantic
    # reject the request before that classification ever runs, turning a
    # deliberate schema_deny outcome into a generic 422 the agent's client
    # leg could only read as decision_service_unreachable - the wrong
    # outcome_type entirely.
    tool_args: Any
    agent_id: str = "base_agent"


def _outcome(outcome_type, fault_class=None, policy_revision=None, reasons=None):
    return {
        "outcome_type": outcome_type,
        "fault_class": fault_class,
        "policy_revision": policy_revision,
        "reasons": reasons or [],
    }


_SENSITIVE_KEYS = frozenset({"query", "approval_ticket", "commit_hash", "tags"})


def _redact_args(args) -> dict:
    if not isinstance(args, dict):
        return {"_shape": type(args).__name__}
    redacted = {}
    for k, v in args.items():
        if k in _SENSITIVE_KEYS:
            redacted[k] = "[REDACTED]"
        elif isinstance(v, dict):
            redacted[k] = _redact_args(v)
        else:
            redacted[k] = v
    return redacted


def query_opa_policy(tool_name: str, tool_args) -> dict:
    """
    Schema validation (Stage 2) then OPA evaluation (Stage 3). Unchanged in
    substance from Phase 1's interceptor/middleware.py, minus the SPIFFE
    mTLS handshake - that hop protected the agent-to-Envoy-to-OPA leg, which
    no longer exists (the agent no longer talks to OPA at all, D12). This
    service reaches OPA over the internal network directly, the same trust
    level control_plane's own OPA/bundle calls already use.
    """
    if not isinstance(tool_args, dict):
        msg = f"tool_args must be a JSON object; got {type(tool_args).__name__}."
        logging.warning("Pre-flight validation blocked malformed tool_args shape for %s: %s", tool_name, type(tool_args).__name__)
        return _outcome(OUTCOME_SCHEMA_DENY, reasons=[msg])

    reg = TOOL_REGISTRY.get(tool_name)
    if reg is None:
        msg = f"No registered schema for tool '{tool_name}'."
        logging.warning("Pre-flight validation blocked unregistered tool: %s", tool_name)
        return _outcome(OUTCOME_SCHEMA_DENY, reasons=[msg])
    is_valid, error_message = reg.validator(tool_args)
    if not is_valid:
        logging.warning("Pre-flight validation failed for %s: %s", tool_name, error_message)
        return _outcome(OUTCOME_SCHEMA_DENY, reasons=[error_message])

    try:
        with httpx.Client() as client:
            response = client.post(
                _OPA_URL,
                json={"input": {"tool_name": tool_name, "tool_args": tool_args}},
                timeout=5,
            )
    except httpx.RequestError as e:
        logging.error("OPA request error: %s", e)
        return _outcome(OUTCOME_FAULT, fault_class=FAULT_OPA_UNREACHABLE)

    if response.status_code != 200:
        logging.error("OPA /evaluation returned HTTP %d. Fail-closed policy enforced.", response.status_code)
        return _outcome(OUTCOME_FAULT, fault_class=FAULT_OPA_UNREACHABLE)

    result = response.json().get("result")
    if result is None:
        logging.error("OPA answered /evaluation but the result was undefined.")
        return _outcome(OUTCOME_FAULT, fault_class=FAULT_REVISION_UNAVAILABLE)

    allow = result.get("allow")
    reasons = result.get("reasons")
    revision = result.get("revision")
    if not isinstance(allow, bool) or not isinstance(reasons, list) or not isinstance(revision, str) or not revision:
        logging.error(
            "OPA /evaluation response missing or malformed field(s) - allow=%r reasons=%r revision=%r",
            allow, reasons, revision,
        )
        return _outcome(OUTCOME_FAULT, fault_class=FAULT_MALFORMED_POLICY_RESPONSE)

    if allow is True:
        return _outcome(OUTCOME_POLICY_ALLOW, policy_revision=revision)
    return _outcome(OUTCOME_POLICY_DENY, policy_revision=revision, reasons=list(reasons))


async def _execute_vault_tool(tool_args: dict) -> str:
    """
    The one tool this gateway executes on the agent's behalf, rather than
    just deciding on. Spawns vault_server.py fresh as this process's own
    child - note the absence of an `env=` argument here: the token never
    passes through this call. vault_server.py reads it itself, from the
    same mounted secret file this container (and only this container) has.
    """
    server_params = StdioServerParameters(
        command=sys.executable,
        args=[_VAULT_SERVER_PATH],
    )
    async with stdio_client(server_params) as (read, write):
        async with ClientSession(read, write) as session:
            await session.initialize()
            result = await session.call_tool("read_vault_secret", tool_args)
            if result.isError:
                text = result.content[0].text if result.content else "vault tool error"
                raise RuntimeError(text)
            return result.content[0].text


_DENIED_PREFIX = "DENIED: "


def _strip_denied_prefix(reason: str) -> str:
    return reason[len(_DENIED_PREFIX):] if reason.startswith(_DENIED_PREFIX) else reason


def _render_message(outcome_type, fault_class, reasons):
    if outcome_type == OUTCOME_POLICY_ALLOW:
        return "Action approved by policy"
    if outcome_type == OUTCOME_POLICY_DENY:
        normalized = [_strip_denied_prefix(r) for r in reasons]
        return _DENIED_PREFIX + ("; ".join(normalized) if normalized else "Action did not pass policy evaluation.")
    if outcome_type == OUTCOME_SCHEMA_DENY:
        return _DENIED_PREFIX + "Schema Validation Failed. " + "; ".join(reasons)
    return f"{_DENIED_PREFIX}Compliance engine fault ({fault_class}). Fail-closed policy enforced."


def _canonical_hash(tool_args) -> str:
    canonical = json.dumps(tool_args, sort_keys=True, separators=(",", ":"))
    return hashlib.sha256(canonical.encode()).hexdigest()


@app.get("/health")
def health():
    return {"status": "ok"}


@app.post("/decide")
async def decide(req: DecideRequest):
    """
    The one route the agent calls. Response shape is exactly what
    interceptor/middleware.py::intercept_tool_call returned before Phase 2
    (status, message, outcome_type, fault_class, policy_revision,
    ledger_tx_id?) so the agent's client shim can pass it straight through
    unchanged - plus an optional `result` key, present only for the one
    tool this service executes itself (read_vault_secret on approval),
    since the agent has no other way to obtain it.
    """
    tool_name = req.tool_name
    tool_args = req.tool_args
    agent_id = req.agent_id

    logging.info("Decide request: %s | args=%s", tool_name, json.dumps(_redact_args(tool_args)))

    outcome = query_opa_policy(tool_name, tool_args)
    outcome_type = outcome["outcome_type"]
    fault_class = outcome["fault_class"]
    policy_revision = outcome["policy_revision"]
    reasons = outcome["reasons"]

    input_sha256 = _canonical_hash(tool_args)
    call_id = uuid.uuid4().hex

    if isinstance(tool_args, dict):
        try:
            from content_store import store_content
            store_content(call_id, tool_args)
            content_state = CONTENT_PRESENT
        except Exception as e:
            logging.error("Content store write failed for call_id=%s: %s", call_id, e)
            outcome_type = OUTCOME_FAULT
            fault_class = FAULT_CONTENT_STORE_UNREACHABLE
            policy_revision = None
            reasons = []
            content_state = None
    else:
        content_state = CONTENT_UNAVAILABLE

    result_payload = None
    if outcome_type == OUTCOME_POLICY_ALLOW and tool_name == "read_vault_secret" and content_state is not None:
        try:
            result_payload = await _execute_vault_tool(tool_args)
        except Exception as e:
            logging.error("Mediated tool execution failed for call_id=%s: %s", call_id, e)
            outcome_type = OUTCOME_FAULT
            fault_class = FAULT_TOOL_EXECUTION_FAILED
            policy_revision = None
            reasons = []

    # "unknown" (R3, Phase 1.3) is reserved for the read-time fallback a
    # structurally profile-less (forged) record gets in
    # control_plane/main.py::get_audit - not for a genuine record this
    # service itself writes. An unregistered tool_name (schema_deny, no
    # TOOL_REGISTRY entry) still gets a real, gateway-produced record, so it
    # defaults to "observed" here, same as every other non-mediated case.
    reg = TOOL_REGISTRY.get(tool_name)
    profile = reg.profile if reg else "observed"
    exclusivity = resolve_exclusivity(tool_name)

    ledger_tx_id = None
    if content_state is not None:
        try:
            from immudb_ledger import get_ledger
            ledger = get_ledger()
            ledger_tx_id = ledger.log_tool_call(
                agent_id=agent_id,
                tool_name=tool_name,
                call_id=call_id,
                input_sha256=input_sha256,
                outcome_type=outcome_type,
                fault_class=fault_class,
                policy_revision=policy_revision,
                reasons=reasons,
                content_state=content_state,
                profile=profile,
                exclusivity=exclusivity,
            )
            logging.info("Ledger tx_id: %s", ledger_tx_id)
        except Exception as e:
            logging.error("ImmuDB ledger unavailable: %s", e)
            outcome_type = OUTCOME_FAULT
            fault_class = FAULT_VERIFIER_UNREACHABLE
            policy_revision = None
            reasons = []
            result_payload = None

    metric_tool_name = tool_name if tool_name in TOOL_REGISTRY else "_unregistered"
    status = "APPROVED" if outcome_type == OUTCOME_POLICY_ALLOW else "DENIED"
    _POLICY_DECISIONS.labels(
        status=status,
        outcome_type=outcome_type,
        fault_class=fault_class or "",
        tool_name=metric_tool_name,
    ).inc()

    message = _render_message(outcome_type, fault_class, reasons)
    logging.info("Decision: %s: %s", status, message)

    response = {
        "status": status,
        "message": message,
        "outcome_type": outcome_type,
        "fault_class": fault_class,
        "policy_revision": policy_revision,
    }
    if ledger_tx_id is not None:
        response["ledger_tx_id"] = ledger_tx_id
    if result_payload is not None:
        response["result"] = result_payload

    return response
