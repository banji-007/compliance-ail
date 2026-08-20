"""
D14 demonstration tool: a minimal MCP stdio server holding a credential
delivered across an OS boundary.

This process is spawned by decision_service/main.py as its own child, inside
decision-service's own container - the agent never spawns it, never sees its
config, and never holds a network route to it (P2-1's network segmentation).

The one thing D14 requires of this file specifically: it reads its own
credential itself, from a mounted path, at its own startup. Nothing that
spawns this process ever passes the credential as an argument or an
environment variable - decision_service/main.py's spawn call sets no `env`
entry carrying it (see tests/test_credential_boundary_static.py, which
parses that spawn call directly). An env-var-delivered credential would
reproduce the spike's own M4 finding (docs/reports/spike-mcp-mediation.md)
and stop qualifying as "demonstrated" under D13.
"""

import os
import sys

from mcp.server.fastmcp import FastMCP

_TOKEN_PATH = os.environ.get("VAULT_TOKEN_PATH", "/run/secrets/vault_api_token")

# Fake in-memory vault for the demonstration - the point of this file is the
# credential-boundary mechanism, not a real secrets backend.
_VAULT = {
    "db_master_password": "correct-horse-battery-staple-demo-only",
    "payment_gateway_key": "pg_live_demo_key_not_real",
}


def _load_token() -> str:
    """
    Read the vault API token from the mounted secret file. Raises if the
    file is absent or unreadable - this process refuses to start in a
    state where it cannot itself authenticate, rather than starting
    tokenless and failing every call individually.
    """
    with open(_TOKEN_PATH, "r", encoding="utf-8") as f:
        token = f.read().strip()
    if not token:
        raise RuntimeError(f"vault token file at {_TOKEN_PATH} is empty")
    return token


_TOKEN = _load_token()

mcp = FastMCP("ail-vault")


@mcp.tool()
def read_vault_secret(secret_name: str) -> str:
    """Read a named secret from the vault, authenticated with this
    process's own token (never handed to it by whatever spawned it)."""
    if not _TOKEN:
        raise RuntimeError("vault token not loaded; refusing to serve any secret")
    if secret_name not in _VAULT:
        raise ValueError(f"no such secret: {secret_name}")
    return _VAULT[secret_name]


if __name__ == "__main__":
    mcp.run(transport="stdio")
