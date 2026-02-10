from __future__ import annotations

import os
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import Dict, Iterable, Optional, Tuple, Type

PROJECT_ROOT = Path(__file__).resolve().parents[1]
if str(PROJECT_ROOT) not in sys.path:
    # Allow running this module directly without installing the package.
    sys.path.insert(0, str(PROJECT_ROOT))

from src.dirsrv_mcp.server import DirSrvMCP
from src.ldap_assistant_mcp.server import LDAPAssistantMCP, LDAPServerConfig
from src.openldap_mcp.server import OpenLDAPMCP


@dataclass(frozen=True)
class ServerDefinition:
    """Metadata describing an MCP server implementation."""

    cls: Type[LDAPAssistantMCP]
    supports_config_path: bool = False
    description: str = ""


SERVER_REGISTRY: Dict[str, ServerDefinition] = {
    "dirsrv": ServerDefinition(
        cls=DirSrvMCP,
        supports_config_path=True,
        description="389 Directory Server",
    ),
    "openldap": ServerDefinition(
        cls=OpenLDAPMCP,
        supports_config_path=False,
        description="OpenLDAP Server",
    ),
}

DEFAULT_PROVIDER = "dirsrv"
PROVIDER_ENV_VAR = "LDAP_PROVIDER"


def create_server(
    *,
    provider: Optional[str] = None,
    config_path: Optional[str] = None,
    servers: Optional[Iterable[LDAPServerConfig]] = None,
    include_env_fallback: bool = True,
    **kwargs,
) -> LDAPAssistantMCP:
    """
    Build an MCP server using registry metadata.

    This helper is the canonical entry point for fastmcp.json.
    """

    _, definition = _resolve_provider(provider)
    init_kwargs = dict(kwargs)

    if servers:
        init_kwargs["servers"] = list(servers)

    if definition.supports_config_path:
        resolved_config_path = (
            config_path if config_path is not None else os.environ.get("LDAP_SERVERS_CONFIG")
        )
        init_kwargs["config_path"] = resolved_config_path

    init_kwargs.setdefault("include_env_fallback", include_env_fallback)

    return definition.cls(**init_kwargs)  # type: ignore[call-arg]


def _resolve_provider(
    provider: Optional[str],
) -> Tuple[str, ServerDefinition]:
    """Resolve provider name to its registry definition.

    Falls back to LDAP_PROVIDER env var, then DEFAULT_PROVIDER.
    """
    requested = (provider or os.environ.get(PROVIDER_ENV_VAR) or DEFAULT_PROVIDER).lower()
    definition = SERVER_REGISTRY.get(requested)
    if not definition:
        valid = ", ".join(sorted(SERVER_REGISTRY))
        raise ValueError(f"Unknown LDAP MCP provider '{requested}'. Valid options: {valid}.")
    return requested, definition


def main() -> None:
    """Simple entry point for `python -m src.main` (uses defaults/env)."""

    server = create_server()
    server.run()


if __name__ == "__main__":
    main()

