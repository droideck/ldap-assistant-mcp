"""Server discovery tools for 389 Directory Server."""

from __future__ import annotations

from typing import TYPE_CHECKING, Any, Dict

from mcp.types import ToolAnnotations

if TYPE_CHECKING:
    from ldap_assistant_mcp.dirsrv_mcp.server import DirSrvMCP

_RO = ToolAnnotations(readOnlyHint=True, idempotentHint=True, destructiveHint=False, openWorldHint=False)


def register_server_tools(mcp: "DirSrvMCP") -> None:
    """Register server discovery tools."""

    @mcp.tool(annotations=_RO, tags={"servers", "live", "offline", "archive"})
    def list_servers() -> Dict[str, Any]:
        """List all configured servers with their connection modes.

        Returns each server's name, mode (live/offline/archive), and
        key properties.  Use this to discover which server name to pass
        to other tools — especially archive and offline tools that
        require a non-live server.

        Returns:
            Dictionary with server count and per-server details including
            name, mode, provider_type, and connection info.
        """
        servers = mcp.describe_servers()
        return {
            "type": "server_list",
            "server_count": len(servers),
            "servers": servers,
        }
