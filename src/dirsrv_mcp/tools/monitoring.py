"""Monitoring tools for 389 Directory Server."""

from __future__ import annotations

import json
from typing import TYPE_CHECKING, Any, Dict, Optional

from fastmcp.exceptions import ToolError
from lib389.backend import Backends
from lib389.monitor import Monitor

if TYPE_CHECKING:
    from src.dirsrv_mcp.server import DirSrvMCP


def _sanitize_monitor_result(mcp: "DirSrvMCP", result: Dict[str, Any]) -> Dict[str, Any]:
    """Sanitize monitor result for privacy mode."""
    if not mcp.privacy_enabled:
        return result

    sanitizer = mcp.sanitizer
    sanitized = dict(result)

    # Sanitize server name
    if "server" in sanitized:
        sanitized["server"] = sanitizer.sanitize_server_name(sanitized["server"])

    # Sanitize backend name
    if "backend" in sanitized and sanitized["backend"] != "main":
        sanitized["backend"] = "[backend]"

    # Sanitize suffix in parameters
    if "suffix" in sanitized:
        sanitized["suffix"] = sanitizer.sanitize_suffix(sanitized["suffix"])

    return sanitized


def register_monitoring_tools(mcp: DirSrvMCP) -> None:
    """Register monitoring tools with the MCP server."""

    @mcp.tool()
    def run_monitor(
        backend: str = "", suffix: str = "", server_name: Optional[str] = None
    ) -> Dict[str, Any]:
        """Return server or backend monitor information."""
        target = server_name or mcp.default_server
        with mcp._connection(target) as (srv, ds):
            try:
                if backend or suffix:
                    bes = Backends(ds)
                    be = bes.get(backend or suffix)
                    monitor = be.get_monitor()
                else:
                    monitor = Monitor(ds)
                data_json = monitor.get_all_attrs_json()
                result = json.loads(data_json)
                return _sanitize_monitor_result(mcp, {
                    "type": "monitor",
                    "server": srv,
                    "backend": backend or suffix or "main",
                    "item": result,
                })
            except Exception as exc:
                display_name = (
                    mcp.sanitizer.sanitize_server_name(srv)
                    if mcp.privacy_enabled else srv
                )
                mcp.logger.error("Error accessing monitor on %s: %s", display_name, exc)
                raise ToolError(f"Error accessing monitor on {display_name}: {exc}") from exc

