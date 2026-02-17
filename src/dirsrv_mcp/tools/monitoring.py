"""Monitoring tools for 389 Directory Server."""

from __future__ import annotations

import json
from typing import TYPE_CHECKING, Any, Dict, Optional

from fastmcp.exceptions import ToolError
from lib389.backend import Backends
from lib389.monitor import Monitor

from src.dirsrv_mcp.connection import require_live_server

if TYPE_CHECKING:
    from src.dirsrv_mcp.server import DirSrvMCP

# Monitor attributes safe to expose in privacy mode (numeric/diagnostic only)
SAFE_MONITOR_KEYS = {
    "currentconnections", "totalconnections", "threads",
    "currentconnectionsatmaxthreads", "maxthreadsperconnhits",
    "dtablesize", "readwaiters", "opsinitiated", "opscompleted",
    "entriessent", "bytessent", "nbackends", "version", "starttime",
    "currenttime", "connection", "backendmonitordn",
    # DB cache metrics
    "dbcachehits", "dbcachetries", "dbcachehitratio",
    "dbcachepagein", "dbcachepageout", "dbcacheroevict", "dbcacherwevict",
    # Entry/DN cache metrics
    "entrycachehits", "entrycachetries", "entrycachehitratio",
    "currententrycachesize", "maxentrycachesize",
    "currententrycachecount", "maxentrycachecount",
    "dncachehits", "dncachetries", "dncachehitratio",
    "currentdncachesize", "maxdncachesize",
    "currentdncachecount", "maxdncachecount",
    # Normalized DN cache
    "normalizeddncachehits", "normalizeddncachetries",
    "normalizeddncachehitratio", "normalizeddncachemisses",
    "normalizeddncacheevictions", "currentnormalizeddncachesize",
    "maxnormalizeddncachesize", "currentnormalizeddncachecount",
    # SNMP/operation counters
    "anonymousbinds", "unauthbinds", "simpleauthbinds", "strongauthbinds",
    "bindsecurityerrors", "inops", "readops", "compareops",
    "addentryops", "removeentryops", "modifyentryops", "modifyrdnops",
    "searchops", "onelevelsearchops", "wholesubtreesearchops",
    "referrals", "securityerrors", "errors", "bytesrecv",
    "entriesreturned", "referralsreturned",
}


def _sanitize_monitor_result(mcp: "DirSrvMCP", result: Dict[str, Any]) -> Dict[str, Any]:
    """Sanitize monitor result for privacy mode."""
    if not mcp.privacy_enabled:
        return result

    sanitizer = mcp.sanitizer
    sanitized = dict(result)

    # Sanitize server name
    original_server = sanitized.get("server")
    if "server" in sanitized:
        sanitized["server"] = sanitizer.sanitize_server_name(sanitized["server"])
    if "error" in sanitized and isinstance(sanitized["error"], str):
        err = sanitized["error"]
        if original_server and original_server in err:
            err = err.replace(original_server, sanitized.get("server", "[server]"))
        sanitized["error"] = sanitizer._sanitize_text_field(err)

    # Sanitize backend name
    if "backend" in sanitized and sanitized["backend"] != "main":
        sanitized["backend"] = "[backend]"

    # Sanitize suffix in parameters
    if "suffix" in sanitized:
        sanitized["suffix"] = sanitizer.sanitize_suffix(sanitized["suffix"])

    # Filter monitor item to safe keys only
    if "item" in sanitized and isinstance(sanitized["item"], dict):
        filtered = {}
        for k, v in sanitized["item"].items():
            if k.lower() in SAFE_MONITOR_KEYS:
                filtered[k] = v
        filtered["_privacy_note"] = "Filtered to safe diagnostic keys only"
        sanitized["item"] = filtered

    return sanitized


def register_monitoring_tools(mcp: DirSrvMCP) -> None:
    """Register monitoring tools with the MCP server."""

    @mcp.tool()
    def run_monitor(
        backend: str = "", suffix: str = "", server_name: Optional[str] = None
    ) -> Dict[str, Any]:
        """Return raw cn=monitor attributes for a server or specific backend.

        Use this tool when you need low-level monitor counters not covered
        by the higher-level performance tools.  For most diagnostic work,
        prefer ``get_performance_summary`` or the specific ``get_cache_statistics``
        / ``get_connection_statistics`` / ``get_operation_statistics`` tools
        which provide interpreted results with health assessments.

        Requires a live LDAP connection.

        Args:
            backend: Specific backend name (e.g., 'userroot') to monitor.
            suffix: Alternative to backend — specify the suffix instead.
            server_name: Target server name. Uses default if not specified.

        Returns:
            All monitor attributes as key-value pairs.  In privacy mode,
            only safe diagnostic/numeric keys are included.
        """
        target = server_name or mcp.default_server
        require_live_server(mcp.connection_manager, target, "run_monitor")
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

