"""Monitoring tools for 389 Directory Server."""

from __future__ import annotations

import json
from typing import TYPE_CHECKING, Any, Dict, Optional

from fastmcp.exceptions import ToolError
from lib389.backend import Backends
from lib389.monitor import Monitor

from mcp.types import ToolAnnotations



if TYPE_CHECKING:
    from src.dirsrv_mcp.server import DirSrvMCP

_RO = ToolAnnotations(readOnlyHint=True, idempotentHint=True, destructiveHint=False, openWorldHint=True)

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

    # Server names are never sanitized (user-chosen config labels).
    if "error" in sanitized and isinstance(sanitized["error"], str):
        sanitized["error"] = sanitizer.sanitize_text(sanitized["error"])

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

    @mcp.tool(annotations=_RO, tags={"monitoring", "live"})
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
        mcp.require_live(target,"run_monitor")
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
                mcp.logger.error("Error accessing monitor on %s: %s", srv, exc)
                raise ToolError(f"Error accessing monitor on {srv}: {exc}") from exc

