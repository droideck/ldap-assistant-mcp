"""Operability and capability-discovery tools.

Three cheap, always-safe probes of the MCP service itself:

- ``get_capabilities`` — per-server mode, privacy posture, file access,
  evidence limitations, and a tool availability matrix derived from each
  registered tool's mode tags (with the reason a tool is unavailable).
- ``service_liveness`` — process liveness only; never touches the
  connection manager, LDAP, or the filesystem.
- ``service_readiness`` — ready|degraded|not_ready with stable reason
  codes; static config validation only unless reachability is requested.

Shared helpers (``server_mode``, ``registered_tools``,
``evaluate_server_config``) are also used by the ``doctor`` and
``support-bundle`` CLI subcommands in ``ldap_assistant_mcp.main``.
"""

from __future__ import annotations

import os
import time
from typing import TYPE_CHECKING, Any, Dict, List, Optional, Tuple

from mcp.types import ToolAnnotations

from ldap_assistant_mcp.core import __version__
from ldap_assistant_mcp.dirsrv_mcp.connection import UnknownServer
from ldap_assistant_mcp.dirsrv_mcp.tools.error_utils import format_error_message
from ldap_assistant_mcp.lib.envelope import (
    CODE_CONNECTION_FAILED,
    CODE_INVALID_CONFIG,
)

if TYPE_CHECKING:
    from ldap_assistant_mcp.dirsrv_mcp.server import DirSrvMCP

# Liveness/readiness never open connections by themselves.
_RO = ToolAnnotations(
    readOnlyHint=True, idempotentHint=True, destructiveHint=False, openWorldHint=False
)
# May open LDAP connections when the caller opts into reachability checks.
_RO_OPEN = ToolAnnotations(
    readOnlyHint=True, idempotentHint=True, destructiveHint=False, openWorldHint=True
)

# Mode tags carried by every tool registration ({"live","offline","archive"}).
_MODE_TAGS = frozenset({"live", "offline", "archive"})

# Server mode -> the tag a tool must carry to work in that mode.
_MODE_TO_TAG = {
    "remote_live": "live",
    "local_live": "live",
    "offline": "offline",
    "archive": "archive",
}

# Tools that refuse to run in privacy mode (they return raw entries or
# raw log lines); mirrors the create_privacy_error() call sites.
_PRIVACY_DISABLED_TOOLS = frozenset(
    {
        "ldap_search",
        "get_user_details",
        "search_users_by_attribute",
        "parse_access_log",
        "parse_error_log",
        "parse_audit_log",
    }
)

# What each mode structurally cannot show, no matter which tool is called.
_MODE_LIMITATIONS: Dict[str, List[str]] = {
    "remote_live": [
        "no local file access: log-file analysis (analyze_*/parse_* log "
        "tools, find_unindexed_searches) is unavailable",
        "history is limited to what the live server exposes over LDAP "
        "(cn=monitor counters are cumulative since last restart)",
    ],
    "local_live": [
        "log evidence is limited to files still on disk (rotation may have "
        "removed older history)",
    ],
    "offline": [
        "no live metrics: cn=monitor, replication status, and entry "
        "queries are unavailable",
        "evidence reflects dse.ldif and log files as of the last time the "
        "instance ran",
    ],
    "archive": [
        "no live metrics: data is a static snapshot taken when the archive "
        "was collected",
        "relative time ranges anchor to the dataset end, not the current "
        "wall clock",
    ],
}


def server_mode(config: Any) -> str:
    """Classify a server config into remote_live/local_live/offline/archive.

    Same mapping as ``tools.case._server_mode`` but operating directly on a
    config object (``LDAPServerConfig`` or connection ``ServerConfig``),
    so it needs no connection manager.
    """
    if getattr(config, "is_archive", False):
        return "archive"
    if getattr(config, "is_offline", False):
        return "offline"
    if getattr(config, "is_local", False):
        return "local_live"
    return "remote_live"


def file_access_of(config: Any) -> str:
    """Return the file-access class of a server: local, archive, or none."""
    if getattr(config, "is_archive", False):
        return "archive"
    if getattr(config, "is_local", False) and getattr(config, "serverid", None):
        return "local"
    return "none"


def registered_tools(mcp: "DirSrvMCP") -> List[Any]:
    """Return the registered FastMCP Tool objects (name/tags/annotations).

    Reads the local provider's component registry.  If the FastMCP
    internals ever change shape, this returns an empty list and callers
    report the matrix as unavailable instead of guessing (a regression
    test pins the registry being populated).
    """
    try:
        from fastmcp.tools import Tool

        provider = getattr(mcp, "_local_provider", None)
        components = getattr(provider, "_components", None)
        if components:
            return [c for c in components.values() if isinstance(c, Tool)]
    except Exception:  # pragma: no cover - defensive against fastmcp changes
        pass
    return []


def evaluate_server_config(config: Any) -> Tuple[str, Optional[str], Optional[str]]:
    """Statically validate one server config without opening connections.

    Returns ``(state, code, detail)`` where state is ``"valid"`` or
    ``"invalid"``; code is a stable ``LAMCP-*`` error code when invalid.
    Checks mirror the refusals ``ConnectionManager.connect`` would raise,
    so readiness can predict them without contacting anything.
    """
    mode = server_mode(config)

    if mode == "archive":
        path = getattr(config, "archive_path", None) or getattr(
            config, "config_path", None
        )
        if not path:
            return (
                "invalid",
                CODE_INVALID_CONFIG,
                "archive mode requires archive_path or config_path",
            )
        if not os.path.exists(path):
            return ("invalid", CODE_INVALID_CONFIG, "archive path does not exist")
        return ("valid", None, None)

    if mode == "offline":
        if not getattr(config, "serverid", None):
            return (
                "invalid",
                CODE_INVALID_CONFIG,
                "offline mode requires serverid to be set",
            )
        return ("valid", None, None)

    auth = getattr(config.auth_method, "value", None) or str(config.auth_method)
    use_ldapi = getattr(config, "use_ldapi", False)
    if auth not in ("simple", "anonymous") and not use_ldapi:
        return (
            "invalid",
            CODE_INVALID_CONFIG,
            f"auth_method '{auth}' is not implemented (supported: simple, "
            "anonymous, or use_ldapi=true for SASL EXTERNAL)",
        )
    has_password = bool(
        getattr(config, "bind_password", None)
        or getattr(config, "bind_password_env", None)
        or getattr(config, "bind_password_file", None)
    )
    if auth == "simple" and not use_ldapi and not has_password:
        return (
            "invalid",
            CODE_INVALID_CONFIG,
            "simple auth is configured but no bind password source is set",
        )
    if not getattr(config, "hostname", None):
        return ("invalid", CODE_INVALID_CONFIG, "no hostname configured")
    return ("valid", None, None)


def _tool_availability(
    tool_name: str,
    tags: frozenset,
    mode: str,
    file_ok: bool,
    privacy_enabled: bool,
) -> Tuple[bool, Optional[str]]:
    """Decide whether one tool works against a server in the given mode."""
    mode_tag = _MODE_TO_TAG[mode]
    tool_modes = tags & _MODE_TAGS
    if tool_modes and mode_tag not in tool_modes:
        if mode_tag == "live":
            return (
                False,
                "requires an offline or archive server (works on dse.ldif "
                "and files, not live LDAP)",
            )
        return (False, f"requires live server (server mode is {mode})")
    if "logs" in tags and not file_ok:
        return (
            False,
            "requires local file access (log files live on the server host)",
        )
    if privacy_enabled and tool_name in _PRIVACY_DISABLED_TOOLS:
        return (
            False,
            "disabled in privacy mode (set expose_sensitive_data=true to enable)",
        )
    return (True, None)


def _probe_reachability(
    mcp: "DirSrvMCP", server_name: str
) -> Tuple[bool, Optional[str]]:
    """Try one bounded connect (LDAP_CONNECT_TIMEOUT applies) and close it."""
    ds = None
    try:
        ds = mcp.connection_manager.connect(server_name)
        return (True, None)
    except Exception as exc:
        detail = format_error_message(exc)
        if mcp.privacy_enabled:
            try:
                detail = mcp.sanitizer.sanitize_text(detail)
            except Exception:
                detail = "[redacted]"
        return (False, detail)
    finally:
        if ds is not None:
            try:
                ds.close()
            except Exception:
                pass


def register_capability_tools(mcp: "DirSrvMCP") -> None:
    """Register capability-discovery and service-probe tools."""

    registered_at = time.monotonic()

    @mcp.tool(annotations=_RO_OPEN, tags={"capabilities", "live", "offline", "archive"})
    def get_capabilities(
        server_name: Optional[str] = None,
        check_reachability: bool = False,
    ) -> Dict[str, Any]:
        """Discover what this MCP service can do for each configured server.

        Capability discovery for planning: reports every server's mode
        (remote_live, local_live, offline, or archive), privacy mode, file
        access, evidence limitations, and a per-tool availability matrix —
        for EVERY registered tool, whether it works against that server and
        the reason when it does not ("requires live server", "requires
        local file access", "disabled in privacy mode"). Call this before
        choosing tools so mode mismatches never surprise you.

        Cheap by default: no connections are opened unless
        check_reachability=true, which performs one bounded connect per
        server to report whether it is actually reachable.

        Args:
            server_name: Limit the report to one server (default: all).
            check_reachability: Also probe each server with one bounded
                connection attempt (default false — configuration only).
        """
        if server_name is not None and server_name not in mcp.server_configs:
            raise UnknownServer(server_name, available=list(mcp.server_configs))

        configs = (
            [mcp.server_configs[server_name]]
            if server_name
            else list(mcp.server_configs.values())
        )
        tools = registered_tools(mcp)
        tool_meta = [(t.name, frozenset(t.tags or ())) for t in tools]
        privacy = mcp.privacy_enabled

        servers_out: List[Dict[str, Any]] = []
        for config in configs:
            mode = server_mode(config)
            file_access = file_access_of(config)
            entry: Dict[str, Any] = {
                "name": config.name,
                "mode": mode,
                "configured": True,
                "file_access": file_access,
                "evidence_limitations": list(_MODE_LIMITATIONS[mode]),
            }
            if check_reachability:
                reachable, error = _probe_reachability(mcp, config.name)
                entry["reachable"] = reachable
                if error:
                    entry["reachability_error"] = error
            else:
                entry["reachable"] = None
                entry["reachability_note"] = (
                    "not probed (pass check_reachability=true to test connectivity)"
                )

            matrix: Dict[str, Any] = {}
            available_count = 0
            for name, tags in tool_meta:
                available, reason = _tool_availability(
                    name, tags, mode, file_access != "none", privacy
                )
                cell: Dict[str, Any] = {"available": available}
                if reason:
                    cell["reason"] = reason
                else:
                    available_count += 1
                matrix[name] = cell
            entry["tools"] = matrix
            entry["available_tool_count"] = available_count
            entry["unavailable_tool_count"] = len(tool_meta) - available_count
            servers_out.append(entry)

        result: Dict[str, Any] = {
            "type": "capabilities",
            "service": {
                "version": __version__,
                "privacy_mode": privacy,
                "tool_count": len(tool_meta),
            },
            "servers": servers_out,
        }
        if not tool_meta:
            result["note"] = (
                "tool registry inaccessible: the per-tool availability "
                "matrix could not be built"
            )
        return result

    @mcp.tool(annotations=_RO, tags={"capabilities", "health", "live", "offline", "archive"})
    def service_liveness() -> Dict[str, Any]:
        """Liveness probe for the MCP service process itself — always cheap.

        Touches NO LDAP server, NO connection manager, and NO files: if
        this responds, the service process is alive. Reports status, the
        package version, configured server count, and uptime seconds.
        Use ``service_readiness`` to check whether the service is actually
        usable, and ``first_look`` for directory server health.
        """
        return {
            "type": "service_liveness",
            "status": "alive",
            "version": __version__,
            "server_count": len(mcp.server_configs),
            "uptime_seconds": round(time.monotonic() - registered_at, 3),
        }

    @mcp.tool(annotations=_RO_OPEN, tags={"capabilities", "health", "live", "offline", "archive"})
    def service_readiness(check_reachability: bool = False) -> Dict[str, Any]:
        """Readiness probe: is this MCP service usable right now?

        Returns ready, degraded, or not_ready with stable LAMCP-* reason
        codes. Verifies that server configuration is loaded (zero servers
        is not_ready — never silently healthy), that tools are registered,
        and that each server's configuration is statically valid (auth
        method implemented, bind password source present, archive path
        exists, offline serverid set). No connection is opened unless
        check_reachability=true.

        Args:
            check_reachability: Also attempt one bounded connection per
                statically-valid server (default false).
        """
        reasons: List[Dict[str, str]] = []

        server_count = len(mcp.server_configs)
        config_loaded_ok = server_count > 0
        if not config_loaded_ok:
            reasons.append(
                {"code": CODE_INVALID_CONFIG, "detail": "no servers configured"}
            )

        tool_count = len(registered_tools(mcp))
        tools_ok = tool_count > 0
        if not tools_ok:
            reasons.append(
                {"code": CODE_INVALID_CONFIG, "detail": "no tools registered"}
            )

        server_states: List[Dict[str, Any]] = []
        degraded = False
        for config in mcp.server_configs.values():
            state, code, detail = evaluate_server_config(config)
            record: Dict[str, Any] = {
                "name": config.name,
                "mode": server_mode(config),
                "state": state,
            }
            if state != "valid":
                record["code"] = code
                record["detail"] = detail
                reasons.append(
                    {"code": code or CODE_INVALID_CONFIG, "detail": f"{config.name}: {detail}"}
                )
                degraded = True
            elif check_reachability:
                reachable, error = _probe_reachability(mcp, config.name)
                if reachable:
                    record["state"] = "reachable"
                else:
                    record["state"] = "unreachable"
                    record["code"] = CODE_CONNECTION_FAILED
                    record["detail"] = error
                    reasons.append(
                        {
                            "code": CODE_CONNECTION_FAILED,
                            "detail": f"{config.name}: unreachable",
                        }
                    )
                    degraded = True
            server_states.append(record)

        if not config_loaded_ok or not tools_ok:
            status = "not_ready"
        elif degraded:
            status = "degraded"
        else:
            status = "ready"

        return {
            "type": "service_readiness",
            "status": status,
            "reasons": reasons,
            "reachability_checked": check_reachability,
            "checks": {
                "config_loaded": {
                    "status": "ok" if config_loaded_ok else "failed",
                    "server_count": server_count,
                },
                "tools_registered": {
                    "status": "ok" if tools_ok else "failed",
                    "tool_count": tool_count,
                },
                "servers": server_states,
            },
        }


__all__ = [
    "register_capability_tools",
    "registered_tools",
    "server_mode",
    "file_access_of",
    "evaluate_server_config",
]
