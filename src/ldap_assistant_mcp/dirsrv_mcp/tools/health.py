"""Health check tools for 389 Directory Server."""

from __future__ import annotations

import copy
import logging
import re
from datetime import datetime, timezone
from typing import TYPE_CHECKING, Any, Dict, List, Optional

from lib389 import lint
from lib389.backend import Backends
from lib389.config import RSA, Config, Encryption
from lib389.dirsrv_log import DirsrvAccessLog
from lib389.dseldif import DSEldif, FSChecks
from lib389.monitor import Monitor, MonitorDiskSpace
from lib389.nss_ssl import NssSsl
from lib389.plugins import MemberOfPlugin, ReferentialIntegrityPlugin
from lib389.replica import Replica, Replicas
from lib389.tunables import Tunables

from fastmcp.exceptions import ToolError
from mcp.types import ToolAnnotations

from ldap_assistant_mcp.dirsrv_mcp.connection import is_archive_server, is_local_server, is_offline_or_archive
from ldap_assistant_mcp.dirsrv_mcp.tools.dse_utils import find_child_dns, get_dse_ldif_path
from ldap_assistant_mcp.dirsrv_mcp.tools.error_utils import format_error_message, format_tool_error
from ldap_assistant_mcp.lib.disk_utils import parse_dsdisk_entry
from ldap_assistant_mcp.lib.result_formatter import Severity, format_finding
from ldap_assistant_mcp.lib.value_utils import safe_float, safe_int

if TYPE_CHECKING:
    from ldap_assistant_mcp.dirsrv_mcp.connection import ServerConfig
    from ldap_assistant_mcp.dirsrv_mcp.server import DirSrvMCP

_RO = ToolAnnotations(readOnlyHint=True, idempotentHint=True, destructiveHint=False, openWorldHint=True)
_RO_LOCAL = ToolAnnotations(readOnlyHint=True, idempotentHint=True, destructiveHint=False, openWorldHint=False)

_health_logger = logging.getLogger(__name__)


def _sanitize_health_result(mcp: "DirSrvMCP", result: Dict[str, Any]) -> Dict[str, Any]:
    """Sanitize health check result for privacy mode."""
    if not mcp.privacy_enabled:
        return result

    sanitizer = mcp.sanitizer
    sanitized = dict(result)

    # Server names are never sanitized (user-chosen config labels).
    if "error" in sanitized and isinstance(sanitized["error"], str):
        sanitized["error"] = sanitizer.sanitize_text(sanitized["error"])

    # Failure-path summaries embed the raw exception text (e.g. run_healthcheck
    # "FAILED: ... - <message>"), which can carry hostnames/DNs/paths.
    if "summary" in sanitized and isinstance(sanitized["summary"], str):
        sanitized["summary"] = sanitizer.sanitize_text(sanitized["summary"])

    if "findings" in sanitized and isinstance(sanitized["findings"], list):
        sanitized["findings"] = sanitizer.sanitize_findings(sanitized["findings"])

    if "metrics" in sanitized and isinstance(sanitized["metrics"], dict):
        sanitized["metrics"] = _sanitize_metrics(sanitizer, sanitized["metrics"])

    if "detailed_metrics" in sanitized and isinstance(sanitized["detailed_metrics"], dict):
        sanitized["detailed_metrics"] = _sanitize_metrics(sanitizer, sanitized["detailed_metrics"])

    for key in ("evidence_gaps", "checks_failed", "discovery_errors"):
        if key in sanitized and isinstance(sanitized[key], list):
            sanitized[key] = [
                {**item, "error": sanitizer.sanitize_text(item["error"])}
                if isinstance(item, dict) and isinstance(item.get("error"), str)
                else item
                for item in sanitized[key]
            ]

    return sanitized


def _sanitize_metrics(sanitizer, metrics: Dict[str, Any]) -> Dict[str, Any]:
    """Sanitize metrics dictionary (server names kept as-is)."""
    result = {}
    for server_name, server_data in metrics.items():
        if isinstance(server_data, dict):
            result[server_name] = _sanitize_server_metrics(sanitizer, server_data)
        else:
            result[server_name] = server_data
    return result


def _sanitize_server_metrics(sanitizer, data: Dict[str, Any]) -> Dict[str, Any]:
    """Sanitize server-level metrics."""
    result = {}
    for key, value in data.items():
        if key == "server":
            result[key] = value  # Server names are never sanitized
        elif key == "replication" and isinstance(value, dict):
            result[key] = _sanitize_replication_metrics(sanitizer, value)
        elif key == "cache" and isinstance(value, dict):
            result[key] = _sanitize_cache_metrics(sanitizer, value)
        elif key == "disk" and isinstance(value, dict):
            result[key] = _sanitize_disk_metrics(sanitizer, value)
        elif key == "certificates" and isinstance(value, dict):
            result[key] = _sanitize_cert_metrics(value, sanitizer)
        elif key in ("connections", "threads", "operations") and isinstance(value, dict):
            section = dict(value)
            if isinstance(section.get("error"), str):
                section["error"] = sanitizer.sanitize_text(section["error"])
            result[key] = section
        elif key == "suffixes" and isinstance(value, list):
            result[key] = [sanitizer.sanitize_suffix(s) for s in value]
        elif key in ("port", "secure_port"):
            result[key] = "[port]"
        elif key in ("error", "dse_error", "dse_lint_error", "fs_lint_error") and isinstance(value, str):
            result[key] = sanitizer.sanitize_text(value)
        elif key in ("dse_lint_errors", "fs_lint_errors") and isinstance(value, list):
            result[key] = [sanitizer.sanitize_text(str(v)) for v in value]
        else:
            # Keep numeric metrics and status flags
            result[key] = value
    return result


def _sanitize_replication_metrics(sanitizer, repl: Dict[str, Any]) -> Dict[str, Any]:
    """Sanitize replication metrics."""
    result = dict(repl)
    if "error" in result and isinstance(result["error"], str):
        result["error"] = sanitizer.sanitize_text(result["error"])
    if "errors" in result and isinstance(result["errors"], list):
        result["errors"] = [sanitizer.sanitize_text(str(e)) for e in result["errors"]]
    if "agreements" in result and isinstance(result["agreements"], list):
        result["agreements"] = [
            {
                "name": "[agreement]",
                "consumer": sanitizer.sanitize_hostname(a.get("consumer")),
                "suffix": sanitizer.sanitize_suffix(a.get("suffix")),
            }
            for a in result["agreements"]
        ]
    return result


def _sanitize_cache_metrics(sanitizer, cache: Dict[str, Any]) -> Dict[str, Any]:
    """Sanitize cache metrics."""
    result = dict(cache)
    if "error" in result and isinstance(result["error"], str):
        result["error"] = sanitizer.sanitize_text(result["error"])
    if "errors" in result and isinstance(result["errors"], list):
        result["errors"] = [sanitizer.sanitize_text(str(e)) for e in result["errors"]]
    if "backends" in result and isinstance(result["backends"], list):
        result["backends"] = [
            {
                "name": "[backend]",
                "entry_cache_hit_ratio": b.get("entry_cache_hit_ratio"),
                "entry_cache_tries": b.get("entry_cache_tries"),
            }
            for b in result["backends"]
        ]
    return result


def _sanitize_disk_metrics(sanitizer, disk: Dict[str, Any]) -> Dict[str, Any]:
    """Sanitize disk metrics."""
    result = dict(disk)
    if "error" in result and isinstance(result["error"], str):
        result["error"] = sanitizer.sanitize_text(result["error"])
    if "partitions" in result and isinstance(result["partitions"], list):
        result["partitions"] = [
            {
                "partition": "[partition]",
                "usage_percent": p.get("usage_percent"),
                "size": p.get("size"),
                "available": p.get("available"),
            }
            for p in result["partitions"]
        ]
    return result


def _sanitize_cert_metrics(certs: Dict[str, Any], sanitizer=None) -> Dict[str, Any]:
    """Sanitize certificate metrics."""
    result = dict(certs)
    if "error" in result and isinstance(result["error"], str) and sanitizer:
        result["error"] = sanitizer.sanitize_text(result["error"])
    if "active_nickname" in result and isinstance(result["active_nickname"], str):
        # Nicknames can embed hostnames
        result["active_nickname"] = "[certificate]"
    if "certs" in result and isinstance(result["certs"], list):
        new_certs = []
        for c in result["certs"]:
            new_c = {
                "subject": "[certificate]",
                "type": c.get("type"),
                "days_until_expiry": c.get("days_until_expiry"),
            }
            if "is_active" in c:
                new_c["is_active"] = c["is_active"]
            new_certs.append(new_c)
        result["certs"] = new_certs
    return result

# Check classes whose CONSTRUCTION needs local file access; discovery
# failures for these against a remote live server are expected N/A.
_LOCAL_ONLY_CHECK_CLASSES = {
    "DSEldif",
    "FSChecks",
    "MonitorDiskSpace",
    "NssSsl",
    "DirsrvAccessLog",
}

LOCAL_ONLY_CHECK_UIDS = {
    "fschecks",
    "monitor-disk-space",
    "dseldif",
    "tls",
    "logs",
}

OFFLINE_COMPATIBLE_CHECK_UIDS = {
    "dseldif",
    "fschecks",
    "tls",
    "logs",
}

ARCHIVE_COMPATIBLE_CHECK_UIDS = {
    "dseldif",
}

CHECK_OBJECTS = [
    Config,
    Backends,
    Encryption,
    FSChecks,
    ReferentialIntegrityPlugin,
    MemberOfPlugin,
    MonitorDiskSpace,
    Replica,
    DSEldif,
    NssSsl,
    DirsrvAccessLog,
    Tunables,
]


def _get_all_error_codes() -> List[Dict[str, Any]]:
    """Get all known DSLE error codes from lib389.lint module."""
    errors = []
    for name in dir(lint):
        if re.match(r"^DS", name):
            error_def = getattr(lint, name)
            if isinstance(error_def, dict) and "dsle" in error_def:
                errors.append({
                    "code": error_def["dsle"],
                    "severity": error_def.get("severity", "UNKNOWN"),
                    "description": error_def.get("description", ""),
                })
    return sorted(errors, key=lambda x: x["code"])


def _list_check_targets(ds, discovery_errors: Optional[List[Dict[str, str]]] = None) -> Dict[str, Any]:
    """List all check targets and their available lint checks.

    Discovery uses the lib389 DSLint API (``lint_list()``), the same mechanism
    as ``dsctl healthcheck``. This is required because collection objects like
    ``Backends`` expose no ``_lint_*`` methods themselves — their checks live
    on the child objects (e.g. ``backends:userroot:mappingtree``) and are only
    reachable through ``lint_list()`` recursion.

    Returns a dict of ``uid -> {"object": obj, "checks": {spec_name: callable}}``.
    Categories that failed to instantiate or enumerate are appended to
    ``discovery_errors`` (when given) so callers can report incomplete coverage.
    """
    targets = {}
    for check_class in CHECK_OBJECTS:
        try:
            obj = check_class(ds)
            uid = obj.lint_uid()
            checks = dict(obj.lint_list())
            if checks:
                targets[uid] = {
                    "object": obj,
                    "checks": checks,
                }
        except Exception as exc:
            # Some objects may fail to instantiate or enumerate without proper
            # config — log it so a whole category can't vanish silently.
            _health_logger.warning(
                "Skipping health check category %s: %s: %s",
                getattr(check_class, "__name__", check_class), type(exc).__name__, exc,
            )
            if discovery_errors is not None:
                discovery_errors.append({
                    "category": getattr(check_class, "__name__", str(check_class)),
                    "error": format_error_message(exc),
                })
            continue
    return targets


def _match_check_pattern(pattern: str, spec_name: str) -> bool:
    """Match a user-supplied check pattern against a lint spec name.

    Supports ``*`` per colon-separated segment. A shorter pattern matches the
    trailing segments, so ``mappingtree`` matches ``userroot:mappingtree`` on
    every backend (mirroring how ``dsctl healthcheck`` runs suffix specs).
    """
    if pattern == "*" or pattern == spec_name:
        return True
    pattern_segs = pattern.split(":")
    spec_segs = spec_name.split(":")
    if len(pattern_segs) > len(spec_segs):
        return False
    # Compare against the trailing segments of the spec name
    return all(
        p == "*" or p == s
        for p, s in zip(pattern_segs, spec_segs[len(spec_segs) - len(pattern_segs):])
    )


def _expand_check_spec(targets: Dict[str, Any], spec: str) -> List[tuple]:
    """Expand a check spec like 'config:*' or 'backends:userroot:mappingtree'.

    Returns a list of ``(uid, spec_name, lint_callable)`` tuples.
    """
    checks = []
    if ":" in spec:
        uid_pattern, check_pattern = spec.split(":", 1)
    else:
        uid_pattern = spec
        check_pattern = "*"

    for uid, target_info in targets.items():
        # Match UID
        if uid_pattern != "*" and uid_pattern != uid:
            continue

        # Match checks
        for spec_name, lint_fn in target_info["checks"].items():
            if _match_check_pattern(check_pattern, spec_name):
                checks.append((uid, spec_name, lint_fn))

    return checks


def _run_single_check(check_id: str, lint_fn) -> tuple:
    """Run a single lint check callable.

    Returns ``(results, error, malformed_count)``. ``error`` is set when the
    check raised, and ``malformed_count`` counts non-dict lint results that
    had to be discarded — either condition means the check did not complete
    successfully and must not be counted as passed.
    """
    results = []
    error = None
    malformed = 0
    try:
        for result in lint_fn() or []:
            if isinstance(result, dict):
                # Add check identifier if not present
                if "check" not in result:
                    result = copy.deepcopy(result)
                    result["check"] = check_id
                results.append(result)
            else:
                malformed += 1
    except Exception as e:
        error = format_error_message(e)
        # Also surface the failure as a finding for visibility
        results.append({
            "dsle": "RUNTIME_ERROR",
            "severity": "MEDIUM",
            "description": f"Check failed: {check_id}",
            "items": [],
            "detail": str(e),
            "fix": "Review server logs and verify the server is accessible.",
            "check": check_id,
        })
    return results, error, malformed


def _convert_lib389_result_to_finding(result: Dict[str, Any], server_name: str) -> Dict[str, Any]:
    """Convert a lib389 lint result to the MCP finding format."""
    severity_map = {
        "CRITICAL": Severity.CRITICAL,
        "HIGH": Severity.HIGH,
        "MEDIUM": Severity.MEDIUM,
        "LOW": Severity.LOW,
        "INFO": Severity.INFO,
    }
    raw_severity = result.get("severity", "MEDIUM").upper()
    severity = severity_map.get(raw_severity, Severity.MEDIUM)

    items = result.get("items", [])
    items_str = ", ".join(str(item) for item in items) if items else "N/A"

    return format_finding(
        title=f"[{result.get('dsle', 'UNKNOWN')}] {result.get('description', 'Health check finding')}",
        severity=severity,
        impact=f"Affects: {items_str}",
        details=result.get("detail", "No details available"),
        remediation=result.get("fix", "No remediation steps provided"),
        server=server_name,
        metadata={
            "dsle": result.get("dsle"),
            "check": result.get("check"),
            "items": items,
        },
    )


_get_dse_ldif_path = get_dse_ldif_path
_find_child_dns = find_child_dns

# Metric keys written by the per-server health probes. Each probe leaves an
# ``error`` trail in its section when it could not collect required evidence;
# explicit not-applicable sections ({"available": False, "reason": ...} or
# {"configured": False} without an error) are not evidence gaps.
_PROBE_METRIC_KEYS = ("connections", "replication", "cache", "disk", "certificates")


def _metrics_evidence_gaps(server_name: str, srv_metrics: Dict[str, Any]) -> List[Dict[str, str]]:
    """List required-evidence gaps recorded in a server's health metrics.

    A ``healthy``/all-clear conclusion is impossible while any gap exists:
    a failed probe proves nothing about the state it was meant to observe.
    """
    gaps: List[Dict[str, str]] = []
    if isinstance(srv_metrics.get("error"), str):
        gaps.append({"server": server_name, "probe": "connect", "error": srv_metrics["error"]})
        return gaps
    for probe in _PROBE_METRIC_KEYS:
        value = srv_metrics.get(probe)
        if not isinstance(value, dict):
            continue
        if isinstance(value.get("error"), str):
            gaps.append({"server": server_name, "probe": probe, "error": value["error"]})
        elif value.get("incomplete"):
            errors = value.get("errors") or []
            detail = "; ".join(str(e) for e in errors) or "incomplete evidence"
            gaps.append({"server": server_name, "probe": probe, "error": detail})
    for key, probe in (
        ("dse_error", "dse"),
        ("dse_lint_error", "dse_lint"),
        ("fs_lint_error", "fs_checks"),
    ):
        if isinstance(srv_metrics.get(key), str):
            gaps.append({"server": server_name, "probe": probe, "error": srv_metrics[key]})
    for key, probe in (("dse_lint_errors", "dse_lint"), ("fs_lint_errors", "fs_checks")):
        errors = srv_metrics.get(key)
        if isinstance(errors, list) and errors:
            gaps.append({
                "server": server_name,
                "probe": probe,
                "error": "; ".join(str(e) for e in errors),
            })
    return gaps


def _check_server_health_offline(
    mcp: "DirSrvMCP",
    ds,
    server_name: str,
    config: "ServerConfig",
    findings: List[Dict[str, Any]],
    server_metrics: Dict[str, Any],
) -> None:
    """Check health metrics for an offline or archive server using dse.ldif."""
    from lib389.dseldif import DSEldif

    is_archive = config.is_archive
    mode_label = "ARCHIVE" if is_archive else "OFFLINE"
    metrics: Dict[str, Any] = {
        "server": server_name,
        "mode": mode_label.lower(),
        "is_local": not is_archive,
    }

    dse_path = _get_dse_ldif_path(ds)

    try:
        dse = DSEldif(ds, path=dse_path)

        version = dse.get("cn=config", "nsslapd-versionstring", single=True)
        port = dse.get("cn=config", "nsslapd-port", single=True)
        secure_port = dse.get("cn=config", "nsslapd-secureport", single=True)
        security = dse.get("cn=config", "nsslapd-security", single=True)

        metrics["version"] = version
        metrics["port"] = port
        metrics["secure_port"] = secure_port
        metrics["security_enabled"] = security == "on" if security else False

        ldbm_dn = "cn=ldbm database,cn=plugins,cn=config"
        backend_dns = _find_child_dns(dse, ldbm_dn)
        suffixes = []
        real_backends = 0
        for be_dn in backend_dns:
            suffix = dse.get(be_dn, "nsslapd-suffix", single=True)
            if suffix:
                real_backends += 1
                suffixes.append(suffix)

        plugins_dn = "cn=plugins,cn=config"
        plugin_dns = _find_child_dns(dse, plugins_dn)

        metrics["backends"] = real_backends
        metrics["suffixes"] = suffixes
        metrics["plugins"] = len(plugin_dns)

    except Exception as e:
        mcp.logger.debug("Could not read dse.ldif for %s: %s", server_name, e)
        metrics["dse_error"] = format_error_message(e)

    # Run DSEldif lint checks. Failures are recorded in the metrics so the
    # aggregation can tell "lint passed" apart from "lint never ran".
    dse_lint_errors: List[str] = []
    try:
        dse = DSEldif(ds, path=dse_path)
        for method_name in dir(dse):
            if method_name.startswith("_lint_"):
                try:
                    lint_method = getattr(dse, method_name)
                    for result in lint_method() or []:
                        if isinstance(result, dict):
                            finding = _convert_lib389_result_to_finding(result, server_name)
                            findings.append(finding)
                except Exception as e:
                    mcp.logger.debug("DSEldif lint %s failed: %s", method_name, e)
                    dse_lint_errors.append(f"{method_name}: {format_error_message(e)}")
    except Exception as e:
        mcp.logger.debug("Could not run DSEldif checks for %s: %s", server_name, e)
        metrics["dse_lint_error"] = format_error_message(e)
    if dse_lint_errors:
        metrics["dse_lint_errors"] = dse_lint_errors

    # For offline (non-archive) servers, we can also run FSChecks and log analysis
    if not is_archive:
        fs_lint_errors: List[str] = []
        try:
            fs_checks = FSChecks(ds)
            for method_name in dir(fs_checks):
                if method_name.startswith("_lint_"):
                    try:
                        lint_method = getattr(fs_checks, method_name)
                        for result in lint_method() or []:
                            if isinstance(result, dict):
                                finding = _convert_lib389_result_to_finding(result, server_name)
                                findings.append(finding)
                    except Exception as e:
                        mcp.logger.debug("FSChecks lint %s failed: %s", method_name, e)
                        fs_lint_errors.append(f"{method_name}: {format_error_message(e)}")
        except Exception as e:
            mcp.logger.debug("Could not run FSChecks for %s: %s", server_name, e)
            metrics["fs_lint_error"] = format_error_message(e)
        if fs_lint_errors:
            metrics["fs_lint_errors"] = fs_lint_errors

    metrics["connections"] = {"available": False, "reason": f"{mode_label} mode - no live connection"}
    metrics["replication"] = {"available": False, "reason": f"{mode_label} mode - no live connection"}
    metrics["cache"] = {"available": False, "reason": f"{mode_label} mode - no live connection"}
    metrics["disk"] = {"available": False, "reason": f"{mode_label} mode - no live monitoring"}
    metrics["certificates"] = {"available": False, "reason": f"{mode_label} mode - no NSS DB access"}

    server_metrics[server_name] = metrics

    findings.append(
        format_finding(
            title=f"[{mode_label}] Limited Health Check: {server_name}",
            severity=Severity.INFO,
            impact=f"Server analyzed in {mode_label.lower()} mode - only configuration checks available",
            details=(
                f"Server '{server_name}' is in {mode_label.lower()} mode. "
                f"Health checks are limited to dse.ldif analysis"
                + (" and filesystem checks" if not is_archive else "")
                + ". Live metrics (connections, replication, cache) are unavailable."
            ),
            remediation="Start the server for a full health assessment" if not is_archive else "Use a live server for full health assessment",
            server=server_name,
        )
    )


def _list_check_targets_offline(
    ds, is_archive: bool, discovery_errors: Optional[List[Dict[str, str]]] = None
) -> Dict[str, Any]:
    """List check targets available for offline/archive mode.

    Categories that failed to instantiate or enumerate are appended to
    ``discovery_errors`` (when given) so callers can report incomplete coverage.
    """
    compatible_uids = ARCHIVE_COMPATIBLE_CHECK_UIDS if is_archive else OFFLINE_COMPATIBLE_CHECK_UIDS
    targets = {}

    uid_to_class = {
        "dseldif": DSEldif,
        "fschecks": FSChecks,
        "tls": NssSsl,
        "logs": DirsrvAccessLog,
    }

    for uid in compatible_uids:
        check_class = uid_to_class.get(uid)
        if not check_class:
            continue
        try:
            if uid == "dseldif":
                dse_path = _get_dse_ldif_path(ds)
                obj = check_class(ds, path=dse_path)
            else:
                obj = check_class(ds)
            checks = dict(obj.lint_list())
            if checks:
                targets[uid] = {
                    "object": obj,
                    "checks": checks,
                }
        except Exception as exc:
            _health_logger.warning(
                "Skipping offline health check category %s: %s: %s",
                uid, type(exc).__name__, exc,
            )
            if discovery_errors is not None:
                discovery_errors.append({"category": uid, "error": format_error_message(exc)})
            continue
    return targets


def register_health_tools(mcp: DirSrvMCP) -> None:
    """Register health check tools with the MCP server."""

    @mcp.tool(annotations=_RO_LOCAL, tags={"health", "live", "offline", "archive"})
    def server_health() -> Dict[str, Any]:
        """Probe the MCP service itself (NOT directory server health — use ``first_look`` for that).

        Lightweight readiness check that never contacts any LDAP server:
        reports how many servers are configured and whether privacy/debug
        modes are active.

        Returns:
            Dictionary with status, server_count, privacy_mode, debug_mode.
        """
        try:
            return {
                "type": "server_health",
                "status": "healthy",
                "server_count": len(mcp.server_configs),
                "privacy_mode": mcp.privacy_enabled,
                "debug_mode": mcp.debug_enabled,
            }
        except Exception as e:
            mcp.logger.error("Error in server_health: %s", e)
            return format_tool_error(e, mcp, "server_health")

    @mcp.tool(annotations=_RO, tags={"health", "live", "offline", "archive"})
    def first_look() -> Dict[str, Any]:
        """Multi-server health overview — the first tool to call for any directory investigation.

        Scans ALL configured servers (live, offline, and archive) and returns
        prioritized findings with severity levels and actionable recommendations.
        For live servers: connectivity, connections, threads, replication,
        cache efficiency, disk space, and certificate expiration.
        For offline/archive servers: dse.ldif lint, filesystem checks (offline only).

        Use ``run_healthcheck`` for deeper per-server lint checks, or the
        ``get_performance_summary`` tool when focused on a single live server's
        performance counters.

        Works in all modes: LIVE, OFFLINE, ARCHIVE.

        Returns:
            Dict with ``overall_health``, severity counts, ``findings`` list,
            and per-server ``metrics``. Disk/certificate checks require
            local server access (is_local=True with serverid).
        """
        server_names = mcp.connection_manager.get_server_names()

        if not server_names:
            return {
                "type": "first_look",
                "summary": "No servers configured",
                "overall_health": "unknown",
                "critical_count": 1,
                "high_count": 0,
                "medium_count": 0,
                "low_count": 0,
                "info_count": 0,
                "findings": [
                    format_finding(
                        title="No LDAP Servers Configured",
                        severity=Severity.CRITICAL,
                        impact="Cannot perform any directory operations",
                        details=(
                            "The LDAP Assistant has no servers configured. "
                            "Configure at least one server via environment variables "
                            "or the JSON configuration file."
                        ),
                        remediation=(
                            "1. Set LDAP_URL, LDAP_BASE_DN, LDAP_BIND_DN, "
                            "LDAP_BIND_PASSWORD for single-server mode\n"
                            "2. Or provide a servers.json file via LDAP_SERVERS_CONFIG"
                        ),
                    )
                ],
                "servers_checked": [],
                "servers_failed": [],
                "metrics": {},
            }

        findings: List[Dict[str, Any]] = []
        servers_checked: List[str] = []
        servers_failed: List[str] = []
        server_metrics: Dict[str, Any] = {}

        for server_name in server_names:
            ds = None
            try:
                config = mcp.connection_manager.get_config(server_name)
                offline_archive = is_offline_or_archive(mcp.connection_manager, server_name)
                ds = mcp.connection_manager.connect(server_name)
                servers_checked.append(server_name)

                if offline_archive:
                    _check_server_health_offline(mcp, ds, server_name, config, findings, server_metrics)
                else:
                    _check_server_health(mcp, ds, server_name, config, findings, server_metrics)
            except Exception as exc:
                servers_failed.append(server_name)
                severity = Severity.CRITICAL if "connect" in str(exc).lower() else Severity.HIGH
                findings.append(
                    format_finding(
                        title=f"Server Unreachable: {server_name}",
                        severity=severity,
                        impact=f"Cannot connect to {server_name} - server may be down",
                        details=str(exc),
                        remediation="Verify server is running, check network connectivity and credentials",
                        server=server_name,
                    )
                )
                server_metrics[server_name] = {"error": format_error_message(exc)}
            finally:
                if ds is not None:
                    try:
                        ds.close()
                    except Exception:
                        pass

        # Count findings by severity
        severity_counts = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}
        for finding in findings:
            severity = finding.get("severity", "info")
            if severity in severity_counts:
                severity_counts[severity] += 1

        # Sort findings by severity (critical first)
        severity_order = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
        findings.sort(key=lambda f: severity_order.get(f.get("severity", "info"), 5))

        # Required-evidence completeness: any probe that failed left an error
        # trail in its metrics. A HEALTHY conclusion is impossible while a
        # required probe is missing its evidence.
        evidence_gaps: List[Dict[str, str]] = []
        for srv_name, srv_metrics in server_metrics.items():
            evidence_gaps.extend(_metrics_evidence_gaps(srv_name, srv_metrics))

        # Determine overall health. Incomplete evidence outranks a FAIR
        # verdict (mirroring run_healthcheck's INCOMPLETE-over-OK): medium
        # findings from partial evidence must not read as a fully-observed
        # "fair" system.
        if severity_counts["critical"] > 0:
            overall_health = "critical"
            summary = (
                f"CRITICAL: {severity_counts['critical']} critical issue(s) require immediate attention"
            )
        elif severity_counts["high"] > 0:
            overall_health = "degraded"
            summary = f"DEGRADED: {severity_counts['high']} high-priority issue(s) found"
        elif evidence_gaps:
            overall_health = "unknown"
            gap_servers = sorted({g["server"] for g in evidence_gaps})
            summary = (
                f"INCOMPLETE: {len(evidence_gaps)} required probe(s) failed on "
                f"{len(gap_servers)} server(s) - health cannot be confirmed"
            )
            if severity_counts["medium"] > 0:
                summary += (
                    f"; {severity_counts['medium']} issue(s) found in collected evidence"
                )
            else:
                summary += "; no issues found in collected evidence"
        elif severity_counts["medium"] > 0:
            overall_health = "fair"
            summary = f"FAIR: {severity_counts['medium']} issue(s) found that should be addressed"
        elif servers_failed:
            overall_health = "degraded"
            summary = f"DEGRADED: {len(servers_failed)} server(s) unreachable"
        else:
            overall_health = "healthy"
            summary = f"HEALTHY: All {len(servers_checked)} server(s) operating normally"

        # Build quick metrics summary
        metrics_summary = {}
        for srv_name, srv_metrics in server_metrics.items():
            if "error" in srv_metrics:
                metrics_summary[srv_name] = {"status": "unreachable"}
            else:
                srv_gaps = _metrics_evidence_gaps(srv_name, srv_metrics)
                srv_summary = {"status": "incomplete" if srv_gaps else "ok"}

                # Connection summary
                if "connections" in srv_metrics and "error" not in srv_metrics["connections"]:
                    srv_summary["connections"] = srv_metrics["connections"].get("current", 0)
                    srv_summary["fd_utilization"] = srv_metrics["connections"].get("fd_utilization_pct", 0)

                # Replication summary
                if "replication" in srv_metrics:
                    repl = srv_metrics["replication"]
                    if repl.get("configured"):
                        srv_summary["replication"] = {
                            "configured": True,
                            "agreements": len(repl.get("agreements", [])),
                        }
                    else:
                        srv_summary["replication"] = {"configured": False}

                # Cache summary
                if "cache" in srv_metrics and "backends" in srv_metrics["cache"]:
                    backends = srv_metrics["cache"]["backends"]
                    if backends:
                        avg_ratio = sum(b.get("entry_cache_hit_ratio", 0) for b in backends) / len(backends)
                        srv_summary["cache_hit_ratio_avg"] = round(avg_ratio, 1)

                metrics_summary[srv_name] = srv_summary

        result = {
            "type": "first_look",
            "summary": summary,
            "overall_health": overall_health,
            "critical_count": severity_counts["critical"],
            "high_count": severity_counts["high"],
            "medium_count": severity_counts["medium"],
            "low_count": severity_counts["low"],
            "info_count": severity_counts["info"],
            "findings": findings,
            "servers_checked": servers_checked,
            "servers_failed": servers_failed,
            "total_servers": len(server_names),
            "evidence_status": "partial" if evidence_gaps else "complete",
            "evidence_gaps": evidence_gaps,
            "metrics": metrics_summary,
            "detailed_metrics": server_metrics,
        }

        mcp.logger.info("first_look completed: %s", summary)
        return _sanitize_health_result(mcp, result)

    @mcp.tool(annotations=_RO_LOCAL, tags={"health", "live", "offline", "archive"})
    def list_healthcheck_errors() -> Dict[str, Any]:
        """List all known DSLE error codes that ``run_healthcheck`` can return.

        Use this to look up what a specific error code means (e.g. DSELE0001).
        Equivalent to ``dsctl <instance> healthcheck --list-errors``.
        No server connection required — this is a static reference list.
        """
        try:
            errors = _get_all_error_codes()
            return {
                "type": "healthcheck_errors",
                "total_count": len(errors),
                "errors": errors,
            }
        except Exception as e:
            mcp.logger.error("Error listing healthcheck errors: %s", e)
            return format_tool_error(e, mcp, "healthcheck_errors")

    @mcp.tool(annotations=_RO, tags={"health", "live", "offline", "archive"})
    def list_healthchecks(server_name: Optional[str] = None) -> Dict[str, Any]:
        """List available health checks for a server in ``category:check`` format.

        Returns checks that can be passed to ``run_healthcheck(checks=[...])``.
        The list is mode-aware: offline/archive servers only show compatible checks.
        Equivalent to ``dsctl <instance> healthcheck --list-checks``.

        Works in all modes: LIVE, OFFLINE, ARCHIVE.

        Args:
            server_name: Target server name. Uses default if not specified.
        """
        target = server_name or mcp.default_server
        if not target:
            return {
                "type": "healthcheck_list",
                "error": "No server configured",
                "checks": [],
            }

        ds = None
        try:
            offline_archive = is_offline_or_archive(mcp.connection_manager, target)
            ds = mcp.connection_manager.connect(target)

            if offline_archive:
                is_archive = is_archive_server(mcp.connection_manager, target)
                targets = _list_check_targets_offline(ds, is_archive)
            else:
                targets = _list_check_targets(ds)

            checks = []
            for uid, target_info in sorted(targets.items()):
                for spec_name in sorted(target_info["checks"]):
                    checks.append({
                        "name": f"{uid}:{spec_name}",
                        "category": uid,
                        "check": spec_name,
                    })

            result = {
                "type": "healthcheck_list",
                "server": target,
                "total_count": len(checks),
                "checks": checks,
                "categories": sorted(targets.keys()),
            }
            if offline_archive:
                mode = "archive" if is_archive else "offline"
                result["mode"] = mode
                result["note"] = f"Server is in {mode} mode. Only compatible checks are listed."

            return _sanitize_health_result(mcp, result)
        except Exception as e:
            result = format_tool_error(e, mcp, "healthcheck_list", server=target)
            result["checks"] = []
            return _sanitize_health_result(mcp, result)
        finally:
            if ds:
                try:
                    ds.close()
                except Exception:
                    pass

    @mcp.tool(annotations=_RO, tags={"health", "live", "offline", "archive"})
    def run_healthcheck(
        checks: Optional[List[str]] = None,
        exclude_checks: Optional[List[str]] = None,
        server_name: Optional[str] = None,
    ) -> Dict[str, Any]:
        """Run targeted lint checks on a single server (like ``dsctl healthcheck``).

        Use this tool after ``first_look`` to drill into specific check
        categories (config, backends, dseldif, tls, fschecks, plugins, etc.).
        For a broad multi-server overview, use ``first_look`` instead.

        Works in all modes: LIVE, OFFLINE, ARCHIVE.
        In offline mode: dseldif, fschecks, tls, and logs checks are available.
        In archive mode: only dseldif checks are available.
        For remote live servers: local-only checks (fschecks, disk, dseldif,
        tls, logs) are automatically skipped.

        Args:
            checks: Optional list of specific checks to run (e.g.,
                    ['config:*', 'backends:userroot:mappingtree']).
                    Use '*' as wildcard; a short form like 'backends:mappingtree'
                    runs that check on every backend. If not specified, runs all
                    available checks. Use ``list_healthchecks`` to see available
                    checks. A spec that matches nothing raises an error.
            exclude_checks: Optional list of checks to skip (same format as 'checks').
            server_name: Target server name. Uses default if not specified.

        Returns:
            Dict with ``summary``, severity counts, ``findings`` list with
            DSLE error codes, ``checks_executed``, and ``checks_skipped``.
        """
        target = server_name or mcp.default_server
        if not target:
            return {
                "type": "healthcheck",
                "error": "No server configured",
                "findings": [],
            }

        ds = None
        try:
            offline_archive = is_offline_or_archive(mcp.connection_manager, target)
            ds = mcp.connection_manager.connect(target)

            # Use mode-appropriate check targets. Discovery failures are
            # collected so incomplete coverage cannot pass as an all-clear.
            discovery_errors: List[Dict[str, str]] = []
            if offline_archive:
                is_archive = is_archive_server(mcp.connection_manager, target)
                targets = _list_check_targets_offline(ds, is_archive, discovery_errors)
            else:
                targets = _list_check_targets(ds, discovery_errors)

            # Check if this is a local server
            is_local = is_local_server(mcp.connection_manager, target)

            # Local-only categories (dse.ldif, filesystem, NSS DB, disk,
            # local logs) cannot even construct against a remote server —
            # that is expected N/A, not incomplete evidence. Their checks
            # would be excluded via LOCAL_ONLY_CHECK_UIDS anyway.
            if not is_local and not offline_archive:
                discovery_errors = [
                    e for e in discovery_errors
                    if e.get("category") not in _LOCAL_ONLY_CHECK_CLASSES
                ]

            # Determine which checks to run
            if checks:
                checks_to_run = []
                seen_check_ids = set()
                for spec in checks:
                    matched = _expand_check_spec(targets, spec)
                    if not matched:
                        raise ToolError(
                            f"No health checks match spec '{spec}' on server '{target}'. "
                            "Use list_healthchecks to see available checks."
                        )
                    for uid, spec_name, lint_fn in matched:
                        check_id = f"{uid}:{spec_name}"
                        if check_id not in seen_check_ids:
                            seen_check_ids.add(check_id)
                            checks_to_run.append((uid, spec_name, lint_fn))
            else:
                # Run all checks
                checks_to_run = []
                for uid, target_info in targets.items():
                    for spec_name, lint_fn in target_info["checks"].items():
                        checks_to_run.append((uid, spec_name, lint_fn))

            # Build exclusion set
            excluded = set()
            if exclude_checks:
                for spec in exclude_checks:
                    for uid, spec_name, _ in _expand_check_spec(targets, spec):
                        excluded.add(f"{uid}:{spec_name}")

            # For remote servers (not offline/archive), automatically exclude local-only checks
            local_only_skipped = []
            if not is_local and not offline_archive:
                for uid, target_info in targets.items():
                    # Check if this uid matches any local-only check
                    if uid.lower() in LOCAL_ONLY_CHECK_UIDS:
                        for spec_name in target_info["checks"]:
                            check_id = f"{uid}:{spec_name}"
                            if check_id not in excluded:
                                excluded.add(check_id)
                                local_only_skipped.append(check_id)

            # Run checks. A check is counted as executed (passed evidence
            # collection) only after it completed without raising and without
            # discarding malformed results.
            raw_results = []
            checks_executed = []
            checks_skipped = []
            checks_failed = []

            for uid, spec_name, lint_fn in checks_to_run:
                check_id = f"{uid}:{spec_name}"
                if check_id in excluded:
                    checks_skipped.append(check_id)
                    continue

                results, check_error, malformed = _run_single_check(check_id, lint_fn)
                raw_results.extend(results)
                if check_error is not None:
                    checks_failed.append({"check": check_id, "error": check_error})
                elif malformed:
                    checks_failed.append({
                        "check": check_id,
                        "error": f"{malformed} malformed (non-dict) lint result(s) discarded",
                    })
                else:
                    checks_executed.append(check_id)

            # Convert results to findings format
            findings = []
            for result in raw_results:
                finding = _convert_lib389_result_to_finding(result, target)
                findings.append(finding)

            # Count by severity
            severity_counts = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}
            for finding in findings:
                sev = finding.get("severity", "info").lower()
                if sev in severity_counts:
                    severity_counts[sev] += 1

            # Generate summary. An all-clear ("HEALTHY"/"OK") is impossible
            # unless at least one check executed and none failed, was
            # malformed, or vanished during discovery.
            total_issues = sum(severity_counts.values())
            # Findings synthesized from check FAILURES (RUNTIME_ERROR) are
            # already reported via checks_failed — "issue(s) found in
            # completed checks" must not count them a second time.
            failure_findings = sum(
                1
                for r in raw_results
                if isinstance(r, dict) and r.get("dsle") == "RUNTIME_ERROR"
            )
            completed_issues = total_issues - failure_findings
            attempted = len(checks_executed) + len(checks_failed)
            incomplete = bool(checks_failed or discovery_errors)
            if severity_counts["critical"] > 0:
                summary = f"CRITICAL: {severity_counts['critical']} critical issue(s) found"
            elif severity_counts["high"] > 0:
                summary = f"WARNING: {severity_counts['high']} high-priority issue(s) found"
            elif attempted == 0:
                summary = "UNKNOWN: no health checks could be executed"
                if discovery_errors:
                    summary += f" - {len(discovery_errors)} check category(ies) failed discovery"
            elif incomplete:
                parts = []
                if checks_failed:
                    parts.append(f"{len(checks_failed)} of {attempted} check(s) failed to complete")
                if discovery_errors:
                    parts.append(f"{len(discovery_errors)} check category(ies) failed discovery")
                summary = "INCOMPLETE: " + ", ".join(parts)
                if completed_issues:
                    summary += f"; {completed_issues} issue(s) found in completed checks"
            elif total_issues > 0:
                summary = f"OK: {total_issues} issue(s) found (no critical or high severity)"
            else:
                summary = f"HEALTHY: No issues found ({len(checks_executed)} checks passed)"

            if attempted == 0:
                evidence_status = "unavailable"
            elif incomplete:
                evidence_status = "partial"
            else:
                evidence_status = "complete"

            mcp.logger.info("run_healthcheck completed: %s", summary)

            result = {
                "type": "healthcheck",
                "server": target,
                "is_local": is_local,
                "summary": summary,
                "critical_count": severity_counts["critical"],
                "high_count": severity_counts["high"],
                "medium_count": severity_counts["medium"],
                "low_count": severity_counts["low"],
                "info_count": severity_counts["info"],
                "total_issues": total_issues,
                "evidence_status": evidence_status,
                "checks_failed": checks_failed,
                "discovery_errors": discovery_errors,
                "findings": findings,
                "checks_executed": checks_executed,
                "checks_skipped": checks_skipped,
                "total_checks_run": len(checks_executed),
            }

            # Add mode info for offline/archive
            if offline_archive:
                mode = "archive" if is_archive else "offline"
                result["mode"] = mode
                result["mode_note"] = (
                    f"Server is in {mode} mode. Only {mode}-compatible checks were run."
                )

            # Add local-only skipped checks info for remote servers
            if local_only_skipped:
                result["local_only_checks_skipped"] = local_only_skipped
                result["local_only_note"] = (
                    f"Skipped {len(local_only_skipped)} check(s) that require local server access. "
                    "Configure the server with is_local=True and serverid=<instance> to enable these checks."
                )

            return _sanitize_health_result(mcp, result)

        except ToolError:
            # User-facing errors (e.g. a check spec that matches nothing)
            # must propagate to the client instead of being masked.
            raise
        except Exception as e:
            mcp.logger.error("run_healthcheck failed: %s", e)
            err_msg = format_error_message(e)
            result = format_tool_error(e, mcp, "healthcheck", server=target)
            result["summary"] = f"FAILED: Health check could not complete - {err_msg}"
            result["findings"] = [
                format_finding(
                    title="Health Check Failed",
                    severity=Severity.CRITICAL,
                    impact="Unable to complete health check",
                    details=err_msg,
                    remediation="Verify server connectivity and check server logs",
                    server=target,
                )
            ]
            return _sanitize_health_result(mcp, result)
        finally:
            if ds:
                try:
                    ds.close()
                except Exception:
                    pass


def _check_server_health(
    mcp: DirSrvMCP,
    ds,
    server_name: str,
    config: ServerConfig,
    findings: List[Dict[str, Any]],
    server_metrics: Dict[str, Any],
) -> None:
    """Check comprehensive health metrics for a single server."""
    metrics: Dict[str, Any] = {"server": server_name}

    # Check if this is a local server
    is_local = is_local_server(mcp.connection_manager, server_name)
    metrics["is_local"] = is_local

    # Run all health checks - each adds to findings and metrics
    _check_connection_health(mcp, ds, server_name, findings, metrics)
    _check_replication_health(mcp, ds, server_name, findings, metrics)
    _check_cache_health(mcp, ds, server_name, findings, metrics)
    _check_disk_health(mcp, ds, server_name, findings, metrics, is_local)
    _check_certificate_health(mcp, ds, server_name, findings, metrics, is_local)

    # Store metrics for this server
    server_metrics[server_name] = metrics

    # Add success indicator only when no critical issues were found AND every
    # probe actually delivered its evidence — a failed probe proves nothing.
    server_findings = [f for f in findings if f.get("server") == server_name]
    critical_count = sum(1 for f in server_findings if f.get("severity") == "critical")
    high_count = sum(1 for f in server_findings if f.get("severity") == "high")

    if critical_count == 0 and high_count == 0 and not _metrics_evidence_gaps(server_name, metrics):
        findings.append(
            format_finding(
                title=f"Server {server_name} is healthy",
                severity=Severity.INFO,
                impact="Server is operating normally",
                details=f"All health checks passed for {config.ldap_url}",
                remediation="No action needed",
                server=server_name,
            )
        )


def _check_replication_health(
    mcp: DirSrvMCP,
    ds,
    server_name: str,
    findings: List[Dict[str, Any]],
    metrics: Dict[str, Any],
) -> None:
    """Check replication status for health issues."""
    try:
        replicas = Replicas(ds)
        replica_list = replicas.list()

        if not replica_list:
            metrics["replication"] = {"configured": False}
            return

        metrics["replication"] = {
            "configured": True,
            "replica_count": len(replica_list),
            "agreements": [],
        }

        for replica in replica_list:
            try:
                suffix = replica.get_suffix()
                agreements = replica.get_agreements()

                for agmt in agreements.list():
                    agmt_name = agmt.get_attr_val_utf8("cn")
                    consumer = agmt.get_attr_val_utf8("nsDS5ReplicaHost")
                    last_result = agmt.get_attr_val_utf8("nsds5replicaLastUpdateStatus") or ""

                    agmt_info = {
                        "name": agmt_name,
                        "consumer": consumer,
                        "suffix": suffix,
                    }
                    metrics["replication"]["agreements"].append(agmt_info)

                    # Check for replication errors
                    if last_result:
                        # Error status typically starts with "Error" or has non-zero code
                        # Note: "Error (0)" means success - error code 0 = no error
                        last_result_lower = last_result.lower()
                        is_error = (
                            ("error" in last_result_lower and not last_result_lower.startswith("error (0)")) or
                            last_result.startswith("(-") or
                            (last_result.startswith("(") and not last_result.startswith("(0)"))
                        )
                        if is_error:
                            findings.append(
                                format_finding(
                                    title=f"Replication Error: {agmt_name}",
                                    severity=Severity.HIGH,
                                    impact=f"Replication to {consumer} for {suffix} is failing",
                                    details=f"Last status: {last_result}",
                                    remediation="Check network connectivity and consumer server status",
                                    server=server_name,
                                    metadata={"agreement": agmt_name, "consumer": consumer},
                                )
                            )

            except Exception as e:
                mcp.logger.debug("Error checking replica %s: %s", replica, e)
                metrics["replication"]["incomplete"] = True
                metrics["replication"].setdefault("errors", []).append(format_error_message(e))

    except Exception as e:
        mcp.logger.debug("Could not check replication for %s: %s", server_name, e)
        metrics["replication"] = {"configured": False, "error": format_error_message(e)}


def _check_cache_health(
    mcp: DirSrvMCP,
    ds,
    server_name: str,
    findings: List[Dict[str, Any]],
    metrics: Dict[str, Any],
) -> None:
    """Check cache efficiency for health issues."""
    try:
        backends = Backends(ds)
        backend_list = list(backends.list())

        cache_metrics = {
            "backends": [],
            "overall_health": "healthy",
        }

        low_hit_ratio_count = 0

        for be in backend_list:
            be_name = be.get_attr_val_utf8("cn")
            try:
                be_monitor = be.get_monitor()
                be_status = be_monitor.get_status()

                entry_hits = safe_int(be_status.get("entrycachehits"))
                entry_tries = safe_int(be_status.get("entrycachetries"))
                entry_ratio = safe_float(be_status.get("entrycachehitratio"))

                if entry_ratio == 0 and entry_tries > 0:
                    entry_ratio = round((entry_hits / entry_tries) * 100, 2) if entry_tries > 0 else 0

                cache_metrics["backends"].append({
                    "name": be_name,
                    "entry_cache_hit_ratio": entry_ratio,
                    "entry_cache_tries": entry_tries,
                })

                # Alert on low hit ratio only if there's significant activity
                if entry_tries > 1000 and entry_ratio < 70:
                    low_hit_ratio_count += 1
                    severity = Severity.HIGH if entry_ratio < 50 else Severity.MEDIUM
                    findings.append(
                        format_finding(
                            title=f"Low Cache Hit Ratio: {be_name}",
                            severity=severity,
                            impact=f"Entry cache hit ratio is {entry_ratio}% - frequent disk reads",
                            details=f"Backend {be_name}: {entry_hits} hits / {entry_tries} tries",
                            remediation=f"Investigate cache sizing for backend {be_name}. If memory is available and hit ratio remains low under normal load, consider adjusting nsslapd-cachememsize. Verify with monitoring before and after any changes.",
                            server=server_name,
                            metadata={"backend": be_name, "hit_ratio": entry_ratio},
                        )
                    )

            except Exception as e:
                mcp.logger.debug("Error checking cache for backend %s: %s", be_name, e)
                cache_metrics["incomplete"] = True
                cache_metrics.setdefault("errors", []).append(format_error_message(e))

        if low_hit_ratio_count > 0:
            cache_metrics["overall_health"] = "degraded"

        metrics["cache"] = cache_metrics

    except Exception as e:
        mcp.logger.debug("Could not check cache for %s: %s", server_name, e)
        metrics["cache"] = {"error": format_error_message(e)}


def _check_disk_health(
    mcp: DirSrvMCP,
    ds,
    server_name: str,
    findings: List[Dict[str, Any]],
    metrics: Dict[str, Any],
    is_local: bool = True,
) -> None:
    """Check disk space for health issues.

    Note: Disk space monitoring requires local server access (is_local=True).
    For remote servers, this check will be skipped with an informational message.
    """
    if not is_local:
        mcp.logger.debug("Skipping disk health check for remote server %s", server_name)
        metrics["disk"] = {
            "available": False,
            "reason": "Disk monitoring requires local server access (is_local=True with serverid)",
        }
        return

    try:
        disk_monitor = MonitorDiskSpace(ds)
        disks = disk_monitor.get_disks()

        disk_metrics = []

        for disk in disks:
            # Parse disk info string (keys are partition/size/used/available/use%)
            disk_entry = parse_dsdisk_entry(disk)

            partition = disk_entry["partition"]
            pct = disk_entry["use_percent"]
            size = disk_entry["size"]
            avail = disk_entry["available"]

            disk_metrics.append({
                "partition": partition,
                "usage_percent": pct,
                "size": size,
                "available": avail,
            })

            if pct >= 95:
                findings.append(
                    format_finding(
                        title=f"Critical Disk Space: {partition}",
                        severity=Severity.CRITICAL,
                        impact=f"Partition {partition} is {pct}% full - server may fail",
                        details=f"Size: {size}, Available: {avail}",
                        remediation="Free up disk space immediately or expand storage",
                        server=server_name,
                        metadata={"partition": partition, "usage": pct},
                    )
                )
            elif pct >= 85:
                findings.append(
                    format_finding(
                        title=f"High Disk Usage: {partition}",
                        severity=Severity.HIGH,
                        impact=f"Partition {partition} is {pct}% full",
                        details=f"Size: {size}, Available: {avail}",
                        remediation="Plan for disk space cleanup or expansion",
                        server=server_name,
                        metadata={"partition": partition, "usage": pct},
                    )
                )

        metrics["disk"] = {"available": True, "partitions": disk_metrics}

    except Exception as e:
        mcp.logger.debug("Could not check disk space for %s: %s", server_name, e)
        metrics["disk"] = {"available": False, "error": format_error_message(e)}


def _get_active_cert_nickname(mcp: DirSrvMCP, ds) -> Optional[str]:
    """Read the nickname of the certificate the server actually serves.

    The active server certificate is named by ``nsSSLPersonalitySSL`` under
    ``cn=RSA,cn=encryption,cn=config``.  Returns None when it cannot be
    determined (activeness of NSS DB certs is then unknown).
    """
    try:
        val = RSA(ds).get_attr_val_utf8("nsSSLPersonalitySSL")
    except Exception as e:
        mcp.logger.debug(
            "Active server certificate nickname unavailable: %s", e
        )
        return None
    if isinstance(val, str) and val.strip():
        return val.strip()
    return None


def _check_certificate_health(
    mcp: DirSrvMCP,
    ds,
    server_name: str,
    findings: List[Dict[str, Any]],
    metrics: Dict[str, Any],
    is_local: bool = True,
) -> None:
    """Check SSL certificate expiration.

    Distinguishes the ACTIVE server certificate (nsSSLPersonalitySSL) from
    the rest of the NSS DB inventory: only the active certificate's expiry
    is an active-service outage; other expired certificates are inventory
    hygiene issues. When the active nickname cannot be determined, findings
    are labeled as certificate inventory with unknown role.

    Note: Certificate checking requires local server access (is_local=True)
    to read the NSS certificate database. For remote servers, this check
    will be skipped with an informational message.
    """
    if not is_local:
        mcp.logger.debug("Skipping certificate health check for remote server %s", server_name)
        metrics["certificates"] = {
            "available": False,
            "reason": "Certificate monitoring requires local server access (is_local=True with serverid)",
        }
        return

    try:
        nss_ssl = NssSsl(ds)

        # Which certificate does the server actually serve?  Without this,
        # every expired cert in the NSS DB would read as a service outage.
        active_nickname = _get_active_cert_nickname(mcp, ds)

        # Enumerate all certificates in the NSS database. list_certs(ca=False)
        # returns server/user certs, list_certs(ca=True) returns CA certs.
        # Each entry is a list: [nickname, subject, issuer, expire_date, trust_flags].
        cert_details = list(nss_ssl.list_certs() or [])
        cert_details.extend(nss_ssl.list_certs(ca=True) or [])

        certs = []
        now = datetime.now(timezone.utc)

        for detail in cert_details:
            nickname = detail[0] if len(detail) > 0 else "Unknown"
            subject = detail[1] if len(detail) > 1 else "Unknown"
            not_after = detail[3] if len(detail) > 3 else None
            trust_flags = detail[4] if len(detail) > 4 else ""

            cert_type = "ca" if "CT" in str(trust_flags) else "server"
            cert_info = {
                "nickname": nickname,
                "subject": subject,
                "type": cert_type,
            }
            is_active: Optional[bool] = None
            if active_nickname is not None:
                is_active = nickname == active_nickname
                cert_info["is_active"] = is_active

            exp_date = _parse_cert_expiry(not_after)
            if exp_date is not None:
                days_until = (exp_date - now).days
                cert_info["expires"] = str(not_after)
                cert_info["days_until_expiry"] = days_until

                if days_until < 0:
                    if is_active:
                        severity = Severity.CRITICAL
                        impact = "The ACTIVE server certificate has expired - clients may reject TLS connections"
                        details = f"Active server certificate '{nickname}' expired {abs(days_until)} day(s) ago ({not_after})"
                        remediation = "Renew the active SSL server certificate immediately"
                    elif is_active is None:
                        # Activeness unknown: keep the worst-case severity but
                        # label it honestly as an inventory observation.
                        severity = Severity.CRITICAL
                        impact = "Certificate inventory: an expired certificate is present (active server certificate could not be determined - this may or may not be the serving certificate)"
                        details = f"Certificate '{nickname}' expired {abs(days_until)} day(s) ago ({not_after}). Active-role unknown: nsSSLPersonalitySSL could not be read."
                        remediation = "Determine whether this certificate is the active server certificate (nsSSLPersonalitySSL) and renew it if so"
                    elif cert_type == "ca":
                        severity = Severity.HIGH
                        impact = "An expired CA certificate in the NSS DB - certificates issued by it fail chain validation"
                        details = f"CA certificate '{nickname}' expired {abs(days_until)} day(s) ago ({not_after})"
                        remediation = "Replace the CA certificate and re-issue dependent certificates if it anchors the active server certificate's chain"
                    else:
                        severity = Severity.MEDIUM
                        impact = "unused/unknown-role certificate expired - not the active server certificate, so no immediate service impact"
                        details = f"Certificate '{nickname}' expired {abs(days_until)} day(s) ago ({not_after}) but is not the active server certificate ('{active_nickname}')"
                        remediation = "Remove or renew the unused certificate to keep the NSS DB inventory clean"
                    findings.append(
                        format_finding(
                            title=f"SSL Certificate Expired: {nickname}",
                            severity=severity,
                            impact=impact,
                            details=details,
                            remediation=remediation,
                            server=server_name,
                            metadata={
                                "nickname": nickname,
                                "days_expired": abs(days_until),
                                "is_active": is_active,
                                "cert_type": cert_type,
                            },
                        )
                    )
                elif days_until <= 30:
                    if is_active is False and cert_type != "ca":
                        expiring_severity = Severity.LOW
                        expiring_impact = f"unused/unknown-role certificate '{nickname}' expires in {days_until} day(s) - not the active server certificate"
                    else:
                        expiring_severity = Severity.HIGH if days_until <= 7 else Severity.MEDIUM
                        expiring_impact = f"Certificate '{nickname}' expires in {days_until} day(s)"
                    findings.append(
                        format_finding(
                            title=f"SSL Certificate Expiring Soon: {nickname}",
                            severity=expiring_severity,
                            impact=expiring_impact,
                            details=f"Expiration: {not_after}",
                            remediation="Plan certificate renewal before expiration",
                            server=server_name,
                            metadata={
                                "nickname": nickname,
                                "days_until_expiry": days_until,
                                "is_active": is_active,
                                "cert_type": cert_type,
                            },
                        )
                    )
            elif not_after is not None:
                mcp.logger.warning(
                    "Could not parse expiration date %r for certificate %s on %s",
                    not_after, nickname, server_name,
                )

            certs.append(cert_info)

        cert_metrics: Dict[str, Any] = (
            {"available": True, "certs": certs}
            if certs
            else {"available": True, "status": "no certificates found"}
        )
        if active_nickname is not None:
            cert_metrics["active_nickname"] = active_nickname
        metrics["certificates"] = cert_metrics

    except Exception as e:
        # Do not silently swallow failures (e.g. missing NSS DB or API changes):
        # surface them in the metrics so the caller can see the check failed.
        mcp.logger.warning("Could not check certificates for %s: %s", server_name, e)
        metrics["certificates"] = {"available": False, "error": format_error_message(e)}


def _parse_cert_expiry(not_after: Any) -> Optional[datetime]:
    """Parse a certificate expiration value into an aware UTC datetime.

    lib389's ``NssSsl.get_cert_details()``/``list_certs()`` return the expiry
    as ``str(datetime)``, e.g. ``'2026-07-10 12:34:56'``. Raw certutil output
    (``'Mon Jul 10 12:34:56 2026'``) is accepted as a fallback.
    """
    if isinstance(not_after, datetime):
        if not_after.tzinfo is None:
            return not_after.replace(tzinfo=timezone.utc)
        return not_after
    if not isinstance(not_after, str) or not not_after.strip():
        return None

    value = not_after.strip()
    for fmt in ("%Y-%m-%d %H:%M:%S", "%a %b %d %H:%M:%S %Y"):
        try:
            return datetime.strptime(value, fmt).replace(tzinfo=timezone.utc)
        except ValueError:
            continue

    # Date-only fallback, as used by lib389's _lint_certificate_expiration
    try:
        return datetime.strptime(value.split()[0], "%Y-%m-%d").replace(tzinfo=timezone.utc)
    except (ValueError, IndexError):
        return None


def _check_connection_health(
    mcp: DirSrvMCP,
    ds,
    server_name: str,
    findings: List[Dict[str, Any]],
    metrics: Dict[str, Any],
) -> None:
    """Check connection and resource utilization."""
    try:
        monitor = Monitor(ds)

        # Get specific attributes. A failed monitor read must leave an error
        # trail — all-zero metrics would silently pass as measured evidence.
        try:
            status = monitor.get_attrs_vals_utf8([
                'currentconnections', 'totalconnections', 'dtablesize',
                'threads', 'currentconnectionsatmaxthreads', 'opsinitiated', 'opscompleted'
            ])
        except Exception as e:
            mcp.logger.debug("Could not read monitor attributes for %s: %s", server_name, e)
            metrics["connections"] = {"error": format_error_message(e)}
            return

        current_conns = safe_int(status.get("currentconnections"))
        total_conns = safe_int(status.get("totalconnections"))
        dtable_size = safe_int(status.get("dtablesize"))
        threads = safe_int(status.get("threads"))
        conns_at_max = safe_int(status.get("currentconnectionsatmaxthreads"))
        ops_initiated = safe_int(status.get("opsinitiated"))
        ops_completed = safe_int(status.get("opscompleted"))

        fd_util = round((current_conns / dtable_size * 100), 2) if dtable_size > 0 else 0
        ops_pending = ops_initiated - ops_completed

        metrics["connections"] = {
            "current": current_conns,
            "total": total_conns,
            "max_fd": dtable_size,
            "fd_utilization_pct": fd_util,
        }

        metrics["threads"] = {
            "configured": threads,
            "at_max_threads": conns_at_max,
        }

        metrics["operations"] = {
            "completed": ops_completed,
            "pending": ops_pending,
        }

        # Check for issues
        if fd_util > 80:
            findings.append(
                format_finding(
                    title="High Connection Utilization",
                    severity=Severity.HIGH,
                    impact=f"Server using {fd_util}% of available file descriptors",
                    details=f"Current: {current_conns}, Max: {dtable_size}",
                    remediation="Investigate connection patterns to determine root cause. Check for connection leaks in client applications, consider whether current descriptor limits match system ulimits before adjusting nsslapd-maxdescriptors.",
                    server=server_name,
                    metadata={"utilization": fd_util},
                )
            )

        if conns_at_max > 0:
            findings.append(
                format_finding(
                    title="Thread Contention Detected",
                    severity=Severity.HIGH,
                    impact=f"{conns_at_max} connections hitting thread limit",
                    details="Connections are being throttled due to thread limits",
                    remediation="Investigate thread utilization patterns and server load. If CPU resources are available and contention persists under normal load, nsslapd-threadnumber may need adjustment. Review server documentation for tuning guidance.",
                    server=server_name,
                    metadata={"at_max_threads": conns_at_max},
                )
            )

        if ops_pending > 100:
            findings.append(
                format_finding(
                    title="High Pending Operations",
                    severity=Severity.HIGH,
                    impact=f"{ops_pending} operations pending",
                    details="Server may be overloaded",
                    remediation="Check server resources and consider scaling",
                    server=server_name,
                    metadata={"pending": ops_pending},
                )
            )

    except Exception as e:
        mcp.logger.debug("Could not check connections for %s: %s", server_name, e)
        metrics["connections"] = {"error": format_error_message(e)}

