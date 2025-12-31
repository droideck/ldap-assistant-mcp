"""Health check tools for 389 Directory Server."""

from __future__ import annotations

import copy
import re
from datetime import datetime, timezone
from typing import TYPE_CHECKING, Any, Dict, List, Optional

from lib389 import lint
from lib389.backend import Backends
from lib389.config import Config, Encryption
from lib389.dirsrv_log import DirsrvAccessLog
from lib389.dseldif import DSEldif, FSChecks
from lib389.monitor import Monitor, MonitorDiskSpace, MonitorLDBM
from lib389.nss_ssl import NssSsl
from lib389.plugins import MemberOfPlugin, ReferentialIntegrityPlugin
from lib389.replica import Replica, Replicas
from lib389.tunables import Tunables

from src.dirsrv_mcp.connection import is_local_server
from src.lib.result_formatter import Severity, format_finding

if TYPE_CHECKING:
    from src.dirsrv_mcp.connection import ServerConfig
    from src.dirsrv_mcp.server import DirSrvMCP

# Check UIDs that ONLY work with local servers (require filesystem or NSS access)
# These are the lint_uid() values returned by the check objects
LOCAL_ONLY_CHECK_UIDS = {
    "fschecks",           # FSChecks - file system permission checks
    "monitor-disk-space", # MonitorDiskSpace - disk space monitoring
    "dseldif",            # DSEldif - DSE.ldif configuration access
    "tls",                # NssSsl - certificate database access (uses "tls" uid)
    "logs",               # DirsrvAccessLog - access log analysis
}


# Check objects that can perform lint operations (mirrors lib389 CHECK_OBJECTS)
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


def _list_check_targets(ds) -> Dict[str, Any]:
    """List all check targets and their available lint methods."""
    targets = {}
    for check_class in CHECK_OBJECTS:
        try:
            obj = check_class(ds)
            uid = obj.lint_uid()
            methods = []
            for method_name in dir(obj):
                if method_name.startswith("_lint_"):
                    pretty_name = method_name[6:]  # Remove '_lint_' prefix
                    methods.append(pretty_name)
            if methods:
                targets[uid] = {
                    "object": obj,
                    "methods": sorted(methods),
                }
        except Exception:
            # Some objects may fail to instantiate without proper config
            continue
    return targets


def _expand_check_spec(targets: Dict[str, Any], spec: str) -> List[tuple]:
    """Expand a check spec like 'config:*' or 'backends:mappingtree' to list of (uid, method)."""
    checks = []
    if ":" in spec:
        uid_pattern, method_pattern = spec.split(":", 1)
    else:
        uid_pattern = spec
        method_pattern = "*"

    for uid, target_info in targets.items():
        # Match UID
        if uid_pattern != "*" and uid_pattern != uid:
            continue

        # Match methods
        for method in target_info["methods"]:
            if method_pattern == "*" or method_pattern == method:
                checks.append((uid, method, target_info["object"]))

    return checks


def _run_single_check(obj, method_name: str) -> List[Dict[str, Any]]:
    """Run a single lint check and return results."""
    results = []
    try:
        lint_method = getattr(obj, f"_lint_{method_name}", None)
        if lint_method and callable(lint_method):
            for result in lint_method() or []:
                if isinstance(result, dict):
                    # Add check identifier if not present
                    if "check" not in result:
                        result = copy.deepcopy(result)
                        result["check"] = f"{obj.lint_uid()}:{method_name}"
                    results.append(result)
    except Exception as e:
        # Return error as a finding
        results.append({
            "dsle": "RUNTIME_ERROR",
            "severity": "MEDIUM",
            "description": f"Check failed: {obj.lint_uid()}:{method_name}",
            "items": [],
            "detail": str(e),
            "fix": "Review server logs and verify the server is accessible.",
            "check": f"{obj.lint_uid()}:{method_name}",
        })
    return results


def _convert_lib389_result_to_finding(result: Dict[str, Any], server_name: str) -> Dict[str, Any]:
    """Convert a lib389 lint result to the MCP finding format."""
    severity_map = {
        "CRITICAL": Severity.CRITICAL,
        "HIGH": Severity.HIGH,
        "MEDIUM": Severity.MEDIUM,
        "LOW": Severity.LOW,
        "INFO": Severity.INFO,
    }
    # Handle case-insensitive severity matching
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


def register_health_tools(mcp: DirSrvMCP) -> None:
    """Register health check tools with the MCP server."""

    @mcp.tool()
    def first_look() -> Dict[str, Any]:
        """Comprehensive health overview - the go-to tool for "what's wrong with my directory?"

        Performs a complete health assessment across all configured servers including:
        - Server connectivity and basic health
        - Connection and thread utilization
        - Replication status and errors
        - Cache efficiency (entry cache hit ratios)
        - Disk space usage (local servers only)
        - SSL certificate expiration (local servers only)

        **Note on local vs remote servers:**
        Most checks work via LDAP and are available for all servers. However, the
        following require local server access (is_local=True with serverid):
        - Disk space monitoring (requires filesystem access)
        - Certificate expiration checking (requires NSS database access)

        For remote servers, these metrics will show as unavailable in the response.

        Returns prioritized findings with severity levels and actionable recommendations.
        This should be the first tool called when investigating directory issues.
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
                ds = mcp.connection_manager.connect(server_name)
                servers_checked.append(server_name)
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
                server_metrics[server_name] = {"error": str(exc)}
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

        # Determine overall health
        if severity_counts["critical"] > 0:
            overall_health = "critical"
            summary = (
                f"CRITICAL: {severity_counts['critical']} critical issue(s) require immediate attention"
            )
        elif severity_counts["high"] > 0:
            overall_health = "degraded"
            summary = f"DEGRADED: {severity_counts['high']} high-priority issue(s) found"
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
                srv_summary = {"status": "ok"}

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
            "metrics": metrics_summary,
            "detailed_metrics": server_metrics,
        }

        mcp.logger.info("first_look completed: %s", summary)
        return result

    @mcp.tool()
    def list_healthcheck_errors() -> Dict[str, Any]:
        """List all known health check error codes (DSLE codes).

        Returns a list of all possible error codes that can be returned by
        the run_healthcheck tool, along with their severity and description.
        This is equivalent to 'dsctl <instance> healthcheck --list-errors'.
        """
        errors = _get_all_error_codes()
        return {
            "type": "healthcheck_errors",
            "total_count": len(errors),
            "errors": errors,
        }

    @mcp.tool()
    def list_healthchecks(server_name: Optional[str] = None) -> Dict[str, Any]:
        """List all available health checks that can be run.

        Returns a list of all available checks in the format 'category:check_name'.
        Use these check names with the run_healthcheck tool's 'checks' parameter.
        This is equivalent to 'dsctl <instance> healthcheck --list-checks'.

        Args:
            server_name: Optional server to query for available checks.
                         If not specified, uses the default server.
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
            ds = mcp.connection_manager.connect(target)
            targets = _list_check_targets(ds)

            checks = []
            for uid, target_info in sorted(targets.items()):
                for method in target_info["methods"]:
                    checks.append({
                        "name": f"{uid}:{method}",
                        "category": uid,
                        "check": method,
                    })

            return {
                "type": "healthcheck_list",
                "server": target,
                "total_count": len(checks),
                "checks": checks,
                "categories": sorted(targets.keys()),
            }
        except Exception as e:
            return {
                "type": "healthcheck_list",
                "server": target,
                "error": str(e),
                "checks": [],
            }
        finally:
            if ds:
                try:
                    ds.close()
                except Exception:
                    pass

    @mcp.tool()
    def run_healthcheck(
        checks: Optional[List[str]] = None,
        exclude_checks: Optional[List[str]] = None,
        server_name: Optional[str] = None,
    ) -> Dict[str, Any]:
        """Run comprehensive health checks on the 389 Directory Server.

        This tool performs the same checks as 'dsctl <instance> healthcheck',
        examining configuration, backends, security, replication, plugins,
        certificates, disk space, and more.

        **Note on local vs remote servers:**
        Some checks require local server access (is_local=True with serverid):
        - fschecks: File system permission checks
        - monitor-disk-space: Disk space monitoring
        - dseldif: DSE.ldif configuration access
        - tls: Certificate database access (requires certutil)
        - logs: Access log analysis

        For remote servers, these checks will be automatically skipped.

        Args:
            checks: Optional list of specific checks to run (e.g., ['config:*', 'backends:mappingtree']).
                    Use '*' as wildcard. If not specified, runs all available checks.
                    Use list_healthchecks() to see available checks.
            exclude_checks: Optional list of checks to skip (same format as 'checks').
            server_name: Optional server to check. If not specified, uses the default server.

        Returns:
            A structured report with findings, including:
            - Summary of issues found by severity
            - Detailed findings with error codes, descriptions, and remediation steps
            - List of checks that were run
            - List of checks skipped (including local-only checks for remote servers)
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
            ds = mcp.connection_manager.connect(target)
            targets = _list_check_targets(ds)

            # Check if this is a local server
            is_local = is_local_server(mcp.connection_manager, target)

            # Determine which checks to run
            if checks:
                checks_to_run = []
                for spec in checks:
                    checks_to_run.extend(_expand_check_spec(targets, spec))
            else:
                # Run all checks
                checks_to_run = []
                for uid, target_info in targets.items():
                    for method in target_info["methods"]:
                        checks_to_run.append((uid, method, target_info["object"]))

            # Build exclusion set
            excluded = set()
            if exclude_checks:
                for spec in exclude_checks:
                    for uid, method, _ in _expand_check_spec(targets, spec):
                        excluded.add(f"{uid}:{method}")

            # For remote servers, automatically exclude local-only checks
            local_only_skipped = []
            if not is_local:
                for uid, target_info in targets.items():
                    # Check if this uid matches any local-only check
                    if uid.lower() in LOCAL_ONLY_CHECK_UIDS:
                        for method in target_info["methods"]:
                            check_id = f"{uid}:{method}"
                            if check_id not in excluded:
                                excluded.add(check_id)
                                local_only_skipped.append(check_id)

            # Run checks
            raw_results = []
            checks_executed = []
            checks_skipped = []

            for uid, method, obj in checks_to_run:
                check_id = f"{uid}:{method}"
                if check_id in excluded:
                    checks_skipped.append(check_id)
                    continue

                checks_executed.append(check_id)
                results = _run_single_check(obj, method)
                raw_results.extend(results)

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

            # Generate summary
            total_issues = sum(severity_counts.values())
            if severity_counts["critical"] > 0:
                summary = f"CRITICAL: {severity_counts['critical']} critical issue(s) found"
            elif severity_counts["high"] > 0:
                summary = f"WARNING: {severity_counts['high']} high-priority issue(s) found"
            elif total_issues > 0:
                summary = f"OK: {total_issues} issue(s) found (no critical or high severity)"
            else:
                summary = f"HEALTHY: No issues found ({len(checks_executed)} checks passed)"

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
                "findings": findings,
                "checks_executed": checks_executed,
                "checks_skipped": checks_skipped,
                "total_checks_run": len(checks_executed),
            }

            # Add local-only skipped checks info for remote servers
            if local_only_skipped:
                result["local_only_checks_skipped"] = local_only_skipped
                result["local_only_note"] = (
                    f"Skipped {len(local_only_skipped)} check(s) that require local server access. "
                    "Configure the server with is_local=True and serverid=<instance> to enable these checks."
                )

            return result

        except Exception as e:
            mcp.logger.error("run_healthcheck failed: %s", e)
            return {
                "type": "healthcheck",
                "server": target,
                "error": str(e),
                "summary": f"FAILED: Health check could not complete - {e}",
                "findings": [
                    format_finding(
                        title="Health Check Failed",
                        severity=Severity.CRITICAL,
                        impact="Unable to complete health check",
                        details=str(e),
                        remediation="Verify server connectivity and check server logs",
                        server=target,
                    )
                ],
            }
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

    # Add success indicator if no critical issues were found for this server
    server_findings = [f for f in findings if f.get("server") == server_name]
    critical_count = sum(1 for f in server_findings if f.get("severity") == "critical")
    high_count = sum(1 for f in server_findings if f.get("severity") == "high")

    if critical_count == 0 and high_count == 0:
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


def _check_connection_limits(
    mcp: DirSrvMCP,
    monitor_data: Dict[str, Any],
    server_name: str,
    findings: List[Dict[str, Any]],
) -> None:
    """Check if connection limits are approaching capacity."""
    try:
        current_conns = int(monitor_data.get("currentconnections", [0])[0])
        max_conns = int(monitor_data.get("maxconnections", [0])[0])
        if max_conns <= 0:
            return
        utilization = (current_conns / max_conns) * 100
        if utilization >= 90:
            severity = Severity.CRITICAL
            title = f"Connection Limit Critical: {server_name}"
        elif utilization >= 75:
            severity = Severity.HIGH
            title = f"Connection Limit Warning: {server_name}"
        else:
            return
        findings.append(
            format_finding(
                title=title,
                severity=severity,
                impact="Server approaching maximum connections",
                details=f"Current connections: {current_conns} / {max_conns} ({utilization:.1f}% utilization)",
                remediation="Review connection usage and increase limits if necessary",
                server=server_name,
                metadata={
                    "current": current_conns,
                    "max": max_conns,
                    "utilization": utilization,
                },
            )
        )
    except (KeyError, ValueError, IndexError):
        mcp.logger.debug("Could not check connection limits for %s", server_name)


def _check_threads(
    mcp: DirSrvMCP,
    monitor_data: Dict[str, Any],
    server_name: str,
    findings: List[Dict[str, Any]],
) -> None:
    """Check if thread count is concerning."""
    try:
        threads = int(monitor_data.get("threads", [0])[0])
        if 0 < threads < 5:
            findings.append(
                format_finding(
                    title=f"Low Thread Count: {server_name}",
                    severity=Severity.MEDIUM,
                    impact="Server may have reduced capacity to handle concurrent requests",
                    details=f"Only {threads} worker threads active",
                    remediation="Check server configuration and resource availability (CPU, memory)",
                    server=server_name,
                    metadata={"threads": threads},
                )
            )
    except (KeyError, ValueError, IndexError):
        mcp.logger.debug("Could not check threads for %s", server_name)


def _safe_int(value: Any, default: int = 0) -> int:
    """Safely convert a value to int."""
    if value is None:
        return default
    if isinstance(value, list):
        value = value[0] if value else default
    try:
        return int(value)
    except (ValueError, TypeError):
        return default


def _safe_float(value: Any, default: float = 0.0) -> float:
    """Safely convert a value to float."""
    if value is None:
        return default
    if isinstance(value, list):
        value = value[0] if value else default
    try:
        return float(value)
    except (ValueError, TypeError):
        return default


def _format_bytes(bytes_val: int) -> str:
    """Format bytes into human-readable string."""
    for unit in ['B', 'KB', 'MB', 'GB', 'TB']:
        if abs(bytes_val) < 1024.0:
            return f"{bytes_val:.1f} {unit}"
        bytes_val /= 1024.0
    return f"{bytes_val:.1f} PB"


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
                role = replica.get_role()
                agreements = replica.get_agreements()

                for agmt in agreements.list():
                    agmt_name = agmt.get_attr_val_utf8("cn")
                    consumer = agmt.get_attr_val_utf8("nsDS5ReplicaHost")
                    last_result = agmt.get_attr_val_utf8("nsds5replicaLastUpdateStatus") or ""
                    last_update = agmt.get_attr_val_utf8("nsds5replicaLastUpdateEnd") or ""

                    agmt_info = {
                        "name": agmt_name,
                        "consumer": consumer,
                        "suffix": suffix,
                    }
                    metrics["replication"]["agreements"].append(agmt_info)

                    # Check for replication errors
                    if last_result:
                        # Error status typically starts with "Error" or has non-zero code
                        is_error = (
                            "error" in last_result.lower() or
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

    except Exception as e:
        mcp.logger.debug("Could not check replication for %s: %s", server_name, e)
        metrics["replication"] = {"configured": False, "error": str(e)}


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

                entry_hits = _safe_int(be_status.get("entrycachehits"))
                entry_tries = _safe_int(be_status.get("entrycachetries"))
                entry_ratio = _safe_float(be_status.get("entrycachehitratio"))

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
                            remediation=f"Consider increasing nsslapd-cachememsize for backend {be_name}",
                            server=server_name,
                            metadata={"backend": be_name, "hit_ratio": entry_ratio},
                        )
                    )

            except Exception as e:
                mcp.logger.debug("Error checking cache for backend %s: %s", be_name, e)

        if low_hit_ratio_count > 0:
            cache_metrics["overall_health"] = "degraded"

        metrics["cache"] = cache_metrics

    except Exception as e:
        mcp.logger.debug("Could not check cache for %s: %s", server_name, e)
        metrics["cache"] = {"error": str(e)}


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
            # Parse disk info string
            parts = disk.split()
            disk_entry = {}
            for part in parts:
                if "=" in part:
                    key, val = part.split("=", 1)
                    disk_entry[key.lower()] = val.strip('"')

            partition = disk_entry.get("partition", "unknown")
            pct = _safe_int(disk_entry.get("percent", "0"))
            size = disk_entry.get("size", "unknown")
            avail = disk_entry.get("avail", "unknown")

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
        metrics["disk"] = {"available": False, "error": str(e)}


def _check_certificate_health(
    mcp: DirSrvMCP,
    ds,
    server_name: str,
    findings: List[Dict[str, Any]],
    metrics: Dict[str, Any],
    is_local: bool = True,
) -> None:
    """Check SSL certificate expiration.

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
        certs = []

        # Try to get server cert info
        try:
            server_cert = nss_ssl.get_server_cert()
            if server_cert:
                # Parse certificate details
                subject = server_cert.get("subject", "Unknown")
                not_after = server_cert.get("not_after")

                cert_info = {
                    "subject": subject,
                    "type": "server",
                }

                if not_after:
                    try:
                        # Parse expiration date
                        if isinstance(not_after, str):
                            # Try common date formats
                            for fmt in ["%Y-%m-%d %H:%M:%S", "%b %d %H:%M:%S %Y %Z"]:
                                try:
                                    exp_date = datetime.strptime(not_after, fmt)
                                    if exp_date.tzinfo is None:
                                        exp_date = exp_date.replace(tzinfo=timezone.utc)
                                    break
                                except ValueError:
                                    continue
                            else:
                                exp_date = None
                        else:
                            exp_date = not_after

                        if exp_date:
                            now = datetime.now(timezone.utc)
                            days_until = (exp_date - now).days
                            cert_info["expires"] = str(not_after)
                            cert_info["days_until_expiry"] = days_until

                            if days_until < 0:
                                findings.append(
                                    format_finding(
                                        title="SSL Certificate Expired",
                                        severity=Severity.CRITICAL,
                                        impact="Server certificate has expired - clients may reject connections",
                                        details=f"Certificate expired {abs(days_until)} days ago",
                                        remediation="Renew the SSL certificate immediately",
                                        server=server_name,
                                        metadata={"days_expired": abs(days_until)},
                                    )
                                )
                            elif days_until <= 30:
                                findings.append(
                                    format_finding(
                                        title="SSL Certificate Expiring Soon",
                                        severity=Severity.HIGH if days_until <= 7 else Severity.MEDIUM,
                                        impact=f"Server certificate expires in {days_until} days",
                                        details=f"Expiration: {not_after}",
                                        remediation="Plan certificate renewal before expiration",
                                        server=server_name,
                                        metadata={"days_until_expiry": days_until},
                                    )
                                )
                    except Exception as e:
                        mcp.logger.debug("Error parsing cert date: %s", e)

                certs.append(cert_info)

        except Exception as e:
            mcp.logger.debug("Could not get server cert: %s", e)

        metrics["certificates"] = {"available": True, "certs": certs} if certs else {"available": True, "status": "no certificates found"}

    except Exception as e:
        mcp.logger.debug("Could not check certificates for %s: %s", server_name, e)
        metrics["certificates"] = {"available": False, "error": str(e)}


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

        # Get specific attributes
        try:
            status = monitor.get_attrs_vals_utf8([
                'currentconnections', 'totalconnections', 'dtablesize',
                'threads', 'currentconnectionsatmaxthreads', 'opsinitiated', 'opscompleted'
            ])
        except Exception:
            status = {}

        current_conns = _safe_int(status.get("currentconnections"))
        total_conns = _safe_int(status.get("totalconnections"))
        dtable_size = _safe_int(status.get("dtablesize"))
        threads = _safe_int(status.get("threads"))
        conns_at_max = _safe_int(status.get("currentconnectionsatmaxthreads"))
        ops_initiated = _safe_int(status.get("opsinitiated"))
        ops_completed = _safe_int(status.get("opscompleted"))

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
                    remediation="Increase nsslapd-maxdescriptors or investigate connection leaks",
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
                    remediation="Increase nsslapd-threadnumber",
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
        metrics["connections"] = {"error": str(e)}

