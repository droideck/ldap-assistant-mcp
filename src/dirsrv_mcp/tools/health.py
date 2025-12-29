"""Health check tools for 389 Directory Server."""

from __future__ import annotations

import copy
import re
from typing import TYPE_CHECKING, Any, Dict, List, Optional

from lib389 import lint
from lib389.backend import Backends
from lib389.config import Config, Encryption
from lib389.dirsrv_log import DirsrvAccessLog
from lib389.dseldif import DSEldif, FSChecks
from lib389.monitor import Monitor, MonitorDiskSpace
from lib389.nss_ssl import NssSsl
from lib389.plugins import MemberOfPlugin, ReferentialIntegrityPlugin
from lib389.replica import Replica
from lib389.tunables import Tunables

from src.lib.result_formatter import Severity, format_finding

if TYPE_CHECKING:
    from src.dirsrv_mcp.connection import ServerConfig
    from src.dirsrv_mcp.server import DirSrvMCP


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
        """Quick health overview across all configured LDAP servers."""
        server_names = mcp.connection_manager.get_server_names()

        if not server_names:
            return {
                "type": "first_look",
                "summary": "No servers configured",
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
            }

        findings: List[Dict[str, Any]] = []
        servers_checked: List[str] = []
        servers_failed: List[str] = []

        for server_name in server_names:
            ds = None
            try:
                config = mcp.connection_manager.get_config(server_name)
                ds = mcp.connection_manager.connect(server_name)
                servers_checked.append(server_name)
                _check_server_health(mcp, ds, server_name, config, findings)
            except Exception as exc:
                servers_failed.append(server_name)
                severity = Severity.CRITICAL if "connect" in str(exc).lower() else Severity.HIGH
                findings.append(
                    format_finding(
                        title=f"Server Check Failed: {server_name}",
                        severity=severity,
                        impact=f"Unable to complete health check for {server_name}",
                        details=str(exc),
                        remediation="Verify server connectivity and credentials",
                        server=server_name,
                    )
                )
            finally:
                if ds is not None:
                    try:
                        ds.close()
                    except Exception:
                        pass

        severity_counts = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}
        for finding in findings:
            severity = finding.get("severity", "info")
            if severity in severity_counts:
                severity_counts[severity] += 1

        total_issues = sum(severity_counts.values())
        if severity_counts["critical"] > 0:
            summary = (
                f"CRITICAL: {severity_counts['critical']} critical issue(s) found "
                f"across {len(server_names)} servers"
            )
        elif severity_counts["high"] > 0:
            summary = f"WARNING: {severity_counts['high']} high-priority issue(s) found"
        elif total_issues > 0:
            summary = f"OK: {total_issues} minor issue(s) found"
        else:
            summary = f"HEALTHY: All {len(servers_checked)} servers are operating normally"

        result = {
            "type": "first_look",
            "summary": summary,
            "critical_count": severity_counts["critical"],
            "high_count": severity_counts["high"],
            "medium_count": severity_counts["medium"],
            "low_count": severity_counts["low"],
            "info_count": severity_counts["info"],
            "findings": findings,
            "servers_checked": servers_checked,
            "servers_failed": servers_failed,
            "total_servers": len(server_names),
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

            return {
                "type": "healthcheck",
                "server": target,
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
) -> None:
    """Check health metrics for a single server."""
    try:
        monitor = Monitor(ds)
        monitor_data = monitor.get_all_attrs()
        _check_connection_limits(mcp, monitor_data, server_name, findings)
        _check_threads(mcp, monitor_data, server_name, findings)
        findings.append(
            format_finding(
                title=f"Server {server_name} is operational",
                severity=Severity.INFO,
                impact="Server is responding to queries",
                details=f"Successfully connected and retrieved monitor data from {config.ldap_url}",
                remediation="No action needed",
                server=server_name,
            )
        )
    except Exception as exc:
        mcp.logger.warning("Error checking server health for %s: %s", server_name, exc)
        findings.append(
            format_finding(
                title=f"Partial Health Check Failure: {server_name}",
                severity=Severity.MEDIUM,
                impact="Unable to retrieve complete health information",
                details=f"Connected successfully but failed to retrieve monitor data: {exc}",
                remediation="Check server logs and verify monitoring endpoints are accessible",
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

