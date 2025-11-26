"""Health check tools for 389 Directory Server."""

from __future__ import annotations

from typing import TYPE_CHECKING, Any, Dict, List

from lib389.monitor import Monitor

from src.lib.result_formatter import Severity, format_finding

if TYPE_CHECKING:
    from src.dirsrv_mcp.connection import ServerConfig
    from src.dirsrv_mcp.server import DirSrvMCP


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

