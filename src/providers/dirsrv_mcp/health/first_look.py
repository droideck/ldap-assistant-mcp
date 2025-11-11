"""First Look - Quick health overview across all configured servers."""

import logging
from typing import Dict, Any, List
from src.lib.result_formatter import format_finding, Severity
from ..connection import get_connection_manager

logger = logging.getLogger(__name__)


def first_look() -> Dict[str, Any]:
    """
    Quick health overview across all configured servers.

    This tool provides a rapid assessment of the entire LDAP topology,
    identifying critical issues that require immediate attention. It's
    designed for the support engineer workflow: "What's wrong?" is
    answered first, with prioritized findings.

    The tool checks:
    - Server connectivity
    - Basic operational status
    - Critical resource indicators (from monitor data)

    Returns:
        Dict containing:
            - summary: High-level health status
            - critical_count: Number of critical findings
            - high_count: Number of high severity findings
            - findings: List of findings with severity/impact/remediation
            - servers_checked: List of servers that were checked
            - servers_failed: List of servers that couldn't be checked

    Examples:
        >>> result = first_look()
        >>> print(f"Found {result['critical_count']} critical issues")
        >>> for finding in result['findings']:
        ...     print(f"[{finding['severity']}] {finding['title']}")
    """
    manager = get_connection_manager()
    server_names = manager.get_server_names()

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
                    details="The LDAP Assistant has no servers configured. "
                            "Please configure at least one server via environment variables "
                            "or a JSON configuration file.",
                    remediation="1. Set LDAP_URL, LDAP_BASE_DN, LDAP_BIND_DN, and "
                                "LDAP_BIND_PASSWORD environment variables for single-server mode, OR "
                                "2. Create a servers.json config file and set LDAP_SERVERS_CONFIG "
                                "environment variable to point to it."
                )
            ],
            "servers_checked": [],
            "servers_failed": []
        }

    logger.info(f"Running first_look health check across {len(server_names)} servers")

    findings: List[Dict[str, Any]] = []
    servers_checked: List[str] = []
    servers_failed: List[str] = []

    # Check each server
    for server_name in server_names:
        try:
            config = manager.get_config(server_name)
            logger.info(f"Checking server: {server_name} ({config.ldap_url})")

            # Try to connect
            try:
                ds = manager.connect(server_name)
                servers_checked.append(server_name)

                # Perform basic health checks
                _check_server_health(ds, server_name, config, findings)

            except Exception as conn_error:
                servers_failed.append(server_name)
                findings.append(
                    format_finding(
                        title=f"Server Connection Failed: {server_name}",
                        severity=Severity.CRITICAL,
                        impact=f"Cannot access directory data on {server_name}. "
                                f"Users and applications may be unable to authenticate or access directory services.",
                        details=f"Failed to connect to {config.ldap_url}: {str(conn_error)}",
                        remediation=f"1. Verify the server at {config.ldap_url} is running\n"
                                    f"2. Check network connectivity to the server\n"
                                    f"3. Verify bind credentials are correct\n"
                                    f"4. Check firewall rules and security groups",
                        server=server_name,
                        metadata={"url": config.ldap_url, "error": str(conn_error)}
                    )
                )

        except Exception as e:
            logger.error(f"Error processing server {server_name}: {str(e)}")
            servers_failed.append(server_name)
            findings.append(
                format_finding(
                    title=f"Server Check Failed: {server_name}",
                    severity=Severity.HIGH,
                    impact=f"Unable to complete health check for {server_name}",
                    details=f"Unexpected error during health check: {str(e)}",
                    remediation="Check server configuration and logs for more details",
                    server=server_name
                )
            )

    # Count findings by severity
    severity_counts = {
        "critical": 0,
        "high": 0,
        "medium": 0,
        "low": 0,
        "info": 0
    }

    for finding in findings:
        severity = finding.get("severity", "info")
        if severity in severity_counts:
            severity_counts[severity] += 1

    # Generate summary
    total_issues = sum(severity_counts.values())
    if severity_counts["critical"] > 0:
        summary = f"CRITICAL: {severity_counts['critical']} critical issue(s) found across {len(server_names)} servers"
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
        "total_servers": len(server_names)
    }

    logger.info(f"first_look completed: {summary}")
    return result


def _check_server_health(ds, server_name: str, config, findings: List[Dict[str, Any]]) -> None:
    """
    Perform health checks on a connected server.

    Args:
        ds: Connected DirSrv instance
        server_name: Name of the server being checked
        config: ServerConfig for the server
        findings: List to append findings to
    """
    try:
        from lib389.monitor import Monitor

        # Get server monitor data
        monitor = Monitor(ds)
        monitor_data = monitor.get_all_attrs()

        # Check various health indicators
        _check_connection_limits(monitor_data, server_name, findings)
        _check_threads(monitor_data, server_name, findings)

        # Info finding for successful check
        findings.append(
            format_finding(
                title=f"Server {server_name} is operational",
                severity=Severity.INFO,
                impact="Server is responding to queries",
                details=f"Successfully connected and retrieved monitor data from {config.ldap_url}",
                remediation="No action needed",
                server=server_name
            )
        )

    except Exception as e:
        logger.warning(f"Error checking server health for {server_name}: {str(e)}")
        findings.append(
            format_finding(
                title=f"Partial Health Check Failure: {server_name}",
                severity=Severity.MEDIUM,
                impact="Unable to retrieve complete health information",
                details=f"Connected successfully but failed to retrieve monitor data: {str(e)}",
                remediation="Check server logs and verify monitoring endpoints are accessible",
                server=server_name
            )
        )


def _check_connection_limits(monitor_data: Dict, server_name: str, findings: List[Dict[str, Any]]) -> None:
    """Check if server is approaching connection limits."""
    try:
        current_conns = int(monitor_data.get('currentconnections', [0])[0])
        max_conns = int(monitor_data.get('maxconnections', [0])[0])

        if max_conns > 0:
            utilization = (current_conns / max_conns) * 100

            if utilization >= 90:
                findings.append(
                    format_finding(
                        title=f"Connection Limit Critical: {server_name}",
                        severity=Severity.CRITICAL,
                        impact="Server may start rejecting new connections, causing authentication failures",
                        details=f"Current connections: {current_conns} / {max_conns} ({utilization:.1f}% utilization)",
                        remediation=f"1. Review and increase nsslapd-maxdescriptors in cn=config\n"
                                    f"2. Check for connection leaks in client applications\n"
                                    f"3. Restart idle/hung connections",
                        server=server_name,
                        metadata={"current": current_conns, "max": max_conns, "utilization": utilization}
                    )
                )
            elif utilization >= 75:
                findings.append(
                    format_finding(
                        title=f"Connection Limit Warning: {server_name}",
                        severity=Severity.HIGH,
                        impact="Server approaching maximum connections",
                        details=f"Current connections: {current_conns} / {max_conns} ({utilization:.1f}% utilization)",
                        remediation=f"Monitor connection usage and consider increasing limits if trend continues",
                        server=server_name,
                        metadata={"current": current_conns, "max": max_conns, "utilization": utilization}
                    )
                )

    except (KeyError, ValueError, IndexError) as e:
        logger.debug(f"Could not check connection limits for {server_name}: {str(e)}")


def _check_threads(monitor_data: Dict, server_name: str, findings: List[Dict[str, Any]]) -> None:
    """Check thread status."""
    try:
        threads = int(monitor_data.get('threads', [0])[0])

        # Very low thread count might indicate a problem
        if 0 < threads < 5:
            findings.append(
                format_finding(
                    title=f"Low Thread Count: {server_name}",
                    severity=Severity.MEDIUM,
                    impact="Server may have reduced capacity to handle concurrent requests",
                    details=f"Only {threads} worker threads active",
                    remediation="Check server configuration and resource availability (CPU, memory)",
                    server=server_name,
                    metadata={"threads": threads}
                )
            )

    except (KeyError, ValueError, IndexError) as e:
        logger.debug(f"Could not check threads for {server_name}: {str(e)}")
