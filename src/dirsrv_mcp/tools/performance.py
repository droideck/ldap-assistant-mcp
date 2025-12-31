"""Performance diagnostic tools for 389 Directory Server.

This module provides comprehensive performance monitoring and diagnostic capabilities
including cache analysis, connection statistics, operation metrics, thread utilization,
and resource usage analysis.

Note on local vs remote servers:
- Most metrics are available via LDAP from cn=monitor and work for remote servers
- Some metrics require local server access (is_local=True with serverid):
  - Process memory/CPU usage (via psutil)
  - Disk space monitoring (via MonitorDiskSpace)
  - Connection state details (ESTABLISHED, CLOSE_WAIT, etc.)

When a server is remote, these local-only metrics will show as unavailable
rather than failing the entire tool.
"""

from __future__ import annotations

from typing import TYPE_CHECKING, Any, Dict, List, Optional

from lib389.backend import Backends
from lib389.monitor import Monitor, MonitorLDBM, MonitorDiskSpace, MonitorSNMP

from src.dirsrv_mcp.connection import is_local_server
from src.lib.result_formatter import Severity, format_finding

if TYPE_CHECKING:
    from src.dirsrv_mcp.server import DirSrvMCP


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


def _calculate_hit_ratio(hits: int, tries: int) -> float:
    """Calculate cache hit ratio as percentage."""
    if tries == 0:
        return 0.0
    return round((hits / tries) * 100, 2)


def _assess_cache_health(hit_ratio: float) -> tuple[str, Severity]:
    """Assess cache health based on hit ratio."""
    if hit_ratio >= 95:
        return "excellent", Severity.INFO
    elif hit_ratio >= 85:
        return "good", Severity.INFO
    elif hit_ratio >= 70:
        return "acceptable", Severity.LOW
    elif hit_ratio >= 50:
        return "poor", Severity.MEDIUM
    else:
        return "critical", Severity.HIGH


def _format_bytes(bytes_val: int) -> str:
    """Format bytes into human-readable string."""
    for unit in ['B', 'KB', 'MB', 'GB', 'TB']:
        if abs(bytes_val) < 1024.0:
            return f"{bytes_val:.2f} {unit}"
        bytes_val /= 1024.0
    return f"{bytes_val:.2f} PB"


def register_performance_tools(mcp: DirSrvMCP) -> None:
    """Register performance diagnostic tools with the MCP server."""

    @mcp.tool()
    def get_cache_statistics(
        backend: Optional[str] = None,
        server_name: Optional[str] = None,
    ) -> Dict[str, Any]:
        """Analyze database and entry cache efficiency.

        Returns comprehensive cache statistics including entry cache,
        DN cache, and database cache with health assessments.

        Args:
            backend: Specific backend to analyze (e.g., 'userroot').
                    If not specified, analyzes all backends.
            server_name: Target server name. Uses default if not specified.

        Returns:
            Cache analysis including:
            - Entry cache hit ratio and utilization
            - DN cache statistics
            - Database cache metrics
            - Normalized DN cache stats
            - Health assessment and recommendations
        """
        target = server_name or mcp.default_server
        if not target:
            return {
                "type": "cache_statistics",
                "error": "No server configured",
            }

        ds = None
        try:
            ds = mcp.connection_manager.connect(target)
            findings: List[Dict[str, Any]] = []
            cache_data = {
                "type": "cache_statistics",
                "server": target,
                "global_db_cache": {},
                "backends": [],
            }

            # Get global database cache statistics
            try:
                ldbm_monitor = MonitorLDBM(ds)
                ldbm_status = ldbm_monitor.get_status()

                # Database cache (BDB) or normalized DN cache (LMDB)
                db_cache = {}

                # BDB-specific cache
                if "dbcachehits" in ldbm_status:
                    hits = _safe_int(ldbm_status.get("dbcachehits"))
                    tries = _safe_int(ldbm_status.get("dbcachetries"))
                    ratio = _safe_float(ldbm_status.get("dbcachehitratio"))
                    if ratio == 0 and tries > 0:
                        ratio = _calculate_hit_ratio(hits, tries)

                    db_cache = {
                        "type": "bdb",
                        "hits": hits,
                        "tries": tries,
                        "hit_ratio": ratio,
                        "page_in": _safe_int(ldbm_status.get("dbcachepagein")),
                        "page_out": _safe_int(ldbm_status.get("dbcachepageout")),
                        "ro_evictions": _safe_int(ldbm_status.get("dbcacheroevict")),
                        "rw_evictions": _safe_int(ldbm_status.get("dbcacherwevict")),
                    }

                    health, severity = _assess_cache_health(ratio)
                    db_cache["health"] = health

                    if severity in [Severity.MEDIUM, Severity.HIGH]:
                        findings.append(
                            format_finding(
                                title="Low Database Cache Hit Ratio",
                                severity=severity,
                                impact=f"Database cache hit ratio is {ratio}% - frequent disk reads slow operations",
                                details=f"Hits: {hits}, Tries: {tries}, Evictions: {db_cache['ro_evictions'] + db_cache['rw_evictions']}",
                                remediation="Consider increasing nsslapd-dbcachesize in cn=config,cn=ldbm database,cn=plugins,cn=config",
                                server=target,
                                metadata={"hit_ratio": ratio, "tries": tries},
                            )
                        )

                # LMDB doesn't have traditional db cache, but has normalized DN cache
                if "normalizeddncachehits" in ldbm_status:
                    ndn_hits = _safe_int(ldbm_status.get("normalizeddncachehits"))
                    ndn_tries = _safe_int(ldbm_status.get("normalizeddncachetries"))
                    ndn_ratio = _safe_float(ldbm_status.get("normalizeddncachehitratio"))
                    if ndn_ratio == 0 and ndn_tries > 0:
                        ndn_ratio = _calculate_hit_ratio(ndn_hits, ndn_tries)

                    db_cache["normalized_dn_cache"] = {
                        "hits": ndn_hits,
                        "tries": ndn_tries,
                        "misses": _safe_int(ldbm_status.get("normalizeddncachemisses")),
                        "hit_ratio": ndn_ratio,
                        "evictions": _safe_int(ldbm_status.get("normalizeddncacheevictions")),
                        "current_size": _safe_int(ldbm_status.get("currentnormalizeddncachesize")),
                        "max_size": _safe_int(ldbm_status.get("maxnormalizeddncachesize")),
                        "current_count": _safe_int(ldbm_status.get("currentnormalizeddncachecount")),
                    }

                cache_data["global_db_cache"] = db_cache

            except Exception as e:
                mcp.logger.warning("Error getting LDBM monitor: %s", e)
                cache_data["global_db_cache"] = {"error": str(e)}

            # Get per-backend cache statistics
            try:
                backends_obj = Backends(ds)
                for be in backends_obj.list():
                    be_name = be.get_attr_val_utf8("cn")

                    # Filter by backend name if specified
                    if backend and be_name.lower() != backend.lower():
                        continue

                    try:
                        be_monitor = be.get_monitor()
                        be_status = be_monitor.get_status()

                        # Entry cache
                        entry_hits = _safe_int(be_status.get("entrycachehits"))
                        entry_tries = _safe_int(be_status.get("entrycachetries"))
                        entry_ratio = _safe_float(be_status.get("entrycachehitratio"))
                        if entry_ratio == 0 and entry_tries > 0:
                            entry_ratio = _calculate_hit_ratio(entry_hits, entry_tries)

                        entry_current_size = _safe_int(be_status.get("currententrycachesize"))
                        entry_max_size = _safe_int(be_status.get("maxentrycachesize"))
                        entry_current_count = _safe_int(be_status.get("currententrycachecount"))
                        entry_max_count = _safe_int(be_status.get("maxentrycachecount"))

                        entry_cache = {
                            "hits": entry_hits,
                            "tries": entry_tries,
                            "hit_ratio": entry_ratio,
                            "current_size": entry_current_size,
                            "current_size_human": _format_bytes(entry_current_size),
                            "max_size": entry_max_size,
                            "max_size_human": _format_bytes(entry_max_size),
                            "current_count": entry_current_count,
                            "max_count": entry_max_count,
                            "utilization_pct": round((entry_current_size / entry_max_size * 100), 2) if entry_max_size > 0 else 0,
                        }

                        health, severity = _assess_cache_health(entry_ratio)
                        entry_cache["health"] = health

                        if severity in [Severity.MEDIUM, Severity.HIGH] and entry_tries > 1000:
                            findings.append(
                                format_finding(
                                    title=f"Low Entry Cache Hit Ratio: {be_name}",
                                    severity=severity,
                                    impact=f"Entry cache hit ratio for {be_name} is {entry_ratio}% - entries frequently read from disk",
                                    details=f"Hits: {entry_hits}, Tries: {entry_tries}, Utilization: {entry_cache['utilization_pct']}%",
                                    remediation=f"Consider increasing nsslapd-cachememsize for backend {be_name}",
                                    server=target,
                                    metadata={"backend": be_name, "hit_ratio": entry_ratio},
                                )
                            )

                        # DN cache
                        dn_hits = _safe_int(be_status.get("dncachehits"))
                        dn_tries = _safe_int(be_status.get("dncachetries"))
                        dn_ratio = _safe_float(be_status.get("dncachehitratio"))
                        if dn_ratio == 0 and dn_tries > 0:
                            dn_ratio = _calculate_hit_ratio(dn_hits, dn_tries)

                        dn_cache = {
                            "hits": dn_hits,
                            "tries": dn_tries,
                            "hit_ratio": dn_ratio,
                            "current_size": _safe_int(be_status.get("currentdncachesize")),
                            "max_size": _safe_int(be_status.get("maxdncachesize")),
                            "current_count": _safe_int(be_status.get("currentdncachecount")),
                            "max_count": _safe_int(be_status.get("maxdncachecount")),
                        }

                        backend_data = {
                            "name": be_name,
                            "suffix": be.get_attr_val_utf8("nsslapd-suffix"),
                            "entry_cache": entry_cache,
                            "dn_cache": dn_cache,
                        }

                        cache_data["backends"].append(backend_data)

                    except Exception as e:
                        mcp.logger.warning("Error getting monitor for backend %s: %s", be_name, e)
                        cache_data["backends"].append({"name": be_name, "error": str(e)})

            except Exception as e:
                mcp.logger.warning("Error listing backends: %s", e)

            # Generate summary
            if findings:
                summary = f"ATTENTION: {len(findings)} cache issue(s) detected"
            elif cache_data["backends"]:
                avg_ratio = sum(
                    b.get("entry_cache", {}).get("hit_ratio", 0)
                    for b in cache_data["backends"]
                    if "entry_cache" in b
                ) / len([b for b in cache_data["backends"] if "entry_cache" in b])
                summary = f"HEALTHY: Average entry cache hit ratio {avg_ratio:.1f}% across {len(cache_data['backends'])} backend(s)"
            else:
                summary = "No backend cache data available"

            cache_data["summary"] = summary
            cache_data["findings"] = findings

            return cache_data

        except Exception as e:
            mcp.logger.error("Error getting cache statistics: %s", e)
            return {
                "type": "cache_statistics",
                "server": target,
                "error": str(e),
            }
        finally:
            if ds:
                try:
                    ds.close()
                except Exception:
                    pass

    @mcp.tool()
    def get_connection_statistics(server_name: Optional[str] = None) -> Dict[str, Any]:
        """Analyze connection patterns and resource usage.

        Returns detailed connection statistics including current connections,
        connection history, and connection state analysis.

        Args:
            server_name: Target server name. Uses default if not specified.

        Returns:
            Connection analysis including:
            - Current vs max connections
            - Total connections since startup
            - Connection state breakdown (established, waiting, etc.)
            - File descriptor utilization
            - Recommendations for tuning
        """
        target = server_name or mcp.default_server
        if not target:
            return {
                "type": "connection_statistics",
                "error": "No server configured",
            }

        ds = None
        try:
            ds = mcp.connection_manager.connect(target)
            monitor = Monitor(ds)
            findings: List[Dict[str, Any]] = []

            # Get basic connection stats from cn=monitor
            try:
                status = monitor.get_attrs_vals_utf8([
                    'currentconnections', 'totalconnections', 'dtablesize', 'readwaiters'
                ])
            except Exception as e:
                mcp.logger.warning("Error getting monitor status: %s", e)
                status = {}

            current_conns = _safe_int(status.get("currentconnections"))
            total_conns = _safe_int(status.get("totalconnections"))
            dtable_size = _safe_int(status.get("dtablesize"))
            read_waiters = _safe_int(status.get("readwaiters"))

            # Connection state from resource stats (may fail for remote connections)
            try:
                resource_stats = monitor.get_resource_stats()
                conn_count = _safe_int(resource_stats.get("connection_count"))
                conn_established = _safe_int(resource_stats.get("connection_established_count"))
                conn_close_wait = _safe_int(resource_stats.get("connection_close_wait_count"))
                conn_time_wait = _safe_int(resource_stats.get("connection_time_wait_count"))
            except Exception as e:
                mcp.logger.debug("Resource stats unavailable (remote connection): %s", e)
                conn_count = 0
                conn_established = 0
                conn_close_wait = 0
                conn_time_wait = 0

            # Calculate utilization
            fd_utilization = round((current_conns / dtable_size * 100), 2) if dtable_size > 0 else 0

            conn_data = {
                "type": "connection_statistics",
                "server": target,
                "current_connections": current_conns,
                "total_connections": total_conns,
                "max_file_descriptors": dtable_size,
                "fd_utilization_pct": fd_utilization,
                "read_waiters": read_waiters,
                "connection_states": {
                    "total": conn_count,
                    "established": conn_established,
                    "close_wait": conn_close_wait,
                    "time_wait": conn_time_wait,
                },
            }

            # Check for connection issues
            if fd_utilization > 80:
                findings.append(
                    format_finding(
                        title="High File Descriptor Utilization",
                        severity=Severity.HIGH,
                        impact=f"Server is using {fd_utilization}% of available file descriptors",
                        details=f"Current: {current_conns}, Max: {dtable_size}",
                        remediation="Increase nsslapd-maxdescriptors or investigate connection leaks",
                        server=target,
                        metadata={"utilization": fd_utilization, "current": current_conns},
                    )
                )
            elif fd_utilization > 60:
                findings.append(
                    format_finding(
                        title="Elevated File Descriptor Usage",
                        severity=Severity.MEDIUM,
                        impact=f"Server is using {fd_utilization}% of file descriptors",
                        details=f"Current: {current_conns}, Max: {dtable_size}",
                        remediation="Monitor connection growth; consider increasing nsslapd-maxdescriptors",
                        server=target,
                        metadata={"utilization": fd_utilization},
                    )
                )

            if read_waiters > 10:
                findings.append(
                    format_finding(
                        title="Connections Waiting for Read",
                        severity=Severity.MEDIUM,
                        impact=f"{read_waiters} connections waiting - potential bottleneck",
                        details="Read waiters indicate clients waiting for server response",
                        remediation="Check server load, consider adding more worker threads",
                        server=target,
                        metadata={"read_waiters": read_waiters},
                    )
                )

            if conn_close_wait > 50:
                findings.append(
                    format_finding(
                        title="High CLOSE_WAIT Connections",
                        severity=Severity.MEDIUM,
                        impact=f"{conn_close_wait} connections in CLOSE_WAIT state",
                        details="May indicate clients not properly closing connections",
                        remediation="Investigate client applications for connection handling issues",
                        server=target,
                        metadata={"close_wait": conn_close_wait},
                    )
                )

            # Generate summary
            if findings:
                summary = f"ATTENTION: {len(findings)} connection issue(s) detected"
            else:
                summary = f"HEALTHY: {current_conns} active connections ({fd_utilization}% of max)"

            conn_data["summary"] = summary
            conn_data["findings"] = findings

            return conn_data

        except Exception as e:
            mcp.logger.error("Error getting connection statistics: %s", e)
            return {
                "type": "connection_statistics",
                "server": target,
                "error": str(e),
            }
        finally:
            if ds:
                try:
                    ds.close()
                except Exception:
                    pass

    @mcp.tool()
    def get_operation_statistics(server_name: Optional[str] = None) -> Dict[str, Any]:
        """Get operation counts and performance metrics.

        Returns comprehensive operation statistics including counts by type,
        bind patterns, and search operation breakdown.

        Args:
            server_name: Target server name. Uses default if not specified.

        Returns:
            Operation metrics including:
            - Operations initiated vs completed
            - Operation breakdown by type (search, bind, modify, etc.)
            - Entries sent and bytes transferred
            - Bind method distribution
        """
        target = server_name or mcp.default_server
        if not target:
            return {
                "type": "operation_statistics",
                "error": "No server configured",
            }

        ds = None
        try:
            ds = mcp.connection_manager.connect(target)
            monitor = Monitor(ds)
            findings: List[Dict[str, Any]] = []

            # Get basic operation stats from cn=monitor
            try:
                status = monitor.get_attrs_vals_utf8([
                    'opsinitiated', 'opscompleted', 'entriessent', 'bytessent'
                ])
            except Exception as e:
                mcp.logger.warning("Error getting monitor status: %s", e)
                status = {}

            ops_initiated = _safe_int(status.get("opsinitiated"))
            ops_completed = _safe_int(status.get("opscompleted"))
            entries_sent = _safe_int(status.get("entriessent"))
            bytes_sent = _safe_int(status.get("bytessent"))

            ops_pending = ops_initiated - ops_completed

            op_data = {
                "type": "operation_statistics",
                "server": target,
                "operations_initiated": ops_initiated,
                "operations_completed": ops_completed,
                "operations_pending": ops_pending,
                "entries_sent": entries_sent,
                "bytes_sent": bytes_sent,
                "bytes_sent_human": _format_bytes(bytes_sent),
            }

            # Get SNMP stats for detailed operation breakdown
            try:
                snmp_monitor = MonitorSNMP(ds)
                snmp_status = snmp_monitor.get_status()

                op_data["operation_breakdown"] = {
                    "binds": {
                        "anonymous": _safe_int(snmp_status.get("anonymousbinds")),
                        "unauthenticated": _safe_int(snmp_status.get("unauthbinds")),
                        "simple": _safe_int(snmp_status.get("simpleauthbinds")),
                        "strong": _safe_int(snmp_status.get("strongauthbinds")),
                    },
                    "searches": {
                        "total": _safe_int(snmp_status.get("searchops")),
                        "one_level": _safe_int(snmp_status.get("onelevelsearchops")),
                        "subtree": _safe_int(snmp_status.get("wholesubtreesearchops")),
                    },
                    "modifications": {
                        "add": _safe_int(snmp_status.get("addentryops")),
                        "modify": _safe_int(snmp_status.get("modifyentryops")),
                        "delete": _safe_int(snmp_status.get("removeentryops")),
                        "modrdn": _safe_int(snmp_status.get("modifyrdnops")),
                    },
                    "compare": _safe_int(snmp_status.get("compareops")),
                    "referrals": _safe_int(snmp_status.get("referrals")),
                }

                op_data["errors"] = {
                    "security_errors": _safe_int(snmp_status.get("securityerrors")),
                    "bind_security_errors": _safe_int(snmp_status.get("bindsecurityerrors")),
                    "total_errors": _safe_int(snmp_status.get("errors")),
                }

                op_data["data_transfer"] = {
                    "bytes_received": _safe_int(snmp_status.get("bytesrecv")),
                    "bytes_sent": _safe_int(snmp_status.get("bytessent")),
                    "entries_returned": _safe_int(snmp_status.get("entriesreturned")),
                    "referrals_returned": _safe_int(snmp_status.get("referralsreturned")),
                }

                # Check for issues
                bind_errors = _safe_int(snmp_status.get("bindsecurityerrors"))
                if bind_errors > 100:
                    findings.append(
                        format_finding(
                            title="High Bind Security Errors",
                            severity=Severity.MEDIUM,
                            impact=f"{bind_errors} bind security errors detected",
                            details="May indicate authentication issues or brute force attempts",
                            remediation="Review access logs for failed bind patterns",
                            server=target,
                            metadata={"bind_errors": bind_errors},
                        )
                    )

                total_errors = _safe_int(snmp_status.get("errors"))
                if total_errors > 1000:
                    findings.append(
                        format_finding(
                            title="High Error Count",
                            severity=Severity.MEDIUM,
                            impact=f"{total_errors} total errors recorded",
                            details="High error counts may indicate configuration or client issues",
                            remediation="Review error logs to identify patterns",
                            server=target,
                            metadata={"total_errors": total_errors},
                        )
                    )

            except Exception as e:
                mcp.logger.warning("Error getting SNMP stats: %s", e)
                op_data["operation_breakdown"] = {"error": str(e)}

            # Check for pending operations
            if ops_pending > 100:
                findings.append(
                    format_finding(
                        title="High Pending Operations",
                        severity=Severity.HIGH,
                        impact=f"{ops_pending} operations pending - server may be overloaded",
                        details=f"Initiated: {ops_initiated}, Completed: {ops_completed}",
                        remediation="Check server resources, consider adding threads or scaling",
                        server=target,
                        metadata={"pending": ops_pending},
                    )
                )

            # Generate summary
            if findings:
                summary = f"ATTENTION: {len(findings)} operational issue(s) detected"
            else:
                summary = f"HEALTHY: {ops_completed:,} operations completed, {ops_pending} pending"

            op_data["summary"] = summary
            op_data["findings"] = findings

            return op_data

        except Exception as e:
            mcp.logger.error("Error getting operation statistics: %s", e)
            return {
                "type": "operation_statistics",
                "server": target,
                "error": str(e),
            }
        finally:
            if ds:
                try:
                    ds.close()
                except Exception:
                    pass

    @mcp.tool()
    def get_thread_statistics(server_name: Optional[str] = None) -> Dict[str, Any]:
        """Analyze worker thread utilization.

        Returns thread pool statistics including current usage,
        contention indicators, and tuning recommendations.

        Args:
            server_name: Target server name. Uses default if not specified.

        Returns:
            Thread analysis including:
            - Current thread count and configuration
            - Connections at max threads
            - Max threads per connection hits
            - Utilization assessment
        """
        target = server_name or mcp.default_server
        if not target:
            return {
                "type": "thread_statistics",
                "error": "No server configured",
            }

        ds = None
        try:
            ds = mcp.connection_manager.connect(target)
            monitor = Monitor(ds)
            findings: List[Dict[str, Any]] = []

            # Get thread stats from cn=monitor
            try:
                status = monitor.get_attrs_vals_utf8([
                    'threads', 'currentconnectionsatmaxthreads', 'maxthreadsperconnhits'
                ])
            except Exception as e:
                mcp.logger.warning("Error getting monitor status: %s", e)
                status = {}

            threads = _safe_int(status.get("threads"))
            conns_at_max_threads = _safe_int(status.get("currentconnectionsatmaxthreads"))
            max_threads_hits = _safe_int(status.get("maxthreadsperconnhits"))

            # Get active thread count from resource stats (may fail for remote connections)
            try:
                resource_stats = monitor.get_resource_stats()
                total_threads = _safe_int(resource_stats.get("total_threads"))
            except Exception as e:
                mcp.logger.debug("Resource stats unavailable (remote connection): %s", e)
                total_threads = 0

            thread_data = {
                "type": "thread_statistics",
                "server": target,
                "configured_threads": threads,
                "active_threads": total_threads,
                "connections_at_max_threads": conns_at_max_threads,
                "max_threads_per_conn_hits": max_threads_hits,
            }

            # Assess thread health
            if conns_at_max_threads > 0:
                findings.append(
                    format_finding(
                        title="Connections Hitting Thread Limit",
                        severity=Severity.HIGH,
                        impact=f"{conns_at_max_threads} connections are at max thread limit",
                        details="Connections are being throttled due to thread limits",
                        remediation="Increase nsslapd-threadnumber to allow more concurrent operations",
                        server=target,
                        metadata={"at_max": conns_at_max_threads, "configured": threads},
                    )
                )

            if max_threads_hits > 100:
                findings.append(
                    format_finding(
                        title="Frequent Max Threads Per Connection Hits",
                        severity=Severity.MEDIUM,
                        impact=f"Max threads per connection limit hit {max_threads_hits} times",
                        details="Single connections are monopolizing thread pool",
                        remediation="Review nsslapd-maxthreadsperconn setting or investigate client behavior",
                        server=target,
                        metadata={"hits": max_threads_hits},
                    )
                )

            # Generate summary
            if findings:
                summary = f"ATTENTION: {len(findings)} thread utilization issue(s)"
            else:
                summary = f"HEALTHY: {threads} configured threads, no contention detected"

            thread_data["summary"] = summary
            thread_data["findings"] = findings

            return thread_data

        except Exception as e:
            mcp.logger.error("Error getting thread statistics: %s", e)
            return {
                "type": "thread_statistics",
                "server": target,
                "error": str(e),
            }
        finally:
            if ds:
                try:
                    ds.close()
                except Exception:
                    pass

    @mcp.tool()
    def get_resource_utilization(server_name: Optional[str] = None) -> Dict[str, Any]:
        """Get system resource usage from Directory Server perspective.

        Returns resource utilization including memory, CPU, and disk usage
        with health assessments and recommendations.

        **Note:** Some metrics require local server access (is_local=True):
        - Process memory (RSS, VMS, swap) - requires psutil access
        - CPU utilization - requires psutil access
        - Disk space - requires file system access

        For remote servers, these metrics will show as "unavailable" but
        server uptime (from cn=monitor) will still be reported.

        Args:
            server_name: Target server name. Uses default if not specified.

        Returns:
            Resource metrics including:
            - Memory usage (RSS, VMS, swap) - LOCAL ONLY
            - CPU utilization - LOCAL ONLY
            - Disk space for database paths - LOCAL ONLY
            - Server uptime - available for all servers
        """
        target = server_name or mcp.default_server
        if not target:
            return {
                "type": "resource_utilization",
                "error": "No server configured",
            }

        ds = None
        try:
            ds = mcp.connection_manager.connect(target)
            monitor = Monitor(ds)
            findings: List[Dict[str, Any]] = []

            # Check if this is a local server
            is_local = is_local_server(mcp.connection_manager, target)

            # Get uptime info from cn=monitor (works for all servers)
            try:
                status = monitor.get_attrs_vals_utf8(['starttime', 'currenttime'])
            except Exception as e:
                mcp.logger.warning("Error getting monitor status: %s", e)
                status = {}

            # Get resource stats (requires local server with psutil access)
            resource_stats = {}
            local_metrics_available = False
            if is_local:
                try:
                    resource_stats = monitor.get_resource_stats()
                    local_metrics_available = True
                except Exception as e:
                    mcp.logger.debug("Resource stats unavailable: %s", e)
            else:
                mcp.logger.debug("Skipping resource stats - server is remote")
                findings.append(
                    format_finding(
                        title="Limited Metrics Available",
                        severity=Severity.INFO,
                        impact="Process memory, CPU, and disk metrics require local server access",
                        details=(
                            f"Server '{target}' is configured as remote. "
                            "To enable full resource metrics, configure the server with "
                            "is_local=True and serverid=<instance>."
                        ),
                        remediation="Configure local server access if this server runs on the same host",
                        server=target,
                    )
                )

            # Memory stats (will be 0 for remote connections)
            rss = _safe_int(resource_stats.get("rss"))
            vms = _safe_int(resource_stats.get("vms"))
            swap = _safe_int(resource_stats.get("swap"))
            total_mem = _safe_int(resource_stats.get("total_mem"))
            mem_rss_pct = _safe_float(resource_stats.get("mem_rss_percent"))
            mem_vms_pct = _safe_float(resource_stats.get("mem_vms_percent"))
            mem_swap_pct = _safe_float(resource_stats.get("mem_swap_percent"))

            # CPU stats
            cpu_usage = _safe_float(resource_stats.get("cpu_usage"))
            total_threads = _safe_int(resource_stats.get("total_threads"))
            server_status = resource_stats.get("server_status", ["Unknown"])
            if isinstance(server_status, list):
                server_status = server_status[0]

            # Uptime calculation
            start_time = status.get("starttime", ["Unknown"])
            current_time = status.get("currenttime", ["Unknown"])
            if isinstance(start_time, list):
                start_time = start_time[0]
            if isinstance(current_time, list):
                current_time = current_time[0]

            resource_data = {
                "type": "resource_utilization",
                "server": target,
                "is_local": is_local,
                "local_metrics_available": local_metrics_available,
                "server_status": server_status if local_metrics_available else "unknown (remote)",
                "memory": {
                    "available": local_metrics_available,
                    "rss": rss if local_metrics_available else None,
                    "rss_human": _format_bytes(rss) if local_metrics_available else "N/A (requires local access)",
                    "rss_percent": mem_rss_pct if local_metrics_available else None,
                    "vms": vms if local_metrics_available else None,
                    "vms_human": _format_bytes(vms) if local_metrics_available else "N/A (requires local access)",
                    "vms_percent": mem_vms_pct if local_metrics_available else None,
                    "swap": swap if local_metrics_available else None,
                    "swap_human": _format_bytes(swap) if local_metrics_available else "N/A (requires local access)",
                    "swap_percent": mem_swap_pct if local_metrics_available else None,
                    "total_system": total_mem if local_metrics_available else None,
                    "total_system_human": _format_bytes(total_mem) if local_metrics_available else "N/A (requires local access)",
                },
                "cpu": {
                    "available": local_metrics_available,
                    "usage_percent": cpu_usage if local_metrics_available else None,
                    "process_threads": total_threads if local_metrics_available else None,
                },
                "uptime": {
                    "start_time": start_time,
                    "current_time": current_time,
                },
            }

            # Get disk space info (requires local access)
            if not is_local:
                resource_data["disk"] = {
                    "available": False,
                    "message": "Disk monitoring requires local server access (is_local=True)",
                }
            else:
                try:
                    disk_monitor = MonitorDiskSpace(ds)
                    disks = disk_monitor.get_disks()
                    disk_info = []
                    for disk in disks:
                        parts = disk.split()
                        disk_entry = {}
                        for part in parts:
                            if "=" in part:
                                key, val = part.split("=", 1)
                                disk_entry[key.lower()] = val.strip('"')
                        disk_info.append(disk_entry)

                        # Check disk usage
                        pct = _safe_int(disk_entry.get("percent", "0"))
                        partition = disk_entry.get("partition", "unknown")
                        if pct >= 90:
                            findings.append(
                                format_finding(
                                    title=f"Critical Disk Usage: {partition}",
                                    severity=Severity.CRITICAL,
                                    impact=f"Partition {partition} is {pct}% full",
                                    details="Server may fail if disk fills completely",
                                    remediation="Free up disk space or expand storage immediately",
                                    server=target,
                                    metadata={"partition": partition, "usage": pct},
                                )
                            )
                        elif pct >= 80:
                            findings.append(
                                format_finding(
                                    title=f"High Disk Usage: {partition}",
                                    severity=Severity.HIGH,
                                    impact=f"Partition {partition} is {pct}% full",
                                    details="Disk is filling up and needs attention",
                                    remediation="Plan for disk space cleanup or expansion",
                                    server=target,
                                    metadata={"partition": partition, "usage": pct},
                                )
                            )

                    resource_data["disk"] = {"available": True, "partitions": disk_info}

                except Exception as e:
                    mcp.logger.warning("Error getting disk stats: %s", e)
                    resource_data["disk"] = {"available": False, "error": str(e)}

            # Check for memory issues
            if mem_rss_pct > 80:
                findings.append(
                    format_finding(
                        title="High Memory Usage",
                        severity=Severity.HIGH,
                        impact=f"Server using {mem_rss_pct}% of system memory",
                        details=f"RSS: {_format_bytes(rss)}, Total: {_format_bytes(total_mem)}",
                        remediation="Review cache sizes or consider adding memory",
                        server=target,
                        metadata={"rss_pct": mem_rss_pct, "rss": rss},
                    )
                )

            if swap > 0 and mem_swap_pct > 5:
                findings.append(
                    format_finding(
                        title="Server Using Swap",
                        severity=Severity.MEDIUM,
                        impact=f"Server has {_format_bytes(swap)} in swap ({mem_swap_pct}%)",
                        details="Swap usage degrades performance significantly",
                        remediation="Reduce cache sizes or add physical memory",
                        server=target,
                        metadata={"swap": swap, "swap_pct": mem_swap_pct},
                    )
                )

            # Generate summary
            if findings:
                critical = sum(1 for f in findings if f.get("severity") == "critical")
                if critical > 0:
                    summary = f"CRITICAL: {critical} critical resource issue(s) require immediate attention"
                else:
                    summary = f"ATTENTION: {len(findings)} resource issue(s) detected"
            else:
                summary = f"HEALTHY: Memory {mem_rss_pct}%, CPU {cpu_usage}%"

            resource_data["summary"] = summary
            resource_data["findings"] = findings

            return resource_data

        except Exception as e:
            mcp.logger.error("Error getting resource utilization: %s", e)
            return {
                "type": "resource_utilization",
                "server": target,
                "error": str(e),
            }
        finally:
            if ds:
                try:
                    ds.close()
                except Exception:
                    pass

    @mcp.tool()
    def get_performance_summary(server_name: Optional[str] = None) -> Dict[str, Any]:
        """Get a comprehensive performance overview in a single call.

        This is a convenience tool that combines key metrics from cache,
        connections, operations, threads, and resources into a single
        summary view with prioritized findings.

        Args:
            server_name: Target server name. Uses default if not specified.

        Returns:
            Combined performance summary including:
            - Overall health status
            - Key metrics from each category
            - Prioritized list of all findings
            - Top recommendations
        """
        target = server_name or mcp.default_server
        if not target:
            return {
                "type": "performance_summary",
                "error": "No server configured",
            }

        ds = None
        try:
            ds = mcp.connection_manager.connect(target)
            monitor = Monitor(ds)

            all_findings: List[Dict[str, Any]] = []
            summary_data = {
                "type": "performance_summary",
                "server": target,
                "metrics": {},
            }

            # Gather key metrics
            try:
                # Get specific attributes from cn=monitor
                try:
                    status = monitor.get_attrs_vals_utf8([
                        'currentconnections', 'dtablesize', 'opsinitiated',
                        'opscompleted', 'threads', 'currentconnectionsatmaxthreads'
                    ])
                except Exception as e:
                    mcp.logger.warning("Error getting monitor status: %s", e)
                    status = {}

                # Get resource stats (may fail for remote connections)
                try:
                    resource_stats = monitor.get_resource_stats()
                except Exception as e:
                    mcp.logger.debug("Resource stats unavailable (remote connection): %s", e)
                    resource_stats = {}

                # Connections
                current_conns = _safe_int(status.get("currentconnections"))
                dtable_size = _safe_int(status.get("dtablesize"))
                fd_util = round((current_conns / dtable_size * 100), 2) if dtable_size > 0 else 0

                summary_data["metrics"]["connections"] = {
                    "current": current_conns,
                    "max": dtable_size,
                    "utilization_pct": fd_util,
                }

                if fd_util > 80:
                    all_findings.append(format_finding(
                        title="High Connection Utilization",
                        severity=Severity.HIGH,
                        impact=f"{fd_util}% of file descriptors in use",
                        details=f"Current: {current_conns}, Max: {dtable_size}",
                        remediation="Increase nsslapd-maxdescriptors",
                        server=target,
                    ))

                # Operations
                ops_initiated = _safe_int(status.get("opsinitiated"))
                ops_completed = _safe_int(status.get("opscompleted"))
                ops_pending = ops_initiated - ops_completed

                summary_data["metrics"]["operations"] = {
                    "completed": ops_completed,
                    "pending": ops_pending,
                }

                if ops_pending > 100:
                    all_findings.append(format_finding(
                        title="High Pending Operations",
                        severity=Severity.HIGH,
                        impact=f"{ops_pending} operations pending",
                        details="Server may be overloaded",
                        remediation="Check resources and consider scaling",
                        server=target,
                    ))

                # Threads
                threads = _safe_int(status.get("threads"))
                conns_at_max = _safe_int(status.get("currentconnectionsatmaxthreads"))

                summary_data["metrics"]["threads"] = {
                    "configured": threads,
                    "at_max_threads": conns_at_max,
                }

                if conns_at_max > 0:
                    all_findings.append(format_finding(
                        title="Thread Contention",
                        severity=Severity.HIGH,
                        impact=f"{conns_at_max} connections at thread limit",
                        details="Connections being throttled",
                        remediation="Increase nsslapd-threadnumber",
                        server=target,
                    ))

                # Memory
                mem_rss_pct = _safe_float(resource_stats.get("mem_rss_percent"))
                rss = _safe_int(resource_stats.get("rss"))
                cpu = _safe_float(resource_stats.get("cpu_usage"))

                summary_data["metrics"]["resources"] = {
                    "memory_pct": mem_rss_pct,
                    "memory_human": _format_bytes(rss),
                    "cpu_pct": cpu,
                }

                if mem_rss_pct > 80:
                    all_findings.append(format_finding(
                        title="High Memory Usage",
                        severity=Severity.HIGH,
                        impact=f"{mem_rss_pct}% of system memory",
                        details=f"RSS: {_format_bytes(rss)}",
                        remediation="Review cache sizes or add memory",
                        server=target,
                    ))

            except Exception as e:
                mcp.logger.warning("Error gathering performance metrics: %s", e)

            # Get cache summary
            try:
                ldbm_monitor = MonitorLDBM(ds)
                ldbm_status = ldbm_monitor.get_status()

                db_ratio = _safe_float(ldbm_status.get("dbcachehitratio"))
                summary_data["metrics"]["cache"] = {
                    "db_hit_ratio": db_ratio,
                }

                if db_ratio < 70 and db_ratio > 0:
                    all_findings.append(format_finding(
                        title="Low Cache Hit Ratio",
                        severity=Severity.MEDIUM,
                        impact=f"DB cache hit ratio is {db_ratio}%",
                        details="Frequent disk reads",
                        remediation="Increase cache sizes",
                        server=target,
                    ))

            except Exception as e:
                mcp.logger.warning("Error getting cache metrics: %s", e)

            # Sort findings by severity
            severity_order = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
            all_findings.sort(key=lambda f: severity_order.get(f.get("severity", "info"), 5))

            # Determine overall health
            critical_count = sum(1 for f in all_findings if f.get("severity") == "critical")
            high_count = sum(1 for f in all_findings if f.get("severity") == "high")

            if critical_count > 0:
                overall_health = "critical"
                summary = f"CRITICAL: {critical_count} critical issue(s) require immediate attention"
            elif high_count > 0:
                overall_health = "degraded"
                summary = f"DEGRADED: {high_count} high-priority issue(s) detected"
            elif all_findings:
                overall_health = "fair"
                summary = f"FAIR: {len(all_findings)} minor issue(s) detected"
            else:
                overall_health = "healthy"
                summary = "HEALTHY: All performance metrics within normal ranges"

            summary_data["overall_health"] = overall_health
            summary_data["summary"] = summary
            summary_data["findings"] = all_findings
            summary_data["finding_count"] = {
                "critical": critical_count,
                "high": high_count,
                "medium": sum(1 for f in all_findings if f.get("severity") == "medium"),
                "low": sum(1 for f in all_findings if f.get("severity") == "low"),
            }

            return summary_data

        except Exception as e:
            mcp.logger.error("Error getting performance summary: %s", e)
            return {
                "type": "performance_summary",
                "server": target,
                "error": str(e),
            }
        finally:
            if ds:
                try:
                    ds.close()
                except Exception:
                    pass
