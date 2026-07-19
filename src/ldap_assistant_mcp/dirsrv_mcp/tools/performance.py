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

from datetime import datetime, timezone
from typing import TYPE_CHECKING, Any, Dict, List, Optional

from lib389.backend import Backends
from lib389.monitor import Monitor, MonitorLDBM, MonitorDiskSpace, MonitorSNMP

from mcp.types import ToolAnnotations

from ldap_assistant_mcp.dirsrv_mcp.connection import is_local_server
from ldap_assistant_mcp.dirsrv_mcp.tools.error_utils import format_error_message, format_tool_error
from ldap_assistant_mcp.lib.disk_utils import parse_dsdisk_entry
from ldap_assistant_mcp.lib.result_formatter import Severity, format_finding
from ldap_assistant_mcp.lib.value_utils import format_bytes, safe_float, safe_int

_RO = ToolAnnotations(readOnlyHint=True, idempotentHint=True, destructiveHint=False, openWorldHint=True)

# cn=snmp,cn=monitor error counters and maxThreadsPerConnHits are
# cumulative since server start, so absolute thresholds mislabel healthy
# long-uptime servers (and miss a fresh server under attack).  When uptime
# is available (cn=monitor starttime/currenttime) findings are rate-based.
# The rates are deliberately conservative — a sustained ~1 event/minute for
# security/thread events and ~10/minute for the aggregate error counter —
# chosen as the same order of magnitude the old absolute thresholds implied
# for a one-hour-old server, not as calibrated SLOs.
BIND_SECURITY_ERRORS_PER_HOUR = 60.0
TOTAL_ERRORS_PER_HOUR = 600.0
MAX_THREADS_HITS_PER_HOUR = 60.0
# Fallback gates when uptime is unavailable: the historical absolute counts
# are reused, but the finding is downgraded to LOW with an explicit
# cumulative-counter caveat (no new absolute thresholds are invented).
BIND_SECURITY_ERRORS_CUMULATIVE_GATE = 100
TOTAL_ERRORS_CUMULATIVE_GATE = 1000
MAX_THREADS_HITS_CUMULATIVE_GATE = 100

if TYPE_CHECKING:
    from ldap_assistant_mcp.dirsrv_mcp.server import DirSrvMCP

def _sanitize_performance_result(mcp: "DirSrvMCP", result: Dict[str, Any]) -> Dict[str, Any]:
    """Sanitize performance result for privacy mode.

    Performance metrics are numeric and diagnostic — we keep them.
    We only sanitize server names, backend names, suffixes, partitions,
    and findings.  Creates new dicts to avoid mutating the input.
    """
    if not mcp.privacy_enabled:
        return result

    sanitizer = mcp.sanitizer
    sanitized = dict(result)

    # Server names are never sanitized (user-chosen config labels).
    if "error" in sanitized and isinstance(sanitized["error"], str):
        sanitized["error"] = sanitizer.sanitize_text(sanitized["error"])

    if "backends" in sanitized and isinstance(sanitized["backends"], list):
        new_backends = []
        for be in sanitized["backends"]:
            if isinstance(be, dict) and "name" in be:
                be = {**be, "name": "[backend]", "suffix": sanitizer.sanitize_suffix(be.get("suffix"))}
                if "error" in be and isinstance(be["error"], str):
                    be["error"] = sanitizer.sanitize_text(be["error"])
            new_backends.append(be)
        sanitized["backends"] = new_backends

    if "findings" in sanitized and isinstance(sanitized["findings"], list):
        sanitized["findings"] = sanitizer.sanitize_findings(sanitized["findings"])

    if "resources" in sanitized and isinstance(sanitized["resources"], dict):
        resources = dict(sanitized["resources"])
        if "disk" in resources and isinstance(resources["disk"], dict):
            disk = dict(resources["disk"])
            if "partitions" in disk and isinstance(disk["partitions"], list):
                disk["partitions"] = [
                    {**p, "partition": "[partition]"} for p in disk["partitions"]
                ]
            resources["disk"] = disk
        sanitized["resources"] = resources

    # Handle top-level disk key (from get_resource_utilization)
    if "disk" in sanitized and isinstance(sanitized["disk"], dict):
        disk = dict(sanitized["disk"])
        if "partitions" in disk and isinstance(disk["partitions"], list):
            disk["partitions"] = [
                {**p, "partition": "[partition]"} for p in disk["partitions"]
            ]
        sanitized["disk"] = disk

    # Sanitize error fields in any nested sub-dicts (e.g. global_db_cache, operation_breakdown)
    for key, value in sanitized.items():
        if isinstance(value, dict) and "error" in value and isinstance(value["error"], str):
            sanitized[key] = {**value, "error": sanitizer.sanitize_text(value["error"])}

    if "probe_failures" in sanitized and isinstance(sanitized["probe_failures"], list):
        sanitized["probe_failures"] = [
            {**p, "error": sanitizer.sanitize_text(p["error"])}
            if isinstance(p, dict) and isinstance(p.get("error"), str)
            else p
            for p in sanitized["probe_failures"]
        ]

    # Error trails nested one level under "metrics" (e.g. metrics.cache.error)
    if "metrics" in sanitized and isinstance(sanitized["metrics"], dict):
        metrics = dict(sanitized["metrics"])
        for mkey, mval in metrics.items():
            if isinstance(mval, dict) and isinstance(mval.get("error"), str):
                metrics[mkey] = {**mval, "error": sanitizer.sanitize_text(mval["error"])}
        sanitized["metrics"] = metrics

    return sanitized

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

def _parse_generalized_time(value: Any) -> Optional[datetime]:
    """Parse an LDAP GeneralizedTime value (e.g. ``20260713012345Z``).

    Accepts the raw string or a single-element list as returned by
    ``get_attrs_vals_utf8``.  Returns None when absent or unparseable.
    """
    if isinstance(value, list):
        value = value[0] if value else None
    if not isinstance(value, str) or not value:
        return None
    try:
        return datetime.strptime(value, "%Y%m%d%H%M%SZ").replace(tzinfo=timezone.utc)
    except ValueError:
        return None


def _uptime_hours(status: Dict[str, Any]) -> Optional[float]:
    """Server uptime in hours from cn=monitor starttime/currenttime.

    Returns None when either timestamp is missing/unparseable or the
    difference is non-positive — callers must then treat cumulative
    counters as rate-less and caveat accordingly.
    """
    start = _parse_generalized_time(status.get("starttime"))
    now = _parse_generalized_time(status.get("currenttime"))
    if start is None or now is None:
        return None
    seconds = (now - start).total_seconds()
    if seconds <= 0:
        return None
    return seconds / 3600.0


def _finalize_drilldown(
    result: Dict[str, Any],
    findings: List[Dict[str, Any]],
    probe_failures: List[Dict[str, str]],
    healthy_summary: str,
    issue_noun: str,
) -> None:
    """Attach summary/findings/evidence keys to a drill-down result.

    Mirrors the ``get_performance_summary`` evidence pattern: a confident
    healthy/normal summary is impossible while a required probe failed.
    ``evidence_status`` is "partial" whenever probes failed.
    """
    if probe_failures and findings:
        summary = (
            f"ATTENTION (incomplete evidence): {len(findings)} {issue_noun}(s) detected; "
            f"{len(probe_failures)} required probe(s) failed"
        )
    elif probe_failures:
        summary = (
            f"INCOMPLETE: {len(probe_failures)} required probe(s) failed - "
            "results may not reflect actual server state"
        )
    elif findings:
        summary = f"ATTENTION: {len(findings)} {issue_noun}(s) detected"
    else:
        summary = healthy_summary
    result["summary"] = summary
    result["evidence_status"] = "partial" if probe_failures else "complete"
    result["probe_failures"] = probe_failures
    result["findings"] = findings


def register_performance_tools(mcp: DirSrvMCP) -> None:
    """Register performance diagnostic tools with the MCP server."""

    @mcp.tool(annotations=_RO, tags={"performance", "live"})
    def get_cache_statistics(
        backend: Optional[str] = None,
        server_name: Optional[str] = None,
    ) -> Dict[str, Any]:
        """Analyze database and entry cache efficiency. LIVE only.

        Use this to drill into cache problems identified by ``first_look``
        or ``get_performance_summary``. Returns per-backend hit ratios and
        sizing recommendations.

        Args:
            backend: Specific backend to analyze (e.g., 'userroot').
                    If not specified, analyzes all backends.
            server_name: Target server name. Uses default if not specified.

        Returns:
            Cache analysis with entry/DN/DB cache hit ratios, utilization
            percentages, health assessments, and tuning recommendations.
        """
        target = server_name or mcp.default_server
        if not target:
            return _sanitize_performance_result(mcp, {
                "type": "cache_statistics",
                "error": "No server configured",
            })
        mcp.require_live(target,"get_cache_statistics")

        ds = None
        try:
            ds = mcp.connection_manager.connect(target)
            findings: List[Dict[str, Any]] = []
            # Required probes that failed — a healthy summary is impossible
            # while this list is non-empty.
            probe_failures: List[Dict[str, str]] = []
            cache_data = {
                "type": "cache_statistics",
                "server": target,
                "global_db_cache": {},
                "backends": [],
            }

            try:
                ldbm_monitor = MonitorLDBM(ds)
                ldbm_status = ldbm_monitor.get_status()

                db_cache = {}

                if "dbcachehits" in ldbm_status:
                    hits = safe_int(ldbm_status.get("dbcachehits"))
                    tries = safe_int(ldbm_status.get("dbcachetries"))
                    ratio = safe_float(ldbm_status.get("dbcachehitratio"))
                    if ratio == 0 and tries > 0:
                        ratio = _calculate_hit_ratio(hits, tries)

                    db_cache = {
                        "type": "bdb",
                        "hits": hits,
                        "tries": tries,
                        "hit_ratio": ratio,
                        "page_in": safe_int(ldbm_status.get("dbcachepagein")),
                        "page_out": safe_int(ldbm_status.get("dbcachepageout")),
                        "ro_evictions": safe_int(ldbm_status.get("dbcacheroevict")),
                        "rw_evictions": safe_int(ldbm_status.get("dbcacherwevict")),
                    }

                    health, severity = _assess_cache_health(ratio)
                    db_cache["health"] = health

                    # tries > 1000 gates out idle-server false alarms (a
                    # freshly started instance has a meaningless ratio),
                    # matching the entry-cache path below.
                    if severity in [Severity.MEDIUM, Severity.HIGH] and tries > 1000:
                        findings.append(
                            format_finding(
                                title="Low Database Cache Hit Ratio",
                                severity=severity,
                                impact=f"Database cache hit ratio is {ratio}% - frequent disk reads slow operations",
                                details=f"Hits: {hits}, Tries: {tries}, Evictions: {db_cache['ro_evictions'] + db_cache['rw_evictions']}",
                                remediation="Investigate database cache efficiency. If sufficient memory is available and this pattern persists under typical load, review nsslapd-dbcachesize tuning. Monitor cache evictions before and after any changes.",
                                server=target,
                                metadata={"hit_ratio": ratio, "tries": tries},
                            )
                        )

                if "normalizeddncachehits" in ldbm_status:
                    ndn_hits = safe_int(ldbm_status.get("normalizeddncachehits"))
                    ndn_tries = safe_int(ldbm_status.get("normalizeddncachetries"))
                    ndn_ratio = safe_float(ldbm_status.get("normalizeddncachehitratio"))
                    if ndn_ratio == 0 and ndn_tries > 0:
                        ndn_ratio = _calculate_hit_ratio(ndn_hits, ndn_tries)

                    db_cache["normalized_dn_cache"] = {
                        "hits": ndn_hits,
                        "tries": ndn_tries,
                        "misses": safe_int(ldbm_status.get("normalizeddncachemisses")),
                        "hit_ratio": ndn_ratio,
                        "evictions": safe_int(ldbm_status.get("normalizeddncacheevictions")),
                        "current_size": safe_int(ldbm_status.get("currentnormalizeddncachesize")),
                        "max_size": safe_int(ldbm_status.get("maxnormalizeddncachesize")),
                        "current_count": safe_int(ldbm_status.get("currentnormalizeddncachecount")),
                    }

                cache_data["global_db_cache"] = db_cache

            except Exception as e:
                mcp.logger.warning("Error getting LDBM monitor: %s", e)
                cache_data["global_db_cache"] = {"error": format_error_message(e)}
                probe_failures.append({
                    "probe": "ldbm_monitor",
                    "error": format_error_message(e),
                })

            try:
                backends_obj = Backends(ds)
                for be in backends_obj.list():
                    be_name = be.get_attr_val_utf8("cn")

                    if backend and be_name.lower() != backend.lower():
                        continue

                    try:
                        be_monitor = be.get_monitor()
                        be_status = be_monitor.get_status()

                        entry_hits = safe_int(be_status.get("entrycachehits"))
                        entry_tries = safe_int(be_status.get("entrycachetries"))
                        entry_ratio = safe_float(be_status.get("entrycachehitratio"))
                        if entry_ratio == 0 and entry_tries > 0:
                            entry_ratio = _calculate_hit_ratio(entry_hits, entry_tries)

                        entry_current_size = safe_int(be_status.get("currententrycachesize"))
                        entry_max_size = safe_int(be_status.get("maxentrycachesize"))
                        entry_current_count = safe_int(be_status.get("currententrycachecount"))
                        entry_max_count = safe_int(be_status.get("maxentrycachecount"))

                        entry_cache = {
                            "hits": entry_hits,
                            "tries": entry_tries,
                            "hit_ratio": entry_ratio,
                            "current_size": entry_current_size,
                            "current_size_human": format_bytes(entry_current_size),
                            "max_size": entry_max_size,
                            "max_size_human": format_bytes(entry_max_size),
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
                                    remediation=f"Investigate entry cache utilization for backend {be_name}. If sufficient memory is available and low hit ratio persists under normal operations, review nsslapd-cachememsize tuning. Verify current memory usage before making changes.",
                                    server=target,
                                    metadata={"backend": be_name, "hit_ratio": entry_ratio},
                                )
                            )

                        dn_hits = safe_int(be_status.get("dncachehits"))
                        dn_tries = safe_int(be_status.get("dncachetries"))
                        dn_ratio = safe_float(be_status.get("dncachehitratio"))
                        if dn_ratio == 0 and dn_tries > 0:
                            dn_ratio = _calculate_hit_ratio(dn_hits, dn_tries)

                        dn_cache = {
                            "hits": dn_hits,
                            "tries": dn_tries,
                            "hit_ratio": dn_ratio,
                            "current_size": safe_int(be_status.get("currentdncachesize")),
                            "max_size": safe_int(be_status.get("maxdncachesize")),
                            "current_count": safe_int(be_status.get("currentdncachecount")),
                            "max_count": safe_int(be_status.get("maxdncachecount")),
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
                        cache_data["backends"].append({"name": be_name, "error": format_error_message(e)})
                        probe_failures.append({
                            "probe": "backend_cache",
                            "error": format_error_message(e),
                        })

            except Exception as e:
                mcp.logger.warning("Error listing backends: %s", e)
                probe_failures.append({
                    "probe": "backend_list",
                    "error": format_error_message(e),
                })

            backends_with_cache = [b for b in cache_data["backends"] if "entry_cache" in b]
            if backends_with_cache:
                avg_ratio = sum(
                    b.get("entry_cache", {}).get("hit_ratio", 0) for b in backends_with_cache
                ) / len(backends_with_cache)
                healthy_summary = f"HEALTHY: Average entry cache hit ratio {avg_ratio:.1f}% across {len(cache_data['backends'])} backend(s)"
            else:
                healthy_summary = "No backend cache data available"

            _finalize_drilldown(cache_data, findings, probe_failures, healthy_summary, "cache issue")

            return _sanitize_performance_result(mcp, cache_data)

        except Exception as e:
            mcp.logger.error("Error getting cache statistics: %s", e)
            return _sanitize_performance_result(
                mcp, format_tool_error(e, mcp, "cache_statistics", server=target),
            )
        finally:
            if ds:
                try:
                    ds.close()
                except Exception:
                    pass

    @mcp.tool(annotations=_RO, tags={"performance", "live"})
    def get_connection_statistics(server_name: Optional[str] = None) -> Dict[str, Any]:
        """Analyze connection patterns and file descriptor usage. LIVE only.

        Use this to investigate connection-related issues (FD exhaustion,
        CLOSE_WAIT buildup, connection spikes). Connection state breakdown
        requires local server access.

        Args:
            server_name: Target server name. Uses default if not specified.

        Returns:
            Connection counts, FD utilization, connection state breakdown
            (local only), and tuning recommendations.
        """
        target = server_name or mcp.default_server
        if not target:
            return _sanitize_performance_result(mcp, {
                "type": "connection_statistics",
                "error": "No server configured",
            })
        mcp.require_live(target,"get_connection_statistics")

        ds = None
        try:
            ds = mcp.connection_manager.connect(target)
            monitor = Monitor(ds)
            findings: List[Dict[str, Any]] = []
            probe_failures: List[Dict[str, str]] = []
            is_local = is_local_server(mcp.connection_manager, target)

            try:
                status = monitor.get_attrs_vals_utf8([
                    'currentconnections', 'totalconnections', 'dtablesize', 'readwaiters'
                ])
            except Exception as e:
                mcp.logger.warning("Error getting monitor status: %s", e)
                status = {}
                probe_failures.append({
                    "probe": "ldap_monitor",
                    "error": format_error_message(e),
                })

            current_conns = safe_int(status.get("currentconnections"))
            total_conns = safe_int(status.get("totalconnections"))
            dtable_size = safe_int(status.get("dtablesize"))
            read_waiters = safe_int(status.get("readwaiters"))

            # lib389 Monitor.get_resource_stats() inspects sockets on
            # the MCP HOST via psutil (and does not raise for remote targets),
            # so for a remote server it would report the wrong machine's
            # connection states.  Only call it when the target is local.
            conn_count: Optional[int] = None
            conn_established: Optional[int] = None
            conn_close_wait: Optional[int] = None
            conn_time_wait: Optional[int] = None
            states_available = False
            states_reason: Optional[str] = None
            if is_local:
                try:
                    resource_stats = monitor.get_resource_stats()
                    conn_count = safe_int(resource_stats.get("connection_count"))
                    conn_established = safe_int(resource_stats.get("connection_established_count"))
                    conn_close_wait = safe_int(resource_stats.get("connection_close_wait_count"))
                    conn_time_wait = safe_int(resource_stats.get("connection_time_wait_count"))
                    states_available = True
                except Exception as e:
                    mcp.logger.debug("Resource stats unavailable: %s", e)
                    states_reason = "Local connection state probe failed"
                    probe_failures.append({
                        "probe": "local_connection_states",
                        "error": format_error_message(e),
                    })
            else:
                states_reason = (
                    "Connection state breakdown requires local server access "
                    "(is_local=True); socket states measured on the MCP host "
                    "would describe the MCP host, not the directory server"
                )

            fd_utilization = round((current_conns / dtable_size * 100), 2) if dtable_size > 0 else 0

            connection_states: Dict[str, Any] = {
                "available": states_available,
                "total": conn_count,
                "established": conn_established,
                "close_wait": conn_close_wait,
                "time_wait": conn_time_wait,
            }
            if states_reason:
                connection_states["reason"] = states_reason

            conn_data = {
                "type": "connection_statistics",
                "server": target,
                "current_connections": current_conns,
                "total_connections": total_conns,
                "max_file_descriptors": dtable_size,
                "fd_utilization_pct": fd_utilization,
                "read_waiters": read_waiters,
                "connection_states": connection_states,
            }

            if fd_utilization > 80:
                findings.append(
                    format_finding(
                        title="High File Descriptor Utilization",
                        severity=Severity.HIGH,
                        impact=f"Server is using {fd_utilization}% of available file descriptors",
                        details=f"Current: {current_conns}, Max: {dtable_size}",
                        remediation="Investigate connection patterns - check for client connection leaks or unexpected growth. Verify system ulimits before considering nsslapd-maxdescriptors adjustments. Monitor trends to identify root cause.",
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
                        remediation="Monitor connection growth trends. Investigate whether this is normal load growth or an issue with client connection handling before considering descriptor limit changes.",
                        server=target,
                        metadata={"utilization": fd_utilization},
                    )
                )

            if read_waiters > 10:
                findings.append(
                    format_finding(
                        title="Requests Waiting for Worker Threads",
                        severity=Severity.MEDIUM,
                        impact=f"{read_waiters} connections have incoming requests waiting to be read/serviced - worker threads may be saturated",
                        details="cn=monitor readwaiters counts connections whose requests are waiting for a worker thread to read and service them; sustained high values indicate worker thread saturation",
                        remediation="Investigate what is occupying worker threads (e.g. long-running or unindexed searches). If load is legitimate and CPU headroom exists, review nsslapd-threadnumber (global worker thread pool).",
                        server=target,
                        metadata={"read_waiters": read_waiters},
                    )
                )

            if conn_close_wait is not None and conn_close_wait > 50:
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

            _finalize_drilldown(
                conn_data, findings, probe_failures,
                f"HEALTHY: {current_conns} active connections ({fd_utilization}% of max)",
                "connection issue",
            )

            return _sanitize_performance_result(mcp, conn_data)

        except Exception as e:
            mcp.logger.error("Error getting connection statistics: %s", e)
            return _sanitize_performance_result(
                mcp, format_tool_error(e, mcp, "connection_statistics", server=target),
            )
        finally:
            if ds:
                try:
                    ds.close()
                except Exception:
                    pass

    @mcp.tool(annotations=_RO, tags={"performance", "live"})
    def get_operation_statistics(server_name: Optional[str] = None) -> Dict[str, Any]:
        """Get operation counts by type and bind method distribution. LIVE only.

        Use this to understand workload composition (search-heavy vs write-heavy),
        identify bind errors, or track data transfer volumes.

        Args:
            server_name: Target server name. Uses default if not specified.

        Returns:
            Operation breakdown by type (search, bind, modify, add, delete),
            entries sent, bytes transferred, and bind method distribution.
        """
        target = server_name or mcp.default_server
        if not target:
            return _sanitize_performance_result(mcp, {
                "type": "operation_statistics",
                "error": "No server configured",
            })
        mcp.require_live(target,"get_operation_statistics")

        ds = None
        try:
            ds = mcp.connection_manager.connect(target)
            monitor = Monitor(ds)
            findings: List[Dict[str, Any]] = []
            probe_failures: List[Dict[str, str]] = []

            try:
                status = monitor.get_attrs_vals_utf8([
                    'opsinitiated', 'opscompleted', 'entriessent', 'bytessent',
                    'starttime', 'currenttime'
                ])
            except Exception as e:
                mcp.logger.warning("Error getting monitor status: %s", e)
                status = {}
                probe_failures.append({
                    "probe": "ldap_monitor",
                    "error": format_error_message(e),
                })

            # Uptime basis for rate-converting cumulative SNMP counters
            uptime_h = _uptime_hours(status)

            ops_initiated = safe_int(status.get("opsinitiated"))
            ops_completed = safe_int(status.get("opscompleted"))
            entries_sent = safe_int(status.get("entriessent"))
            bytes_sent = safe_int(status.get("bytessent"))

            ops_pending = ops_initiated - ops_completed

            op_data = {
                "type": "operation_statistics",
                "server": target,
                "operations_initiated": ops_initiated,
                "operations_completed": ops_completed,
                "operations_pending": ops_pending,
                "entries_sent": entries_sent,
                "bytes_sent": bytes_sent,
                "bytes_sent_human": format_bytes(bytes_sent),
            }

            try:
                snmp_monitor = MonitorSNMP(ds)
                snmp_status = snmp_monitor.get_status()

                op_data["operation_breakdown"] = {
                    "binds": {
                        "anonymous": safe_int(snmp_status.get("anonymousbinds")),
                        "unauthenticated": safe_int(snmp_status.get("unauthbinds")),
                        "simple": safe_int(snmp_status.get("simpleauthbinds")),
                        "strong": safe_int(snmp_status.get("strongauthbinds")),
                    },
                    "searches": {
                        "total": safe_int(snmp_status.get("searchops")),
                        "one_level": safe_int(snmp_status.get("onelevelsearchops")),
                        "subtree": safe_int(snmp_status.get("wholesubtreesearchops")),
                    },
                    "modifications": {
                        "add": safe_int(snmp_status.get("addentryops")),
                        "modify": safe_int(snmp_status.get("modifyentryops")),
                        "delete": safe_int(snmp_status.get("removeentryops")),
                        "modrdn": safe_int(snmp_status.get("modifyrdnops")),
                    },
                    "compare": safe_int(snmp_status.get("compareops")),
                    "referrals": safe_int(snmp_status.get("referrals")),
                }

                op_data["errors"] = {
                    "security_errors": safe_int(snmp_status.get("securityerrors")),
                    "bind_security_errors": safe_int(snmp_status.get("bindsecurityerrors")),
                    "total_errors": safe_int(snmp_status.get("errors")),
                }

                op_data["data_transfer"] = {
                    "bytes_received": safe_int(snmp_status.get("bytesrecv")),
                    "bytes_sent": safe_int(snmp_status.get("bytessent")),
                    "entries_returned": safe_int(snmp_status.get("entriesreturned")),
                    "referrals_returned": safe_int(snmp_status.get("referralsreturned")),
                }

                # bindsecurityerrors and errors are cumulative since
                # server start — threshold on the per-hour rate when uptime is
                # known, otherwise downgrade to LOW with an explicit caveat.
                bind_errors = safe_int(snmp_status.get("bindsecurityerrors"))
                if uptime_h is not None:
                    bind_error_rate = bind_errors / uptime_h
                    if bind_error_rate > BIND_SECURITY_ERRORS_PER_HOUR:
                        findings.append(
                            format_finding(
                                title="High Bind Security Error Rate",
                                severity=Severity.MEDIUM,
                                impact=f"~{bind_error_rate:.1f} bind security errors/hour ({bind_errors} cumulative over {uptime_h:.1f}h uptime)",
                                details=f"bindSecurityErrors is cumulative since server start; the rate over {uptime_h:.1f}h of uptime exceeds {BIND_SECURITY_ERRORS_PER_HOUR:.0f}/hour and may indicate authentication issues or brute force attempts",
                                remediation="Review access logs for failed bind patterns",
                                server=target,
                                metadata={
                                    "bind_errors": bind_errors,
                                    "rate_per_hour": round(bind_error_rate, 2),
                                    "uptime_hours": round(uptime_h, 2),
                                    "threshold_per_hour": BIND_SECURITY_ERRORS_PER_HOUR,
                                },
                            )
                        )
                elif bind_errors > BIND_SECURITY_ERRORS_CUMULATIVE_GATE:
                    findings.append(
                        format_finding(
                            title="Bind Security Errors Accumulated",
                            severity=Severity.LOW,
                            impact=f"{bind_errors} bind security errors accumulated since server start",
                            details="bindSecurityErrors is a cumulative lifetime counter and server uptime was unavailable, so an hourly rate could not be computed - a large total on a long-running server may be normal",
                            remediation="Review access logs for failed bind patterns to determine whether the errors are recent",
                            server=target,
                            metadata={"bind_errors": bind_errors, "uptime_hours": None, "basis": "cumulative"},
                        )
                    )

                total_errors = safe_int(snmp_status.get("errors"))
                if uptime_h is not None:
                    error_rate = total_errors / uptime_h
                    if error_rate > TOTAL_ERRORS_PER_HOUR:
                        findings.append(
                            format_finding(
                                title="High Error Rate",
                                severity=Severity.MEDIUM,
                                impact=f"~{error_rate:.1f} errors/hour ({total_errors} cumulative over {uptime_h:.1f}h uptime)",
                                details=f"The errors counter is cumulative since server start; the rate over {uptime_h:.1f}h of uptime exceeds {TOTAL_ERRORS_PER_HOUR:.0f}/hour and may indicate configuration or client issues",
                                remediation="Review error logs to identify patterns",
                                server=target,
                                metadata={
                                    "total_errors": total_errors,
                                    "rate_per_hour": round(error_rate, 2),
                                    "uptime_hours": round(uptime_h, 2),
                                    "threshold_per_hour": TOTAL_ERRORS_PER_HOUR,
                                },
                            )
                        )
                elif total_errors > TOTAL_ERRORS_CUMULATIVE_GATE:
                    findings.append(
                        format_finding(
                            title="Errors Accumulated",
                            severity=Severity.LOW,
                            impact=f"{total_errors} total errors accumulated since server start",
                            details="The errors counter is a cumulative lifetime counter and server uptime was unavailable, so an hourly rate could not be computed - a large total on a long-running server may be normal",
                            remediation="Review error logs to determine whether the errors are recent",
                            server=target,
                            metadata={"total_errors": total_errors, "uptime_hours": None, "basis": "cumulative"},
                        )
                    )

            except Exception as e:
                mcp.logger.warning("Error getting SNMP stats: %s", e)
                op_data["operation_breakdown"] = {"error": format_error_message(e)}
                probe_failures.append({
                    "probe": "snmp_monitor",
                    "error": format_error_message(e),
                })

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

            _finalize_drilldown(
                op_data, findings, probe_failures,
                f"HEALTHY: {ops_completed:,} operations completed, {ops_pending} pending",
                "operational issue",
            )

            return _sanitize_performance_result(mcp, op_data)

        except Exception as e:
            mcp.logger.error("Error getting operation statistics: %s", e)
            return _sanitize_performance_result(
                mcp, format_tool_error(e, mcp, "operation_statistics", server=target),
            )
        finally:
            if ds:
                try:
                    ds.close()
                except Exception:
                    pass

    @mcp.tool(annotations=_RO, tags={"performance", "live"})
    def get_thread_statistics(server_name: Optional[str] = None) -> Dict[str, Any]:
        """Analyze worker thread utilization and contention. LIVE only.

        Use this when ``first_look`` reports thread contention or
        connections hitting max-threads limits.

        Args:
            server_name: Target server name. Uses default if not specified.

        Returns:
            Current worker thread count from cn=monitor (reported as both
            ``current_threads`` and the deprecated-but-retained
            ``configured_threads`` key - the value is the CURRENT thread
            count, not the configured nsslapd-threadnumber),
            connections at the per-connection thread limit
            (nsslapd-maxthreadsperconn), per-connection thread hits,
            utilization assessment, and tuning recommendations. The process
            thread count (``active_threads``) requires local server access.
        """
        target = server_name or mcp.default_server
        if not target:
            return _sanitize_performance_result(mcp, {
                "type": "thread_statistics",
                "error": "No server configured",
            })
        mcp.require_live(target,"get_thread_statistics")

        ds = None
        try:
            ds = mcp.connection_manager.connect(target)
            monitor = Monitor(ds)
            findings: List[Dict[str, Any]] = []
            probe_failures: List[Dict[str, str]] = []
            is_local = is_local_server(mcp.connection_manager, target)

            try:
                status = monitor.get_attrs_vals_utf8([
                    'threads', 'currentconnectionsatmaxthreads', 'maxthreadsperconnhits',
                    'starttime', 'currenttime'
                ])
            except Exception as e:
                mcp.logger.warning("Error getting monitor status: %s", e)
                status = {}
                probe_failures.append({
                    "probe": "ldap_monitor",
                    "error": format_error_message(e),
                })

            threads = safe_int(status.get("threads"))
            conns_at_max_threads = safe_int(status.get("currentconnectionsatmaxthreads"))
            max_threads_hits = safe_int(status.get("maxthreadsperconnhits"))
            # Uptime basis for rate-converting the cumulative
            # maxThreadsPerConnHits counter
            uptime_h = _uptime_hours(status)

            # The psutil-based process thread count comes from the MCP
            # HOST, so for a remote server it would describe the wrong process.
            # Only probe it when the target is local.
            active_threads: Optional[int] = None
            active_threads_available = False
            active_threads_reason: Optional[str] = None
            if is_local:
                try:
                    resource_stats = monitor.get_resource_stats()
                    active_threads = safe_int(resource_stats.get("total_threads"))
                    active_threads_available = True
                except Exception as e:
                    mcp.logger.debug("Resource stats unavailable: %s", e)
                    active_threads_reason = "Local process thread probe failed"
                    probe_failures.append({
                        "probe": "local_threads",
                        "error": format_error_message(e),
                    })
            else:
                active_threads_reason = (
                    "Process thread count requires local server access "
                    "(is_local=True); a thread count measured on the MCP host "
                    "would describe the MCP host process, not the directory server"
                )

            thread_data = {
                "type": "thread_statistics",
                "server": target,
                # cn=monitor `threads` is the CURRENT operational
                # thread count, not the configured nsslapd-threadnumber.
                # `configured_threads` is a deprecated name retained for
                # response compatibility; prefer `current_threads`.
                "configured_threads": threads,
                "current_threads": threads,
                "threads_source": "cn=monitor threads (current thread count)",
                "active_threads": active_threads,
                "active_threads_available": active_threads_available,
                "connections_at_max_threads": conns_at_max_threads,
                "max_threads_per_conn_hits": max_threads_hits,
            }
            if active_threads_reason:
                thread_data["active_threads_reason"] = active_threads_reason

            if conns_at_max_threads > 0:
                findings.append(
                    format_finding(
                        title="Connections at Per-Connection Thread Limit",
                        severity=Severity.HIGH,
                        impact=f"{conns_at_max_threads} connection(s) are currently at the per-connection thread limit (nsslapd-maxthreadsperconn)",
                        details="currentconnectionsatmaxthreads counts connections that have reached nsslapd-maxthreadsperconn; additional operations on those connections queue until one of their threads frees up",
                        remediation="Identify clients issuing many concurrent operations over a single connection. If that behavior is legitimate, review nsslapd-maxthreadsperconn (the per-connection limit); only consider the global nsslapd-threadnumber if overall worker thread saturation is also observed.",
                        server=target,
                        metadata={"at_max": conns_at_max_threads, "current_threads": threads},
                    )
                )

            # maxThreadsPerConnHits is cumulative since server start.
            if uptime_h is not None:
                hits_rate = max_threads_hits / uptime_h
                if hits_rate > MAX_THREADS_HITS_PER_HOUR:
                    findings.append(
                        format_finding(
                            title="Frequent Max Threads Per Connection Hits",
                            severity=Severity.MEDIUM,
                            impact=f"Per-connection thread limit (nsslapd-maxthreadsperconn) hit ~{hits_rate:.1f} times/hour ({max_threads_hits} cumulative over {uptime_h:.1f}h uptime)",
                            details=f"maxThreadsPerConnHits is cumulative since server start; the rate over {uptime_h:.1f}h of uptime exceeds {MAX_THREADS_HITS_PER_HOUR:.0f}/hour - single connections are repeatedly reaching their per-connection thread limit",
                            remediation="Review nsslapd-maxthreadsperconn (per-connection limit) or investigate client behavior - identify clients issuing many concurrent operations on one connection",
                            server=target,
                            metadata={
                                "hits": max_threads_hits,
                                "rate_per_hour": round(hits_rate, 2),
                                "uptime_hours": round(uptime_h, 2),
                                "threshold_per_hour": MAX_THREADS_HITS_PER_HOUR,
                            },
                        )
                    )
            elif max_threads_hits > MAX_THREADS_HITS_CUMULATIVE_GATE:
                findings.append(
                    format_finding(
                        title="Max Threads Per Connection Hits Accumulated",
                        severity=Severity.LOW,
                        impact=f"Per-connection thread limit (nsslapd-maxthreadsperconn) hit {max_threads_hits} times since server start",
                        details="maxThreadsPerConnHits is a cumulative lifetime counter and server uptime was unavailable, so an hourly rate could not be computed - a large total on a long-running server may be normal",
                        remediation="Check whether the hits are recent (access log err=51 / notes) before tuning nsslapd-maxthreadsperconn (per-connection limit)",
                        server=target,
                        metadata={"hits": max_threads_hits, "uptime_hours": None, "basis": "cumulative"},
                    )
                )

            _finalize_drilldown(
                thread_data, findings, probe_failures,
                f"HEALTHY: {threads} worker threads currently running, no contention detected",
                "thread utilization issue",
            )

            return _sanitize_performance_result(mcp, thread_data)

        except Exception as e:
            mcp.logger.error("Error getting thread statistics: %s", e)
            return _sanitize_performance_result(
                mcp, format_tool_error(e, mcp, "thread_statistics", server=target),
            )
        finally:
            if ds:
                try:
                    ds.close()
                except Exception:
                    pass

    @mcp.tool(annotations=_RO, tags={"performance", "live"})
    def get_resource_utilization(server_name: Optional[str] = None) -> Dict[str, Any]:
        """Get memory, CPU, and disk usage for the Directory Server process. LIVE only.

        Most metrics (RSS, CPU, disk) require local server access.
        Remote servers only report uptime from cn=monitor.

        Args:
            server_name: Target server name. Uses default if not specified.

        Returns:
            Memory (RSS, VMS, swap), CPU utilization, disk space per
            partition, and server uptime. Local-only metrics show as
            unavailable for remote servers.
        """
        target = server_name or mcp.default_server
        if not target:
            return _sanitize_performance_result(mcp, {
                "type": "resource_utilization",
                "error": "No server configured",
            })
        mcp.require_live(target,"get_resource_utilization")

        ds = None
        try:
            ds = mcp.connection_manager.connect(target)
            monitor = Monitor(ds)
            findings: List[Dict[str, Any]] = []
            probe_failures: List[Dict[str, str]] = []

            is_local = is_local_server(mcp.connection_manager, target)

            # Get uptime info from cn=monitor (works for all servers)
            try:
                status = monitor.get_attrs_vals_utf8(['starttime', 'currenttime'])
            except Exception as e:
                mcp.logger.warning("Error getting monitor status: %s", e)
                status = {}
                probe_failures.append({
                    "probe": "ldap_monitor",
                    "error": format_error_message(e),
                })

            # Get resource stats (requires local server with psutil access)
            resource_stats = {}
            local_metrics_available = False
            if is_local:
                try:
                    resource_stats = monitor.get_resource_stats()
                    local_metrics_available = True
                except Exception as e:
                    mcp.logger.debug("Resource stats unavailable: %s", e)
                    probe_failures.append({
                        "probe": "local_resources",
                        "error": format_error_message(e),
                    })
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
            rss = safe_int(resource_stats.get("rss"))
            vms = safe_int(resource_stats.get("vms"))
            swap = safe_int(resource_stats.get("swap"))
            total_mem = safe_int(resource_stats.get("total_mem"))
            mem_rss_pct = safe_float(resource_stats.get("mem_rss_percent"))
            mem_vms_pct = safe_float(resource_stats.get("mem_vms_percent"))
            mem_swap_pct = safe_float(resource_stats.get("mem_swap_percent"))

            cpu_usage = safe_float(resource_stats.get("cpu_usage"))
            total_threads = safe_int(resource_stats.get("total_threads"))
            server_status = resource_stats.get("server_status", ["Unknown"])
            if isinstance(server_status, list):
                server_status = server_status[0]

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
                    "rss_human": format_bytes(rss) if local_metrics_available else "N/A (requires local access)",
                    "rss_percent": mem_rss_pct if local_metrics_available else None,
                    "vms": vms if local_metrics_available else None,
                    "vms_human": format_bytes(vms) if local_metrics_available else "N/A (requires local access)",
                    "vms_percent": mem_vms_pct if local_metrics_available else None,
                    "swap": swap if local_metrics_available else None,
                    "swap_human": format_bytes(swap) if local_metrics_available else "N/A (requires local access)",
                    "swap_percent": mem_swap_pct if local_metrics_available else None,
                    "total_system": total_mem if local_metrics_available else None,
                    "total_system_human": format_bytes(total_mem) if local_metrics_available else "N/A (requires local access)",
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
                        # Parse disk info string (keys are partition/size/used/available/use%)
                        disk_entry = parse_dsdisk_entry(disk)
                        disk_info.append(disk_entry)

                        pct = disk_entry["use_percent"]
                        partition = disk_entry["partition"]
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
                    resource_data["disk"] = {"available": False, "error": format_error_message(e)}
                    probe_failures.append({
                        "probe": "disk",
                        "error": format_error_message(e),
                    })

            if mem_rss_pct > 80:
                findings.append(
                    format_finding(
                        title="High Memory Usage",
                        severity=Severity.HIGH,
                        impact=f"Server using {mem_rss_pct}% of system memory",
                        details=f"RSS: {format_bytes(rss)}, Total: {format_bytes(total_mem)}",
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
                        impact=f"Server has {format_bytes(swap)} in swap ({mem_swap_pct}%)",
                        details="Swap usage degrades performance significantly",
                        remediation="Investigate memory allocation - swap usage indicates memory pressure. Review cache configurations (entry cache, database cache) relative to available physical memory. Consider memory capacity planning if workload requires current cache sizes.",
                        server=target,
                        metadata={"swap": swap, "swap_pct": mem_swap_pct},
                    )
                )

            critical = sum(1 for f in findings if f.get("severity") == "critical")
            if critical > 0:
                # Critical issues take precedence over coverage gaps, but the
                # gap stays visible via evidence_status/probe_failures.
                summary = f"CRITICAL: {critical} critical resource issue(s) require immediate attention"
                if probe_failures:
                    summary += f" ({len(probe_failures)} required probe(s) also failed)"
                resource_data["summary"] = summary
                resource_data["evidence_status"] = "partial" if probe_failures else "complete"
                resource_data["probe_failures"] = probe_failures
                resource_data["findings"] = findings
            else:
                _finalize_drilldown(
                    resource_data, findings, probe_failures,
                    f"HEALTHY: Memory {mem_rss_pct}%, CPU {cpu_usage}%",
                    "resource issue",
                )

            return _sanitize_performance_result(mcp, resource_data)

        except Exception as e:
            mcp.logger.error("Error getting resource utilization: %s", e)
            return _sanitize_performance_result(
                mcp, format_tool_error(e, mcp, "resource_utilization", server=target),
            )
        finally:
            if ds:
                try:
                    ds.close()
                except Exception:
                    pass

    @mcp.tool(annotations=_RO, tags={"performance", "live"})
    def get_performance_summary(server_name: Optional[str] = None) -> Dict[str, Any]:
        """Combined performance overview — the first tool when the server is slow or for any performance question. LIVE only.

        Aggregates cache, connection, operation, thread, and resource metrics
        into a single response with prioritized findings. Use the individual
        tools (``get_cache_statistics``, etc.) to drill into specific areas.

        Args:
            server_name: Target server name. Uses default if not specified.

        Returns:
            Overall health status, key metrics from each category,
            prioritized findings, and top recommendations.
        """
        target = server_name or mcp.default_server
        if not target:
            return _sanitize_performance_result(mcp, {
                "type": "performance_summary",
                "error": "No server configured",
            })
        mcp.require_live(target,"get_performance_summary")

        ds = None
        try:
            ds = mcp.connection_manager.connect(target)
            monitor = Monitor(ds)
            is_local = is_local_server(mcp.connection_manager, target)

            all_findings: List[Dict[str, Any]] = []
            # Required probes that failed to deliver evidence. A "healthy"
            # conclusion is impossible while this list is non-empty.
            probe_failures: List[Dict[str, str]] = []
            monitor_status_ok = False
            summary_data = {
                "type": "performance_summary",
                "server": target,
                "metrics": {},
            }

            try:
                monitor_error = None
                try:
                    status = monitor.get_attrs_vals_utf8([
                        'currentconnections', 'dtablesize', 'opsinitiated',
                        'opscompleted', 'threads', 'currentconnectionsatmaxthreads'
                    ])
                    monitor_status_ok = True
                except Exception as e:
                    mcp.logger.warning("Error getting monitor status: %s", e)
                    status = {}
                    monitor_error = format_error_message(e)
                    probe_failures.append({
                        "probe": "ldap_monitor",
                        "error": monitor_error,
                    })

                # Process resource stats come from psutil on the MCP host, so
                # they are only meaningful (and only required) for local servers.
                resource_stats = {}
                resources_error = None
                if is_local:
                    try:
                        resource_stats = monitor.get_resource_stats()
                    except Exception as e:
                        mcp.logger.debug("Resource stats unavailable: %s", e)
                        resources_error = format_error_message(e)
                        probe_failures.append({
                            "probe": "local_resources",
                            "error": resources_error,
                        })

                if monitor_status_ok:
                    current_conns = safe_int(status.get("currentconnections"))
                    dtable_size = safe_int(status.get("dtablesize"))
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
                            remediation="Investigate connection usage patterns before adjusting limits",
                            server=target,
                        ))

                    ops_initiated = safe_int(status.get("opsinitiated"))
                    ops_completed = safe_int(status.get("opscompleted"))
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

                    threads = safe_int(status.get("threads"))
                    conns_at_max = safe_int(status.get("currentconnectionsatmaxthreads"))

                    # cn=monitor `threads` is the CURRENT thread count,
                    # not nsslapd-threadnumber. `configured` is a deprecated name
                    # retained for compatibility; prefer `current`.
                    summary_data["metrics"]["threads"] = {
                        "configured": threads,
                        "current": threads,
                        "at_max_threads": conns_at_max,
                    }

                    if conns_at_max > 0:
                        all_findings.append(format_finding(
                            title="Thread Contention",
                            severity=Severity.HIGH,
                            impact=f"{conns_at_max} connection(s) at the per-connection thread limit (nsslapd-maxthreadsperconn)",
                            details="Operations on those connections queue until one of their threads frees up",
                            remediation="Use get_thread_statistics to investigate; review nsslapd-maxthreadsperconn (per-connection limit) if the client behavior is legitimate",
                            server=target,
                        ))
                else:
                    # A failed monitor read must not fabricate zero readings —
                    # each dependent section carries an explicit error marker.
                    monitor_error = monitor_error or "monitor status unavailable"
                    summary_data["metrics"]["connections"] = {"error": monitor_error}
                    summary_data["metrics"]["operations"] = {"error": monitor_error}
                    summary_data["metrics"]["threads"] = {"error": monitor_error}

                if is_local and resources_error is not None:
                    summary_data["metrics"]["resources"] = {
                        "memory_pct": None,
                        "memory_human": None,
                        "cpu_pct": None,
                        "available": False,
                        "error": resources_error,
                    }
                elif is_local:
                    mem_rss_pct = safe_float(resource_stats.get("mem_rss_percent"))
                    rss = safe_int(resource_stats.get("rss"))
                    cpu = safe_float(resource_stats.get("cpu_usage"))

                    summary_data["metrics"]["resources"] = {
                        "memory_pct": mem_rss_pct,
                        "memory_human": format_bytes(rss),
                        "cpu_pct": cpu,
                    }

                    if mem_rss_pct > 80:
                        all_findings.append(format_finding(
                            title="High Memory Usage",
                            severity=Severity.HIGH,
                            impact=f"{mem_rss_pct}% of system memory",
                            details=f"RSS: {format_bytes(rss)}",
                            remediation="Investigate memory usage patterns and cache efficiency",
                            server=target,
                        ))
                else:
                    # Remote target: host-process metrics would describe the
                    # MCP host, not the directory server. Explicitly N/A.
                    summary_data["metrics"]["resources"] = {
                        "memory_pct": None,
                        "memory_human": None,
                        "cpu_pct": None,
                        "available": False,
                        "reason": "Process resource metrics require local server access (is_local=True)",
                    }

            except Exception as e:
                mcp.logger.warning("Error gathering performance metrics: %s", e)
                probe_failures.append({
                    "probe": "performance_metrics",
                    "error": format_error_message(e),
                })

            try:
                ldbm_monitor = MonitorLDBM(ds)
                ldbm_status = ldbm_monitor.get_status()

                db_ratio = safe_float(ldbm_status.get("dbcachehitratio"))
                summary_data["metrics"]["cache"] = {
                    "db_hit_ratio": db_ratio,
                }

                if db_ratio < 70 and db_ratio > 0:
                    all_findings.append(format_finding(
                        title="Low Cache Hit Ratio",
                        severity=Severity.MEDIUM,
                        impact=f"DB cache hit ratio is {db_ratio}%",
                        details="Frequent disk reads",
                        remediation="Investigate cache configuration relative to workload",
                        server=target,
                    ))

            except Exception as e:
                mcp.logger.warning("Error getting cache metrics: %s", e)
                summary_data["metrics"]["cache"] = {"error": format_error_message(e)}
                probe_failures.append({
                    "probe": "ldbm_cache",
                    "error": format_error_message(e),
                })

            severity_order = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
            all_findings.sort(key=lambda f: severity_order.get(f.get("severity", "info"), 5))

            critical_count = sum(1 for f in all_findings if f.get("severity") == "critical")
            high_count = sum(1 for f in all_findings if f.get("severity") == "high")

            # The monitor status read is required evidence even when its
            # failure was absorbed above — never conclude healthy without it.
            if not monitor_status_ok and not any(p["probe"] == "ldap_monitor" for p in probe_failures):
                probe_failures.append({
                    "probe": "ldap_monitor",
                    "error": "monitor status unavailable",
                })

            if critical_count > 0:
                overall_health = "critical"
                summary = f"CRITICAL: {critical_count} critical issue(s) require immediate attention"
            elif high_count > 0:
                overall_health = "degraded"
                summary = f"DEGRADED: {high_count} high-priority issue(s) detected"
            elif probe_failures:
                overall_health = "unknown"
                summary = (
                    f"INCOMPLETE: {len(probe_failures)} required probe(s) failed - "
                    "performance health cannot be confirmed"
                )
                if all_findings:
                    summary += f"; {len(all_findings)} issue(s) found in collected evidence"
            elif all_findings:
                overall_health = "fair"
                summary = f"FAIR: {len(all_findings)} minor issue(s) detected"
            else:
                overall_health = "healthy"
                summary = "HEALTHY: All performance metrics within normal ranges"

            summary_data["overall_health"] = overall_health
            summary_data["summary"] = summary
            summary_data["evidence_status"] = "partial" if probe_failures else "complete"
            summary_data["probe_failures"] = probe_failures
            summary_data["findings"] = all_findings
            summary_data["finding_count"] = {
                "critical": critical_count,
                "high": high_count,
                "medium": sum(1 for f in all_findings if f.get("severity") == "medium"),
                "low": sum(1 for f in all_findings if f.get("severity") == "low"),
            }

            return _sanitize_performance_result(mcp, summary_data)

        except Exception as e:
            mcp.logger.error("Error getting performance summary: %s", e)
            return _sanitize_performance_result(
                mcp, format_tool_error(e, mcp, "performance_summary", server=target),
            )
        finally:
            if ds:
                try:
                    ds.close()
                except Exception:
                    pass
