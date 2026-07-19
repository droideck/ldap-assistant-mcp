"""Regression tests: performance tool provenance and metric semantics.

Covers:

- psutil-based probes (socket connection states, process thread
  count) run on the MCP HOST and must never be reported as remote-server
  metrics — remote targets get explicit None + ``available: False``.
- cn=monitor ``readwaiters`` findings describe requests waiting for
  worker threads (not "clients waiting for server response");
  cn=monitor ``threads`` is the CURRENT thread count (mirrored as
  ``current_threads``); ``currentconnectionsatmaxthreads`` remediation
  references the per-connection nsslapd-maxthreadsperconn limit.
- Cumulative SNMP counters (bindsecurityerrors, errors,
  maxthreadsperconnhits) are converted to hourly rates using cn=monitor
  starttime/currenttime; without uptime the finding is LOW with an
  explicit cumulative caveat.
- Each drill-down tool reports evidence_status partial and a
  non-confident summary when a required probe fails.

All tests are non-live: lib389 objects are mocked at the tool-module
boundary (the established phase0 idiom).
"""

from __future__ import annotations

from unittest.mock import MagicMock, patch

import pytest
from fastmcp import Client

import ldap_assistant_mcp.dirsrv_mcp.tools.performance as performance
from ldap_assistant_mcp.core import LDAPServerConfig
from ldap_assistant_mcp.dirsrv_mcp.server import DirSrvMCP
from ldap_assistant_mcp.lib.privacy import PrivacySanitizer

# 10 hours of uptime (see _uptime_hours) — rates divide by 10.
START_TIME = "20260713000000Z"
CURRENT_TIME = "20260713100000Z"
UPTIME_HOURS = 10.0

CONN_STATUS = {
    "currentconnections": "5",
    "totalconnections": "100",
    "dtablesize": "1024",
    "readwaiters": "0",
}

THREAD_STATUS = {
    "threads": "16",
    "currentconnectionsatmaxthreads": "0",
    "maxthreadsperconnhits": "0",
    "starttime": START_TIME,
    "currenttime": CURRENT_TIME,
}

OP_STATUS = {
    "opsinitiated": "200",
    "opscompleted": "200",
    "entriessent": "1000",
    "bytessent": "10000",
    "starttime": START_TIME,
    "currenttime": CURRENT_TIME,
}


@pytest.fixture(autouse=True)
def _isolate_servers_config(monkeypatch):
    """Keep synthetic tests independent of live CI server configuration."""
    monkeypatch.setenv("LDAP_SERVERS_CONFIG", "")


def _monitor_mock(status=None, fail=False, resource_stats=None, resource_fail=False):
    monitor = MagicMock()
    if fail:
        monitor.get_attrs_vals_utf8.side_effect = RuntimeError("monitor read denied")
    else:
        monitor.get_attrs_vals_utf8.return_value = dict(status or {})
    if resource_fail:
        monitor.get_resource_stats.side_effect = RuntimeError("psutil denied")
    else:
        monitor.get_resource_stats.return_value = dict(resource_stats or {})
    return monitor


def _snmp_mock(status=None, fail=False):
    snmp = MagicMock()
    if fail:
        snmp.get_status.side_effect = RuntimeError("snmp read denied")
    else:
        snmp.get_status.return_value = dict(status or {})
    return snmp


def _empty_backends_mock(fail=False):
    coll = MagicMock()
    if fail:
        coll.list.side_effect = RuntimeError("backend list denied")
    else:
        coll.list.return_value = []
    return coll


@pytest.fixture
def local_server(mock_env) -> DirSrvMCP:
    """A live *local* server config (enables local-only psutil probes)."""
    cfg = LDAPServerConfig(
        name="local1",
        hostname="localhost",
        port=33891,
        bind_dn="cn=Directory Manager",
        bind_password="TestPassword123",
        base_dn="dc=test,dc=com",
        is_local=True,
        serverid="local1",
    )
    return DirSrvMCP(servers=[cfg], include_env_fallback=False)


async def _call_tool(server, tool_name, monitor, extra_patches=(), args=None):
    patches = [
        patch.object(performance, "Monitor", return_value=monitor),
        patch.object(server.connection_manager, "connect", return_value=MagicMock()),
        *extra_patches,
    ]
    try:
        for p in patches:
            p.start()
        async with Client(server) as client:
            result = await client.call_tool(tool_name, args or {})
            return result.data
    finally:
        for p in patches:
            p.stop()


# ---------------------------------------------------------------------------
# Remote provenance: connection states
# ---------------------------------------------------------------------------


class TestConnectionStateProvenance:
    async def test_remote_states_do_not_report_host_data(self, dirsrv_server):
        """The MCP host's own sockets must never appear as server state."""
        monitor = _monitor_mock(
            CONN_STATUS,
            resource_stats={  # host data that must NOT be reported
                "connection_count": "42",
                "connection_established_count": "40",
                "connection_close_wait_count": "1",
                "connection_time_wait_count": "1",
            },
        )
        data = await _call_tool(dirsrv_server, "get_connection_statistics", monitor)
        states = data["connection_states"]
        # Pre-existing sub-keys stay present (live-test contract) but hold
        # None instead of MCP-host socket counts.
        for key in ("total", "established", "close_wait", "time_wait"):
            assert key in states
            assert states[key] is None
        assert states["available"] is False
        assert "local server access" in states["reason"]
        monitor.get_resource_stats.assert_not_called()
        # A remote N/A section is not an evidence gap
        assert data["evidence_status"] == "complete"
        assert data["summary"].startswith("HEALTHY")

    async def test_local_states_are_reported(self, local_server):
        monitor = _monitor_mock(
            CONN_STATUS,
            resource_stats={
                "connection_count": "7",
                "connection_established_count": "5",
                "connection_close_wait_count": "1",
                "connection_time_wait_count": "1",
            },
        )
        data = await _call_tool(local_server, "get_connection_statistics", monitor)
        states = data["connection_states"]
        assert states["available"] is True
        assert states["total"] == 7
        assert states["established"] == 5
        assert "reason" not in states
        assert data["evidence_status"] == "complete"

    async def test_local_state_probe_failure_is_incomplete(self, local_server):
        monitor = _monitor_mock(CONN_STATUS, resource_fail=True)
        data = await _call_tool(local_server, "get_connection_statistics", monitor)
        assert data["connection_states"]["available"] is False
        assert data["connection_states"]["total"] is None
        assert data["evidence_status"] == "partial"
        assert data["summary"].startswith("INCOMPLETE")
        assert any(p["probe"] == "local_connection_states" for p in data["probe_failures"])

    async def test_shape_compatibility(self, dirsrv_server):
        data = await _call_tool(
            dirsrv_server, "get_connection_statistics", _monitor_mock(CONN_STATUS)
        )
        for key in ("type", "server", "current_connections", "total_connections",
                    "max_file_descriptors", "fd_utilization_pct", "read_waiters",
                    "connection_states", "summary", "findings"):
            assert key in data, f"missing pre-existing key {key}"


# ---------------------------------------------------------------------------
# Remote provenance: process thread count
# ---------------------------------------------------------------------------


class TestThreadProvenance:
    async def test_remote_active_threads_not_from_host(self, dirsrv_server):
        monitor = _monitor_mock(THREAD_STATUS, resource_stats={"total_threads": "99"})
        data = await _call_tool(dirsrv_server, "get_thread_statistics", monitor)
        assert data["active_threads"] is None
        assert data["active_threads_available"] is False
        assert "MCP host" in data["active_threads_reason"]
        monitor.get_resource_stats.assert_not_called()
        # cn=monitor threads value stays available via LDAP
        assert data["configured_threads"] == 16
        assert data["current_threads"] == 16
        assert data["threads_source"] == "cn=monitor threads (current thread count)"
        assert data["evidence_status"] == "complete"

    async def test_local_active_threads_reported(self, local_server):
        monitor = _monitor_mock(THREAD_STATUS, resource_stats={"total_threads": "42"})
        data = await _call_tool(local_server, "get_thread_statistics", monitor)
        assert data["active_threads"] == 42
        assert data["active_threads_available"] is True

    async def test_local_thread_probe_failure_is_incomplete(self, local_server):
        monitor = _monitor_mock(THREAD_STATUS, resource_fail=True)
        data = await _call_tool(local_server, "get_thread_statistics", monitor)
        assert data["active_threads"] is None
        assert data["evidence_status"] == "partial"
        assert data["summary"].startswith("INCOMPLETE")
        assert any(p["probe"] == "local_threads" for p in data["probe_failures"])

    async def test_shape_compatibility(self, dirsrv_server):
        data = await _call_tool(
            dirsrv_server, "get_thread_statistics", _monitor_mock(THREAD_STATUS)
        )
        for key in ("type", "server", "configured_threads", "active_threads",
                    "connections_at_max_threads", "max_threads_per_conn_hits",
                    "summary", "findings"):
            assert key in data, f"missing pre-existing key {key}"


# ---------------------------------------------------------------------------
# Corrected metric semantics
# ---------------------------------------------------------------------------


class TestCorrectedSemantics:
    async def test_readwaiters_finding_direction(self, dirsrv_server):
        """readwaiters = requests waiting for a worker thread, not clients
        waiting for a response."""
        status = dict(CONN_STATUS, readwaiters="25")
        data = await _call_tool(
            dirsrv_server, "get_connection_statistics", _monitor_mock(status)
        )
        finding = next(f for f in data["findings"] if "read_waiters" in f.get("metadata", {}))
        text = " ".join([finding["title"], finding["impact"], finding["details"]])
        assert "worker thread" in text.lower()
        assert "waiting for server response" not in text
        # Remediation targets the global worker pool (correct direction)
        assert "nsslapd-threadnumber" in finding["remediation"]

    async def test_conns_at_max_threads_names_per_conn_limit(self, dirsrv_server):
        status = dict(THREAD_STATUS, currentconnectionsatmaxthreads="3")
        data = await _call_tool(
            dirsrv_server, "get_thread_statistics", _monitor_mock(status)
        )
        finding = next(f for f in data["findings"] if f["severity"] == "high")
        assert "nsslapd-maxthreadsperconn" in finding["impact"]
        assert "nsslapd-maxthreadsperconn" in finding["remediation"]
        assert "per-connection" in finding["remediation"]

    async def test_healthy_summary_does_not_say_configured(self, dirsrv_server):
        data = await _call_tool(
            dirsrv_server, "get_thread_statistics", _monitor_mock(THREAD_STATUS)
        )
        assert "configured threads" not in data["summary"]
        assert data["summary"].startswith("HEALTHY")

    async def test_summary_metrics_mirror_current_threads(self, dirsrv_server):
        ldbm = MagicMock()
        ldbm.get_status.return_value = {"dbcachehitratio": "95"}
        monitor = _monitor_mock({
            "currentconnections": "5", "dtablesize": "1024",
            "opsinitiated": "200", "opscompleted": "200",
            "threads": "16", "currentconnectionsatmaxthreads": "0",
        })
        with patch.object(performance, "MonitorLDBM", return_value=ldbm):
            data = await _call_tool(dirsrv_server, "get_performance_summary", monitor)
        assert data["metrics"]["threads"]["configured"] == 16  # retained
        assert data["metrics"]["threads"]["current"] == 16  # truthful mirror


# ---------------------------------------------------------------------------
# Cumulative counters vs rate thresholds
# ---------------------------------------------------------------------------


class TestCumulativeCounterRates:
    async def _run_ops(self, server, snmp_status, monitor_status=None):
        snmp = _snmp_mock(snmp_status)
        return await _call_tool(
            server, "get_operation_statistics",
            _monitor_mock(monitor_status or OP_STATUS),
            extra_patches=[patch.object(performance, "MonitorSNMP", return_value=snmp)],
        )

    async def test_high_rate_counters_flagged_with_uptime_basis(self, dirsrv_server):
        # 5000/10h = 500/h > 60; 50000/10h = 5000/h > 600
        data = await self._run_ops(
            dirsrv_server, {"bindsecurityerrors": "5000", "errors": "50000"}
        )
        bind = next(f for f in data["findings"] if "bind_errors" in f.get("metadata", {}))
        assert bind["severity"] == "medium"
        assert bind["metadata"]["rate_per_hour"] == pytest.approx(500.0)
        assert bind["metadata"]["uptime_hours"] == pytest.approx(UPTIME_HOURS)
        assert "cumulative" in bind["details"]
        err = next(f for f in data["findings"] if "total_errors" in f.get("metadata", {}))
        assert err["severity"] == "medium"
        assert err["metadata"]["rate_per_hour"] == pytest.approx(5000.0)

    async def test_low_rate_long_uptime_not_flagged(self, dirsrv_server):
        """Counts above the old absolute gates but below the hourly rate
        thresholds must no longer produce findings."""
        # 300/10h = 30/h < 60; 3000/10h = 300/h < 600 (old code flagged both)
        data = await self._run_ops(
            dirsrv_server, {"bindsecurityerrors": "300", "errors": "3000"}
        )
        assert data["findings"] == []
        assert data["summary"].startswith("HEALTHY")
        assert data["evidence_status"] == "complete"

    async def test_no_uptime_downgrades_to_low_with_caveat(self, dirsrv_server):
        no_uptime = {k: v for k, v in OP_STATUS.items()
                     if k not in ("starttime", "currenttime")}
        data = await self._run_ops(
            dirsrv_server, {"bindsecurityerrors": "5000", "errors": "50000"},
            monitor_status=no_uptime,
        )
        for finding in data["findings"]:
            assert finding["severity"] == "low"
            assert "cumulative" in finding["details"]
            assert "uptime was unavailable" in finding["details"]
            assert finding["metadata"]["basis"] == "cumulative"

    async def test_max_threads_hits_rate_based(self, dirsrv_server):
        # 5000/10h = 500/h > 60
        status = dict(THREAD_STATUS, maxthreadsperconnhits="5000")
        data = await _call_tool(
            dirsrv_server, "get_thread_statistics", _monitor_mock(status)
        )
        finding = next(f for f in data["findings"] if "hits" in f.get("metadata", {}))
        assert finding["severity"] == "medium"
        assert finding["metadata"]["rate_per_hour"] == pytest.approx(500.0)
        assert "nsslapd-maxthreadsperconn" in finding["remediation"]

    async def test_max_threads_hits_low_rate_not_flagged(self, dirsrv_server):
        # 300/10h = 30/h < 60 (old code flagged >100 absolute)
        status = dict(THREAD_STATUS, maxthreadsperconnhits="300")
        data = await _call_tool(
            dirsrv_server, "get_thread_statistics", _monitor_mock(status)
        )
        assert data["findings"] == []

    async def test_max_threads_hits_no_uptime_is_low(self, dirsrv_server):
        status = {k: v for k, v in THREAD_STATUS.items()
                  if k not in ("starttime", "currenttime")}
        status["maxthreadsperconnhits"] = "5000"
        data = await _call_tool(
            dirsrv_server, "get_thread_statistics", _monitor_mock(status)
        )
        finding = next(f for f in data["findings"] if "hits" in f.get("metadata", {}))
        assert finding["severity"] == "low"
        assert "uptime was unavailable" in finding["details"]


class TestUptimeHelper:
    def test_parses_strings_and_lists(self):
        assert performance._uptime_hours(
            {"starttime": START_TIME, "currenttime": CURRENT_TIME}
        ) == pytest.approx(10.0)
        assert performance._uptime_hours(
            {"starttime": [START_TIME], "currenttime": [CURRENT_TIME]}
        ) == pytest.approx(10.0)

    def test_missing_or_bad_values_return_none(self):
        assert performance._uptime_hours({}) is None
        assert performance._uptime_hours(
            {"starttime": "garbage", "currenttime": CURRENT_TIME}
        ) is None
        # Non-positive uptime is unusable as a rate denominator
        assert performance._uptime_hours(
            {"starttime": CURRENT_TIME, "currenttime": START_TIME}
        ) is None


# ---------------------------------------------------------------------------
# Drill-down evidence completeness
# ---------------------------------------------------------------------------


class TestDrilldownEvidence:
    async def test_cache_ldbm_probe_failure_is_incomplete(self, dirsrv_server):
        ldbm = MagicMock()
        ldbm.get_status.side_effect = RuntimeError("ldbm denied")
        data = await _call_tool(
            dirsrv_server, "get_cache_statistics", _monitor_mock(),
            extra_patches=[
                patch.object(performance, "MonitorLDBM", return_value=ldbm),
                patch.object(performance, "Backends", return_value=_empty_backends_mock()),
            ],
        )
        assert data["evidence_status"] == "partial"
        assert data["summary"].startswith("INCOMPLETE")
        assert any(p["probe"] == "ldbm_monitor" for p in data["probe_failures"])
        assert "error" in data["global_db_cache"]  # pre-existing shape retained

    async def test_cache_backend_list_failure_is_incomplete(self, dirsrv_server):
        ldbm = MagicMock()
        ldbm.get_status.return_value = {
            "dbcachehits": "900", "dbcachetries": "10000", "dbcachehitratio": "90",
        }
        data = await _call_tool(
            dirsrv_server, "get_cache_statistics", _monitor_mock(),
            extra_patches=[
                patch.object(performance, "MonitorLDBM", return_value=ldbm),
                patch.object(performance, "Backends",
                             return_value=_empty_backends_mock(fail=True)),
            ],
        )
        assert data["evidence_status"] == "partial"
        assert data["summary"].startswith("INCOMPLETE")
        assert any(p["probe"] == "backend_list" for p in data["probe_failures"])

    async def test_cache_complete_evidence_is_normal(self, dirsrv_server):
        ldbm = MagicMock()
        ldbm.get_status.return_value = {
            "dbcachehits": "900", "dbcachetries": "10000", "dbcachehitratio": "90",
        }
        data = await _call_tool(
            dirsrv_server, "get_cache_statistics", _monitor_mock(),
            extra_patches=[
                patch.object(performance, "MonitorLDBM", return_value=ldbm),
                patch.object(performance, "Backends", return_value=_empty_backends_mock()),
            ],
        )
        assert data["evidence_status"] == "complete"
        assert data["probe_failures"] == []
        assert not data["summary"].startswith("INCOMPLETE")

    async def test_connection_monitor_failure_is_incomplete(self, dirsrv_server):
        data = await _call_tool(
            dirsrv_server, "get_connection_statistics", _monitor_mock(fail=True)
        )
        assert data["evidence_status"] == "partial"
        assert data["summary"].startswith("INCOMPLETE")
        assert any(p["probe"] == "ldap_monitor" for p in data["probe_failures"])

    async def test_operation_snmp_failure_is_incomplete(self, dirsrv_server):
        snmp = _snmp_mock(fail=True)
        data = await _call_tool(
            dirsrv_server, "get_operation_statistics", _monitor_mock(OP_STATUS),
            extra_patches=[patch.object(performance, "MonitorSNMP", return_value=snmp)],
        )
        assert data["evidence_status"] == "partial"
        assert data["summary"].startswith("INCOMPLETE")
        assert any(p["probe"] == "snmp_monitor" for p in data["probe_failures"])
        assert "error" in data["operation_breakdown"]  # pre-existing shape retained

    async def test_operation_complete_evidence_is_healthy(self, dirsrv_server):
        snmp = _snmp_mock({})
        data = await _call_tool(
            dirsrv_server, "get_operation_statistics", _monitor_mock(OP_STATUS),
            extra_patches=[patch.object(performance, "MonitorSNMP", return_value=snmp)],
        )
        assert data["evidence_status"] == "complete"
        assert data["summary"].startswith("HEALTHY")

    async def test_thread_monitor_failure_is_incomplete(self, dirsrv_server):
        data = await _call_tool(
            dirsrv_server, "get_thread_statistics", _monitor_mock(fail=True)
        )
        assert data["evidence_status"] == "partial"
        assert data["summary"].startswith("INCOMPLETE")
        assert any(p["probe"] == "ldap_monitor" for p in data["probe_failures"])

    async def test_resource_monitor_failure_is_incomplete(self, dirsrv_server):
        data = await _call_tool(
            dirsrv_server, "get_resource_utilization", _monitor_mock(fail=True)
        )
        assert data["evidence_status"] == "partial"
        # Remote targets always carry the INFO limited-metrics finding, so
        # the summary is the combined non-confident form.
        assert data["summary"].startswith("ATTENTION (incomplete evidence)")
        assert any(p["probe"] == "ldap_monitor" for p in data["probe_failures"])

    async def test_resource_local_disk_failure_is_incomplete(self, local_server):
        disk_monitor = MagicMock()
        disk_monitor.get_disks.side_effect = RuntimeError("disk probe denied")
        monitor = _monitor_mock(
            {"starttime": START_TIME, "currenttime": CURRENT_TIME},
            resource_stats={"rss": "1048576", "mem_rss_percent": "10",
                            "cpu_usage": "5", "total_threads": "40"},
        )
        data = await _call_tool(
            local_server, "get_resource_utilization", monitor,
            extra_patches=[
                patch.object(performance, "MonitorDiskSpace", return_value=disk_monitor),
            ],
        )
        assert data["evidence_status"] == "partial"
        assert data["summary"].startswith("INCOMPLETE")
        assert any(p["probe"] == "disk" for p in data["probe_failures"])

    async def test_resource_local_complete_evidence_is_healthy(self, local_server):
        disk_monitor = MagicMock()
        disk_monitor.get_disks.return_value = []
        monitor = _monitor_mock(
            {"starttime": START_TIME, "currenttime": CURRENT_TIME},
            resource_stats={"rss": "1048576", "mem_rss_percent": "10",
                            "cpu_usage": "5", "total_threads": "40"},
        )
        data = await _call_tool(
            local_server, "get_resource_utilization", monitor,
            extra_patches=[
                patch.object(performance, "MonitorDiskSpace", return_value=disk_monitor),
            ],
        )
        assert data["evidence_status"] == "complete"
        assert data["probe_failures"] == []
        assert data["summary"].startswith("HEALTHY")


# ---------------------------------------------------------------------------
# Privacy: new evidence keys in drill-downs must be sanitized
# ---------------------------------------------------------------------------


class TestDrilldownSanitization:
    def _make_mcp(self):
        mcp = MagicMock()
        mcp.privacy_enabled = True
        mcp.sanitizer = PrivacySanitizer()
        return mcp

    def test_drilldown_probe_failures_are_sanitized(self):
        result = {
            "type": "connection_statistics",
            "probe_failures": [
                {"probe": "ldap_monitor",
                 "error": "denied at secret-host.example.com"},
            ],
            "connection_states": {
                "available": False,
                "total": None, "established": None,
                "close_wait": None, "time_wait": None,
                "reason": "Connection state breakdown requires local server access",
            },
        }
        sanitized = performance._sanitize_performance_result(self._make_mcp(), result)
        assert "secret-host.example.com" not in sanitized["probe_failures"][0]["error"]
        # Static N/A shape passes through untouched
        assert sanitized["connection_states"]["available"] is False
