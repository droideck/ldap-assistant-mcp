"""Regression tests: no false all-clear from failed required probes.

Invariant: within ``first_look``,
``run_healthcheck``, ``get_performance_summary``,
``list_replication_conflicts``, ``analyze_index_configuration``, and
offline/archive ``validate_configuration``, a healthy/OK/no-conflicts
all-clear is impossible unless every required probe for that conclusion
completed successfully with sufficient evidence.

Each test class injects a deterministic failure into one required probe and
asserts the public conclusion is explicitly incomplete/non-healthy, plus a
positive control proving complete healthy evidence still reports healthy.
All tests are non-live: lib389 objects are mocked at the tool-module
boundary (the established phase0 idiom).
"""

from __future__ import annotations

from unittest.mock import MagicMock, patch

import pytest
from fastmcp import Client
from lib389._mapped_object_lint import DSLint, DSLints

import ldap_assistant_mcp.dirsrv_mcp.tools.archive as archive
import ldap_assistant_mcp.dirsrv_mcp.tools.health as health
import ldap_assistant_mcp.dirsrv_mcp.tools.indexes as indexes
import ldap_assistant_mcp.dirsrv_mcp.tools.performance as performance
import ldap_assistant_mcp.dirsrv_mcp.tools.replication as replication
from ldap_assistant_mcp.core import LDAPServerConfig
from ldap_assistant_mcp.dirsrv_mcp.server import DirSrvMCP
from ldap_assistant_mcp.lib.privacy import PrivacySanitizer

HEALTHY_MONITOR_STATUS = {
    "currentconnections": "5",
    "totalconnections": "100",
    "dtablesize": "1024",
    "threads": "16",
    "currentconnectionsatmaxthreads": "0",
    "opsinitiated": "200",
    "opscompleted": "200",
}


@pytest.fixture(autouse=True)
def _isolate_servers_config(monkeypatch):
    """Keep synthetic tests independent of live CI server configuration."""
    monkeypatch.setenv("LDAP_SERVERS_CONFIG", "")


def _monitor_mock(status=None, fail=False):
    monitor = MagicMock()
    if fail:
        monitor.get_attrs_vals_utf8.side_effect = RuntimeError("monitor read denied")
    else:
        monitor.get_attrs_vals_utf8.return_value = dict(status or HEALTHY_MONITOR_STATUS)
    return monitor


def _empty_collection_mock(fail=False):
    coll = MagicMock()
    if fail:
        coll.list.side_effect = RuntimeError("search denied")
    else:
        coll.list.return_value = []
    return coll


@pytest.fixture
def local_server(mock_env) -> DirSrvMCP:
    """A live *local* server config (enables local-only probes)."""
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


@pytest.fixture
def offline_server(mock_env) -> DirSrvMCP:
    """A stopped local instance (offline mode)."""
    cfg = LDAPServerConfig(
        name="off1",
        hostname="localhost",
        port=0,
        is_local=True,
        serverid="off1",
        is_offline=True,
    )
    return DirSrvMCP(servers=[cfg], include_env_fallback=False)


# ---------------------------------------------------------------------------
# AC-01 — first_look (live)
# ---------------------------------------------------------------------------


class TestFirstLookLive:
    async def _run(self, server, monitor=None, replicas=None, backends=None):
        with patch.object(health, "Monitor", return_value=monitor or _monitor_mock()), \
             patch.object(health, "Replicas", return_value=replicas or _empty_collection_mock()), \
             patch.object(health, "Backends", return_value=backends or _empty_collection_mock()), \
             patch.object(server.connection_manager, "connect", return_value=MagicMock()):
            async with Client(server) as client:
                result = await client.call_tool("first_look", {})
                return result.data

    async def test_connection_probe_failure_is_not_healthy(self, dirsrv_server):
        data = await self._run(dirsrv_server, monitor=_monitor_mock(fail=True))
        assert data["overall_health"] != "healthy"
        assert data["overall_health"] == "unknown"
        assert data["summary"].startswith("INCOMPLETE")
        assert data["evidence_status"] == "partial"
        assert any(g["probe"] == "connections" for g in data["evidence_gaps"])
        # No success finding may claim the server is healthy
        assert not any("is healthy" in f["title"] for f in data["findings"])

    async def test_replication_probe_failure_is_not_healthy(self, dirsrv_server):
        data = await self._run(dirsrv_server, replicas=_empty_collection_mock(fail=True))
        assert data["overall_health"] == "unknown"
        assert any(g["probe"] == "replication" for g in data["evidence_gaps"])
        assert not any("is healthy" in f["title"] for f in data["findings"])

    async def test_backend_cache_probe_failure_is_not_healthy(self, dirsrv_server):
        data = await self._run(dirsrv_server, backends=_empty_collection_mock(fail=True))
        assert data["overall_health"] == "unknown"
        assert any(g["probe"] == "cache" for g in data["evidence_gaps"])

    async def test_local_disk_probe_failure_is_not_healthy(self, local_server):
        disk_monitor = MagicMock()
        disk_monitor.get_disks.side_effect = RuntimeError("disk probe denied")
        nss = MagicMock()
        nss.list_certs.return_value = []
        with patch.object(health, "MonitorDiskSpace", return_value=disk_monitor), \
             patch.object(health, "NssSsl", return_value=nss):
            data = await self._run(local_server)
        assert data["overall_health"] == "unknown"
        assert any(g["probe"] == "disk" for g in data["evidence_gaps"])

    async def test_local_certificate_probe_failure_is_not_healthy(self, local_server):
        disk_monitor = MagicMock()
        disk_monitor.get_disks.return_value = []
        nss = MagicMock()
        nss.list_certs.side_effect = RuntimeError("NSS DB unreadable")
        with patch.object(health, "MonitorDiskSpace", return_value=disk_monitor), \
             patch.object(health, "NssSsl", return_value=nss):
            data = await self._run(local_server)
        assert data["overall_health"] == "unknown"
        assert any(g["probe"] == "certificates" for g in data["evidence_gaps"])

    async def test_evidence_gap_outranks_fair_verdict(self, dirsrv_server):
        """Medium findings from partial evidence must not read as a fully
        observed FAIR system — incomplete evidence wins (unknown)."""
        # Cache probe yields a MEDIUM finding (60% hit ratio, active backend)
        be = MagicMock()
        be.get_attr_val_utf8.return_value = "userroot"
        be_monitor = MagicMock()
        be_monitor.get_status.return_value = {
            "entrycachehits": "1200",
            "entrycachetries": "2000",
            "entrycachehitratio": "60",
        }
        be.get_monitor.return_value = be_monitor
        backends = MagicMock()
        backends.list.return_value = [be]
        # ... while the replication probe fails (evidence gap)
        data = await self._run(
            dirsrv_server,
            replicas=_empty_collection_mock(fail=True),
            backends=backends,
        )
        assert data["overall_health"] == "unknown"
        assert data["summary"].startswith("INCOMPLETE")
        assert "issue(s) found in collected evidence" in data["summary"]
        assert data["medium_count"] == 1

    async def test_complete_evidence_still_reports_healthy(self, dirsrv_server):
        """Positive control: all probes succeed -> healthy, complete."""
        data = await self._run(dirsrv_server)
        assert data["overall_health"] == "healthy"
        assert data["summary"].startswith("HEALTHY")
        assert data["evidence_status"] == "complete"
        assert data["evidence_gaps"] == []
        assert any("is healthy" in f["title"] for f in data["findings"])
        # Remote N/A sections must not count as evidence gaps
        detailed = data["detailed_metrics"][data["servers_checked"][0]]
        assert detailed["disk"]["available"] is False
        assert "reason" in detailed["disk"]

    async def test_shape_compatibility(self, dirsrv_server):
        """AC-06: pre-existing keys remain with their existing types."""
        data = await self._run(dirsrv_server)
        for key in (
            "type", "summary", "overall_health", "critical_count", "high_count",
            "medium_count", "low_count", "info_count", "findings",
            "servers_checked", "servers_failed", "total_servers", "metrics",
            "detailed_metrics",
        ):
            assert key in data, f"missing pre-existing key {key}"
        assert isinstance(data["findings"], list)
        assert isinstance(data["metrics"], dict)


# ---------------------------------------------------------------------------
# AC-01 — first_look (offline/archive)
# ---------------------------------------------------------------------------


class FakeCleanFSChecks:
    """FSChecks stand-in with no _lint_* methods (clean pass)."""

    def __init__(self, ds=None):
        pass


class TestFirstLookOffline:
    async def _run(self, server, dse_path):
        with patch.object(health, "_get_dse_ldif_path", return_value=str(dse_path)), \
             patch.object(server.connection_manager, "connect", return_value=MagicMock()):
            async with Client(server) as client:
                result = await client.call_tool("first_look", {})
                return result.data

    async def test_dse_read_failure_is_not_healthy(self, offline_server, tmp_path):
        """offline_dse_lint: unreadable dse.ldif must not aggregate HEALTHY."""
        with patch.object(health, "FSChecks", FakeCleanFSChecks):
            data = await self._run(offline_server, tmp_path / "missing" / "dse.ldif")
        assert data["overall_health"] == "unknown"
        assert data["summary"].startswith("INCOMPLETE")
        probes = {g["probe"] for g in data["evidence_gaps"]}
        assert "dse" in probes
        # The metrics summary must not claim status ok
        assert data["metrics"]["off1"]["status"] == "incomplete"

    async def test_fs_lint_failure_is_not_healthy(self, offline_server, tmp_path):
        """offline_filesystem_lint: a crashed FSChecks pass is a gap."""
        dse = tmp_path / "dse.ldif"
        dse.write_text("dn: cn=config\ncn: config\n\n")

        class ExplodingFSChecks:
            def __init__(self, ds=None):
                raise RuntimeError("cannot stat instance directories")

        with patch.object(health, "FSChecks", ExplodingFSChecks):
            data = await self._run(offline_server, dse)
        assert data["overall_health"] == "unknown"
        assert any(g["probe"] == "fs_checks" for g in data["evidence_gaps"])

    async def test_offline_complete_evidence_reports_healthy(self, offline_server, tmp_path):
        """Positive control: clean offline probes stay healthy."""
        dse = tmp_path / "dse.ldif"
        dse.write_text("dn: cn=config\ncn: config\n\n")
        with patch.object(health, "FSChecks", FakeCleanFSChecks):
            data = await self._run(offline_server, dse)
        assert data["overall_health"] == "healthy"
        assert data["evidence_status"] == "complete"
        assert data["evidence_gaps"] == []


# ---------------------------------------------------------------------------
# AC-05 — run_healthcheck
# ---------------------------------------------------------------------------


class FakeConfig(DSLint):
    def __init__(self, ds=None):
        pass

    @classmethod
    def lint_uid(cls):
        return "config"

    def _lint_passwordscheme(self):
        return iter(())


class FakeBrokenTarget:
    """Category whose construction fails (discovery failure)."""

    def __init__(self, ds=None):
        raise RuntimeError("cannot instantiate without config")


class FakeEnumFailure(DSLints):
    """Category whose child enumeration fails."""

    def __init__(self, ds=None):
        pass

    @classmethod
    def lint_uid(cls):
        return "enumfail"

    def list(self):
        raise RuntimeError("cannot enumerate children")


class FakeMalformedTarget(DSLint):
    """Category yielding malformed (non-dict) lint evidence."""

    def __init__(self, ds=None):
        pass

    @classmethod
    def lint_uid(cls):
        return "malformed"

    def _lint_garbage(self):
        yield "this is not a dict"


class FakeExplodingCheck(DSLint):
    """Category whose lint check raises during execution."""

    def __init__(self, ds=None):
        pass

    @classmethod
    def lint_uid(cls):
        return "exploding"

    def _lint_boom(self):
        raise RuntimeError("lint blew up mid-run")


class TestRunHealthcheck:
    async def _run(self, server, check_objects, args=None):
        with patch.object(health, "CHECK_OBJECTS", check_objects), \
             patch.object(server.connection_manager, "connect", return_value=MagicMock()):
            async with Client(server) as client:
                result = await client.call_tool("run_healthcheck", args or {})
                return result.data

    async def test_category_construction_failure_is_incomplete(self, dirsrv_server):
        data = await self._run(dirsrv_server, [FakeBrokenTarget, FakeConfig])
        assert not data["summary"].startswith("HEALTHY")
        assert data["summary"].startswith("INCOMPLETE")
        assert data["evidence_status"] == "partial"
        assert data["discovery_errors"]
        assert data["discovery_errors"][0]["category"] == "FakeBrokenTarget"

    async def test_category_enumeration_failure_is_incomplete(self, dirsrv_server):
        data = await self._run(dirsrv_server, [FakeEnumFailure, FakeConfig])
        assert data["summary"].startswith("INCOMPLETE")
        assert any(e["category"] == "FakeEnumFailure" for e in data["discovery_errors"])

    async def test_empty_discovery_is_unknown_not_healthy(self, dirsrv_server):
        """'HEALTHY: 0 checks passed' must be impossible."""
        data = await self._run(dirsrv_server, [FakeBrokenTarget])
        assert not data["summary"].startswith("HEALTHY")
        assert data["summary"].startswith("UNKNOWN")
        assert data["evidence_status"] == "unavailable"
        assert data["total_checks_run"] == 0

    async def test_malformed_lint_evidence_is_not_passed(self, dirsrv_server):
        data = await self._run(dirsrv_server, [FakeMalformedTarget, FakeConfig])
        assert data["summary"].startswith("INCOMPLETE")
        failed = {c["check"] for c in data["checks_failed"]}
        assert "malformed:garbage" in failed
        assert "malformed:garbage" not in data["checks_executed"]
        # The successfully completed check is still counted
        assert "config:passwordscheme" in data["checks_executed"]

    async def test_execution_exception_is_not_ok(self, dirsrv_server):
        """A crashed check must not produce an OK-labelled all-clear."""
        data = await self._run(dirsrv_server, [FakeExplodingCheck, FakeConfig])
        assert not data["summary"].startswith("OK")
        assert not data["summary"].startswith("HEALTHY")
        assert data["summary"].startswith("INCOMPLETE")
        failed = {c["check"] for c in data["checks_failed"]}
        assert "exploding:boom" in failed
        assert "exploding:boom" not in data["checks_executed"]
        # The failure also stays visible as a finding
        assert any(
            f.get("metadata", {}).get("dsle") == "RUNTIME_ERROR" for f in data["findings"]
        )

    async def test_complete_run_still_reports_healthy(self, dirsrv_server):
        """Positive control with at least one successful check."""
        data = await self._run(dirsrv_server, [FakeConfig])
        assert data["summary"].startswith("HEALTHY")
        assert data["evidence_status"] == "complete"
        assert data["checks_failed"] == []
        assert data["checks_executed"] == ["config:passwordscheme"]
        assert data["total_checks_run"] == 1

    async def test_shape_compatibility(self, dirsrv_server):
        data = await self._run(dirsrv_server, [FakeConfig])
        for key in (
            "type", "server", "is_local", "summary", "critical_count",
            "high_count", "medium_count", "low_count", "info_count",
            "total_issues", "findings", "checks_executed", "checks_skipped",
            "total_checks_run",
        ):
            assert key in data, f"missing pre-existing key {key}"


# ---------------------------------------------------------------------------
# AC-02 — get_performance_summary
# ---------------------------------------------------------------------------


class TestPerformanceSummary:
    async def _run(self, server, monitor=None, ldbm=None):
        ldbm_mock = ldbm
        if ldbm_mock is None:
            ldbm_mock = MagicMock()
            ldbm_mock.get_status.return_value = {"dbcachehitratio": "95"}
        with patch.object(performance, "Monitor", return_value=monitor or _monitor_mock()), \
             patch.object(performance, "MonitorLDBM", return_value=ldbm_mock), \
             patch.object(server.connection_manager, "connect", return_value=MagicMock()):
            async with Client(server) as client:
                result = await client.call_tool("get_performance_summary", {})
                return result.data

    async def test_monitor_failure_is_not_healthy(self, dirsrv_server):
        data = await self._run(dirsrv_server, monitor=_monitor_mock(fail=True))
        assert data["overall_health"] != "healthy"
        assert data["overall_health"] == "unknown"
        assert data["summary"].startswith("INCOMPLETE")
        assert data["evidence_status"] == "partial"
        assert any(p["probe"] == "ldap_monitor" for p in data["probe_failures"])

    async def test_monitor_failure_leaves_no_fabricated_zeros(self, dirsrv_server):
        """A failed monitor read must not report zeros as measurements."""
        data = await self._run(dirsrv_server, monitor=_monitor_mock(fail=True))
        for section in ("connections", "operations", "threads"):
            assert "error" in data["metrics"][section], section
            assert "current" not in data["metrics"][section], section
            assert "completed" not in data["metrics"][section], section

    async def test_ldbm_cache_failure_is_not_healthy(self, dirsrv_server):
        ldbm = MagicMock()
        ldbm.get_status.side_effect = RuntimeError("ldbm monitor denied")
        data = await self._run(dirsrv_server, ldbm=ldbm)
        assert data["overall_health"] == "unknown"
        assert any(p["probe"] == "ldbm_cache" for p in data["probe_failures"])

    async def test_local_resource_failure_is_not_healthy(self, local_server):
        monitor = _monitor_mock()
        monitor.get_resource_stats.side_effect = RuntimeError("psutil denied")
        data = await self._run(local_server, monitor=monitor)
        assert data["overall_health"] == "unknown"
        assert any(p["probe"] == "local_resources" for p in data["probe_failures"])
        # No fabricated zero readings: the section is explicitly marked failed
        resources = data["metrics"]["resources"]
        assert resources["available"] is False
        assert "error" in resources
        assert resources["memory_pct"] is None
        assert resources["cpu_pct"] is None

    async def test_remote_resources_are_not_applicable_not_missing(self, dirsrv_server):
        """Remote target: resources are explicitly N/A, never a failure."""
        data = await self._run(dirsrv_server)
        assert data["overall_health"] == "healthy"
        resources = data["metrics"]["resources"]
        assert resources["available"] is False
        assert "reason" in resources
        assert resources["memory_pct"] is None
        assert not any(p["probe"] == "local_resources" for p in data["probe_failures"])

    async def test_complete_evidence_still_reports_healthy(self, dirsrv_server):
        data = await self._run(dirsrv_server)
        assert data["overall_health"] == "healthy"
        assert data["summary"].startswith("HEALTHY")
        assert data["evidence_status"] == "complete"
        assert data["probe_failures"] == []

    async def test_local_complete_evidence_reports_healthy(self, local_server):
        monitor = _monitor_mock()
        monitor.get_resource_stats.return_value = {
            "mem_rss_percent": "10",
            "rss": "1048576",
            "cpu_usage": "5",
        }
        data = await self._run(local_server, monitor=monitor)
        assert data["overall_health"] == "healthy"
        assert data["metrics"]["resources"]["memory_pct"] == 10.0

    async def test_shape_compatibility(self, dirsrv_server):
        data = await self._run(dirsrv_server)
        for key in ("type", "server", "metrics", "overall_health", "summary",
                    "findings", "finding_count"):
            assert key in data, f"missing pre-existing key {key}"
        assert set(data["finding_count"]) == {"critical", "high", "medium", "low"}


# ---------------------------------------------------------------------------
# AC-03 — list_replication_conflicts
# ---------------------------------------------------------------------------


def _replica_mock(suffix="dc=example,dc=com", fail=False):
    replica = MagicMock()
    if fail:
        replica.get_suffix.side_effect = RuntimeError("insufficient access")
    else:
        replica.get_suffix.return_value = suffix
    return replica


class TestReplicationConflicts:
    async def _run(self, server, replicas_list, conflicts_cls=None, glue_cls=None, args=None):
        replicas = MagicMock()
        replicas.list.return_value = replicas_list
        conflicts_cls = conflicts_cls or MagicMock(return_value=_empty_collection_mock())
        glue_cls = glue_cls or MagicMock(return_value=_empty_collection_mock())
        with patch.object(replication, "Replicas", return_value=replicas), \
             patch.object(replication, "ConflictEntries", conflicts_cls), \
             patch.object(replication, "GlueEntries", glue_cls), \
             patch.object(server.connection_manager, "connect", return_value=MagicMock()):
            async with Client(server) as client:
                result = await client.call_tool("list_replication_conflicts", args or {})
                return result.data

    async def test_all_suffix_discovery_failures_not_all_clear(self, dirsrv_server):
        """suffix_discovery_all: must not claim 'No replicated suffixes'."""
        data = await self._run(dirsrv_server, [_replica_mock(fail=True)])
        assert "No replicated suffixes" not in data["summary"]
        assert data["summary"].startswith("INCOMPLETE")
        assert data["evidence_status"] == "partial"
        assert data["discovery_errors"]

    async def test_partial_suffix_discovery_failure_not_all_clear(self, dirsrv_server):
        data = await self._run(
            dirsrv_server, [_replica_mock(), _replica_mock(fail=True)]
        )
        assert not data["summary"].startswith("HEALTHY")
        assert data["summary"].startswith("INCOMPLETE")
        # The surviving suffix was still searched
        assert data["suffixes_checked"] == ["dc=example,dc=com"]

    async def test_conflict_search_failure_not_all_clear(self, dirsrv_server):
        conflicts_cls = MagicMock(side_effect=RuntimeError("conflict search denied"))
        data = await self._run(dirsrv_server, [_replica_mock()], conflicts_cls=conflicts_cls)
        assert not data["summary"].startswith("HEALTHY")
        assert data["summary"].startswith("INCOMPLETE")
        assert any(e["search"] == "conflicts" for e in data["search_errors"])
        # The affected suffix stays visible
        assert data["search_errors"][0]["suffix"] == "dc=example,dc=com"

    async def test_glue_search_failure_not_all_clear(self, dirsrv_server):
        glue_cls = MagicMock(side_effect=RuntimeError("glue search denied"))
        data = await self._run(dirsrv_server, [_replica_mock()], glue_cls=glue_cls)
        assert data["summary"].startswith("INCOMPLETE")
        assert any(e["search"] == "glue" for e in data["search_errors"])

    async def test_both_searches_failing_not_all_clear(self, dirsrv_server):
        conflicts_cls = MagicMock(side_effect=RuntimeError("conflict search denied"))
        glue_cls = MagicMock(side_effect=RuntimeError("glue search denied"))
        data = await self._run(
            dirsrv_server, [_replica_mock()], conflicts_cls=conflicts_cls, glue_cls=glue_cls
        )
        assert data["summary"].startswith("INCOMPLETE")
        searches = {e["search"] for e in data["search_errors"]}
        assert searches == {"conflicts", "glue"}

    async def test_no_conflicts_with_complete_searches_is_healthy(self, dirsrv_server):
        """Positive control: both searches succeeded and found nothing."""
        data = await self._run(dirsrv_server, [_replica_mock()])
        assert data["summary"].startswith("HEALTHY: No conflicts found")
        assert data["evidence_status"] == "complete"
        assert data["search_errors"] == []
        assert data["conflict_count"] == 0

    async def test_genuinely_no_replicated_suffixes_still_reported(self, dirsrv_server):
        data = await self._run(dirsrv_server, [])
        assert data["summary"] == "No replicated suffixes found"
        assert data["evidence_status"] == "complete"

    async def test_shape_compatibility(self, dirsrv_server):
        data = await self._run(dirsrv_server, [_replica_mock()])
        for key in ("type", "server", "summary", "suffixes_checked",
                    "conflict_count", "glue_count", "conflicts", "glue_entries",
                    "findings"):
            assert key in data, f"missing pre-existing key {key}"


# ---------------------------------------------------------------------------
# AC-04 — analyze_index_configuration
# ---------------------------------------------------------------------------


def _index_mock(attr, types):
    idx = MagicMock()
    idx.get_attr_val_utf8.side_effect = lambda name: {
        "cn": attr,
        "nsSystemIndex": "false",
    }.get(name)
    idx.get_attr_vals_utf8.side_effect = lambda name: {
        "nsIndexType": list(types),
    }.get(name, [])
    return idx


def _backend_mock(name="userroot", suffix="dc=example,dc=com", indexes_list=None, scan_fail=False):
    be = MagicMock()
    be.get_attr_val_utf8.side_effect = lambda attr: {
        "cn": name,
        "nsslapd-suffix": suffix,
    }.get(attr)
    if scan_fail:
        be.get_indexes.side_effect = RuntimeError("index read denied")
    else:
        idx_coll = MagicMock()
        idx_coll.list.return_value = indexes_list or []
        be.get_indexes.return_value = idx_coll
    return be


class TestIndexAnalysis:
    async def _run(self, server, backend_list, args=None):
        backends = MagicMock()
        backends.list.return_value = backend_list
        with patch.object(indexes, "Backends", return_value=backends), \
             patch.object(server.connection_manager, "connect", return_value=MagicMock()):
            async with Client(server) as client:
                result = await client.call_tool("analyze_index_configuration", args or {})
                return result.data

    async def test_empty_discovery_is_unknown_not_healthy(self, dirsrv_server):
        data = await self._run(dirsrv_server, [])
        assert data["status"] != "healthy"
        assert data["status"] == "unknown"
        assert data["summary"].startswith("UNKNOWN")
        assert data["evidence_status"] == "partial"

    async def test_requested_backend_absent_is_unknown(self, dirsrv_server):
        data = await self._run(
            dirsrv_server, [_backend_mock("userroot")], args={"backend": "missingbackend"}
        )
        assert data["status"] == "unknown"
        assert "not found" in data["summary"]
        assert data["requested_backend"] == "missingbackend"

    async def test_backend_scan_failure_is_not_healthy(self, dirsrv_server):
        data = await self._run(dirsrv_server, [_backend_mock(scan_fail=True)])
        assert data["status"] == "unknown"
        assert data["summary"].startswith("INCOMPLETE")
        assert data["backends_failed"]
        assert data["backends_failed"][0]["backend"] == "userroot"
        assert data["backends_scanned"] == []

    async def test_discovery_exception_remains_explicit_error(self, dirsrv_server):
        """Control: a discovery-level exception is an explicit error result."""
        backends = MagicMock()
        backends.list.side_effect = RuntimeError("cannot enumerate backends")
        with patch.object(indexes, "Backends", return_value=backends), \
             patch.object(dirsrv_server.connection_manager, "connect", return_value=MagicMock()):
            async with Client(dirsrv_server) as client:
                result = await client.call_tool("analyze_index_configuration", {})
                data = result.data
        assert "error" in data
        assert data.get("status") != "healthy"

    async def test_complete_scan_still_reports_healthy(self, dirsrv_server):
        """Positive control: full recommended coverage scans healthy."""
        idx_list = [
            _index_mock(attr, types) for attr, types in indexes.RECOMMENDED_INDEXES.items()
        ]
        data = await self._run(dirsrv_server, [_backend_mock(indexes_list=idx_list)])
        assert data["status"] == "healthy"
        assert data["summary"].startswith("HEALTHY")
        assert data["evidence_status"] == "complete"
        assert data["backends_scanned"] == ["userroot"]
        assert data["backends_failed"] == []

    async def test_partial_scan_with_missing_indexes_stays_visible(self, dirsrv_server):
        """Issues found in scanned backends do not hide the failed backend."""
        idx_list = [
            _index_mock(attr, types) for attr, types in indexes.RECOMMENDED_INDEXES.items()
        ]
        data = await self._run(
            dirsrv_server,
            [_backend_mock("userroot", indexes_list=[]),  # all recommended missing
             _backend_mock("example", suffix="dc=e,dc=com", scan_fail=True)],
        )
        assert data["status"] == "warning"  # issues found take precedence
        assert data["evidence_status"] == "partial"  # but coverage gap stays visible
        assert data["backends_failed"][0]["backend"] == "example"
        del idx_list  # only needed to document intent

    async def test_shape_compatibility(self, dirsrv_server):
        data = await self._run(dirsrv_server, [_backend_mock()])
        for key in ("type", "server", "backends", "findings", "summary",
                    "status", "recommendations"):
            assert key in data, f"missing pre-existing key {key}"


# ---------------------------------------------------------------------------
# AC-08 — validate_configuration (offline/archive)
# ---------------------------------------------------------------------------


_CLEAN_DSE_VALUES = {
    "nsslapd-rootpwstoragescheme": "PBKDF2_SHA256",
    "sslVersionMin": "TLS1.2",
    "nsslapd-accesslog-logbuffering": "on",
    "nsslapd-auditlog-logging-enabled": "on",
    "nsslapd-security": "on",
    "nsslapd-allow-anonymous-access": "rootdse",
}


def _dse_mock(nsstate_fail=False):
    dse = MagicMock()
    dse.get.side_effect = lambda dn, attr, single=False: _CLEAN_DSE_VALUES.get(attr)
    if nsstate_fail:
        dse._lint_nsstate.side_effect = RuntimeError("nsState parse failed")
    else:
        dse._lint_nsstate.return_value = []
    return dse


class TestValidateConfiguration:
    async def _run(self, server, dse):
        with patch.object(archive, "get_dse_ldif_path", return_value="/tmp/dse.ldif"), \
             patch.object(archive, "DSEldif", return_value=dse), \
             patch.object(server.connection_manager, "connect", return_value=MagicMock()):
            async with Client(server) as client:
                result = await client.call_tool("validate_configuration", {})
                return result.data

    async def test_nsstate_lint_failure_is_not_all_clear(self, offline_server):
        data = await self._run(offline_server, _dse_mock(nsstate_fail=True))
        assert not data["summary"].startswith("HEALTHY")
        assert not data["summary"].startswith("OK")
        assert data["summary"].startswith("INCOMPLETE")
        assert data["evidence_status"] == "partial"
        # Failed check is distinct from checks successfully run
        assert "dseldif:nsstate" not in data["checks_run"]
        failed = {c["check"] for c in data["checks_failed"]}
        assert "dseldif:nsstate" in failed

    async def test_complete_validation_still_reports_healthy(self, offline_server):
        data = await self._run(offline_server, _dse_mock())
        assert data["summary"].startswith("HEALTHY")
        assert data["evidence_status"] == "complete"
        assert "dseldif:nsstate" in data["checks_run"]
        assert data["checks_failed"] == []

    async def test_shape_compatibility(self, offline_server):
        data = await self._run(offline_server, _dse_mock())
        for key in ("type", "server", "summary", "critical_count", "high_count",
                    "medium_count", "low_count", "info_count", "total_issues",
                    "findings", "checks_run"):
            assert key in data, f"missing pre-existing key {key}"


# ---------------------------------------------------------------------------
# Privacy: new evidence keys must be sanitized
# ---------------------------------------------------------------------------


class TestEvidenceSanitization:
    def _make_mcp(self):
        mcp = MagicMock()
        mcp.privacy_enabled = True
        mcp.sanitizer = PrivacySanitizer()
        return mcp

    def test_health_evidence_gaps_are_sanitized(self):
        result = {
            "type": "first_look",
            "evidence_gaps": [
                {"server": "srv1", "probe": "connections",
                 "error": "cannot reach ldap://secret-host.example.com:389"},
            ],
        }
        sanitized = health._sanitize_health_result(self._make_mcp(), result)
        assert "secret-host.example.com" not in sanitized["evidence_gaps"][0]["error"]

    def test_failure_summary_is_sanitized(self):
        """run_healthcheck's FAILED summary embeds raw exception text."""
        result = {
            "type": "healthcheck",
            "summary": (
                "FAILED: Health check could not complete - RuntimeError: "
                "SERVER_DOWN: ldap://secret-host.example.com:389 - search on "
                "cn=monitor,dc=corp,dc=example,dc=com failed"
            ),
        }
        sanitized = health._sanitize_health_result(self._make_mcp(), result)
        assert "secret-host.example.com" not in sanitized["summary"]
        assert "dc=corp" not in sanitized["summary"]
        assert sanitized["summary"].startswith("FAILED:")

    def test_healthcheck_failures_are_sanitized(self):
        result = {
            "type": "healthcheck",
            "checks_failed": [
                {"check": "config:x", "error": "failed on secret-host.example.com"},
            ],
            "discovery_errors": [
                {"category": "Config", "error": "denied at secret-host.example.com"},
            ],
        }
        sanitized = health._sanitize_health_result(self._make_mcp(), result)
        assert "secret-host.example.com" not in sanitized["checks_failed"][0]["error"]
        assert "secret-host.example.com" not in sanitized["discovery_errors"][0]["error"]

    def test_replication_search_errors_are_sanitized(self):
        result = {
            "type": "replication_conflicts",
            "search_errors": [
                {"suffix": "dc=corp,dc=example,dc=com", "search": "conflicts",
                 "error": "denied for dc=corp,dc=example,dc=com"},
            ],
        }
        sanitized = replication._sanitize_replication_result(self._make_mcp(), result)
        entry = sanitized["search_errors"][0]
        assert "dc=corp" not in entry["suffix"]
        assert "dc=corp" not in entry["error"]

    def test_index_backend_failures_are_sanitized(self):
        result = {
            "type": "index_analysis",
            "backends_scanned": ["corpRoot"],
            "backends_failed": [
                {"backend": "corpRoot", "error": "failed on secret-host.example.com"},
            ],
            "requested_backend": "corpRoot",
        }
        sanitized = indexes._sanitize_index_result(self._make_mcp(), result)
        assert sanitized["backends_scanned"] == ["[backend]"]
        assert sanitized["backends_failed"][0]["backend"] == "[backend]"
        assert "secret-host.example.com" not in sanitized["backends_failed"][0]["error"]
        assert sanitized["requested_backend"] == "[backend]"

    def test_performance_probe_failures_are_sanitized(self):
        result = {
            "type": "performance_summary",
            "probe_failures": [
                {"probe": "ldap_monitor", "error": "denied at secret-host.example.com"},
            ],
            "metrics": {"cache": {"error": "cn=config on secret-host.example.com"}},
        }
        sanitized = performance._sanitize_performance_result(self._make_mcp(), result)
        assert "secret-host.example.com" not in sanitized["probe_failures"][0]["error"]
        assert "secret-host.example.com" not in sanitized["metrics"]["cache"]["error"]

    def test_archive_checks_failed_are_sanitized(self):
        result = {
            "type": "configuration_validation",
            "checks_failed": [
                {"check": "dseldif:nsstate", "error": "failed on secret-host.example.com"},
            ],
        }
        sanitized = archive._sanitize_archive_result(self._make_mcp(), result)
        assert "secret-host.example.com" not in sanitized["checks_failed"][0]["error"]
