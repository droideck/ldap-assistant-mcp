"""Phase 0 regression tests for silently-wrong health diagnostics.

Covers:

1. dsDisk parsing must read the real lib389 attribute keys (``use%`` and
   ``available``) instead of the nonexistent ``percent``/``avail`` keys that
   made a full disk report ``usage_percent=0`` and stay healthy.
2. The certificate expiry check must enumerate certificates via
   ``NssSsl.list_certs()`` (the old code called the nonexistent
   ``NssSsl.get_server_cert()`` and swallowed the AttributeError, reporting
   "no certificates found" forever).
3. ``run_healthcheck``/``list_healthchecks`` must discover lint checks via
   the lib389 DSLint API (``lint_list()`` recursion) so that child checks of
   collections (e.g. Backend checks under Backends) are included, and an
   unknown check spec must raise ToolError instead of reporting HEALTHY.

These tests follow the FastMCP in-memory testing pattern and never require a
live LDAP server: lib389 objects are mocked at the module boundary.
"""

from __future__ import annotations

from datetime import datetime, timedelta, timezone
from unittest.mock import MagicMock, patch

import pytest
from fastmcp import Client
from fastmcp.exceptions import ToolError
from lib389._mapped_object_lint import DSLint, DSLints

import ldap_assistant_mcp.dirsrv_mcp.tools.health as health
from ldap_assistant_mcp.lib.disk_utils import parse_dsdisk_entry


# Real dsDisk value format, as emitted by 389 DS in cn=disk space,cn=monitor
# and returned by lib389's MonitorDiskSpace.get_disks()
REAL_DSDISK_SAMPLE = (
    'partition="/" size="52521566208" used="9837719552" '
    'available="42683846656" use%="18"'
)


def _make_mcp() -> MagicMock:
    """Create a minimal mcp stand-in with a logger."""
    mcp = MagicMock()
    mcp.logger = MagicMock()
    return mcp


# dsDisk parser unit tests (Bug 1)


class TestParseDsdiskEntry:
    """Unit tests for the shared dsDisk parser in lib/disk_utils.py."""

    def test_parses_real_sample(self):
        """A real dsDisk string parses into the expected dict."""
        entry = parse_dsdisk_entry(REAL_DSDISK_SAMPLE)
        assert entry["partition"] == "/"
        assert entry["size"] == "52521566208"
        assert entry["used"] == "9837719552"
        assert entry["available"] == "42683846656"
        assert entry["use_percent"] == 18

    def test_use_percent_read_from_use_pct_key(self):
        """The percentage must come from the real 'use%' key (the old code
        read 'percent', so a full disk reported 0)."""
        entry = parse_dsdisk_entry('partition="/var" size="100" used="96" available="4" use%="96"')
        assert entry["use_percent"] == 96

    def test_available_read_from_available_key(self):
        """Free space must come from 'available' (old code read 'avail')."""
        entry = parse_dsdisk_entry(REAL_DSDISK_SAMPLE)
        assert entry["available"] == "42683846656"

    def test_quoted_value_with_spaces(self):
        """Quoted values containing spaces are preserved."""
        entry = parse_dsdisk_entry('partition="/mnt/my disk" size="10" used="1" available="9" use%="10"')
        assert entry["partition"] == "/mnt/my disk"
        assert entry["use_percent"] == 10

    def test_missing_keys_use_defaults(self):
        """Missing keys fall back to safe defaults."""
        entry = parse_dsdisk_entry('partition="/"')
        assert entry["partition"] == "/"
        assert entry["size"] == "unknown"
        assert entry["available"] == "unknown"
        assert entry["use_percent"] == 0

    def test_empty_and_none_input(self):
        """Empty input yields all defaults instead of raising."""
        for value in ("", None):
            entry = parse_dsdisk_entry(value)
            assert entry["partition"] == "unknown"
            assert entry["use_percent"] == 0


class TestDiskHealthCheck:
    """_check_disk_health must fire findings based on the real use% key."""

    def _run(self, disk_strings):
        findings = []
        metrics = {}
        disk_monitor = MagicMock()
        disk_monitor.get_disks.return_value = disk_strings
        with patch.object(health, "MonitorDiskSpace", return_value=disk_monitor):
            health._check_disk_health(_make_mcp(), MagicMock(), "srv1", findings, metrics, is_local=True)
        return findings, metrics

    def test_full_disk_produces_critical_finding(self):
        """A 96% full disk must produce a CRITICAL finding (previously the
        wrong 'percent' key parsed to 0 and the server stayed healthy)."""
        findings, metrics = self._run(
            ['partition="/" size="100" used="96" available="4" use%="96"']
        )
        assert metrics["disk"]["partitions"][0]["usage_percent"] == 96
        assert metrics["disk"]["partitions"][0]["available"] == "4"
        critical = [f for f in findings if f["severity"] == "critical"]
        assert len(critical) == 1
        assert "Critical Disk Space" in critical[0]["title"]

    def test_high_usage_produces_high_finding(self):
        """An 87% full disk must produce a HIGH finding."""
        findings, _ = self._run(
            ['partition="/" size="100" used="87" available="13" use%="87"']
        )
        high = [f for f in findings if f["severity"] == "high"]
        assert len(high) == 1
        assert "High Disk Usage" in high[0]["title"]

    def test_healthy_disk_reports_real_usage_and_no_findings(self):
        """A healthy disk yields no findings but real (non-zero) usage."""
        findings, metrics = self._run([REAL_DSDISK_SAMPLE])
        assert findings == []
        assert metrics["disk"]["available"] is True
        assert metrics["disk"]["partitions"][0]["usage_percent"] == 18


# Certificate expiry check tests (Bug 2)


def _cert_detail(nickname, days_from_now, trust="u,u,u"):
    """Build a cert detail list as NssSsl.list_certs()/get_cert_details() do:
    [nickname, subject, issuer, expire_date, trust_flags] where the expiry is
    str(datetime), e.g. '2026-07-10 12:34:56'."""
    expires = (datetime.now(timezone.utc) + timedelta(days=days_from_now)).strftime(
        "%Y-%m-%d %H:%M:%S"
    )
    return [nickname, f"CN={nickname}", "CN=Test CA", expires, trust]


class TestCertificateHealthCheck:
    """_check_certificate_health must enumerate certs via list_certs()."""

    def _run(self, server_certs, ca_certs=None, mcp=None):
        nss = MagicMock()
        nss.list_certs.side_effect = lambda ca=False: (ca_certs or []) if ca else server_certs
        findings = []
        metrics = {}
        with patch.object(health, "NssSsl", return_value=nss):
            health._check_certificate_health(
                mcp or _make_mcp(), MagicMock(), "srv1", findings, metrics, is_local=True
            )
        return findings, metrics

    def test_cert_expiring_in_10_days_produces_medium_finding(self):
        findings, metrics = self._run([_cert_detail("Server-Cert", 10)])
        expiring = [f for f in findings if "Expiring Soon" in f["title"]]
        assert len(expiring) == 1
        assert expiring[0]["severity"] == "medium"
        certs = metrics["certificates"]["certs"]
        assert len(certs) == 1
        assert certs[0]["nickname"] == "Server-Cert"
        # 10 days minus a few microseconds of test runtime
        assert certs[0]["days_until_expiry"] in (9, 10)

    def test_cert_expiring_within_week_is_high(self):
        findings, _ = self._run([_cert_detail("Server-Cert", 5)])
        expiring = [f for f in findings if "Expiring Soon" in f["title"]]
        assert len(expiring) == 1
        assert expiring[0]["severity"] == "high"

    def test_expired_cert_produces_critical_finding(self):
        findings, metrics = self._run([_cert_detail("Server-Cert", -10)])
        expired = [f for f in findings if "Expired" in f["title"]]
        assert len(expired) == 1
        assert expired[0]["severity"] == "critical"
        assert metrics["certificates"]["certs"][0]["days_until_expiry"] < 0

    def test_healthy_cert_produces_no_findings(self):
        findings, metrics = self._run([_cert_detail("Server-Cert", 300)])
        assert findings == []
        certs = metrics["certificates"]["certs"]
        assert certs[0]["days_until_expiry"] > 200

    def test_ca_certs_included_with_type(self):
        _, metrics = self._run(
            [_cert_detail("Server-Cert", 300)],
            ca_certs=[_cert_detail("Self-Signed-CA", 300, trust="CTu,u,u")],
        )
        certs = metrics["certificates"]["certs"]
        types = {c["nickname"]: c["type"] for c in certs}
        assert types == {"Server-Cert": "server", "Self-Signed-CA": "ca"}

    def test_no_certs_reports_status(self):
        _, metrics = self._run([])
        assert metrics["certificates"] == {
            "available": True,
            "status": "no certificates found",
        }

    def test_attribute_error_not_swallowed(self):
        """An AttributeError (e.g. the old nonexistent get_server_cert API)
        must surface as an error, not as 'no certificates found'."""
        mcp = _make_mcp()
        nss = MagicMock()
        nss.list_certs.side_effect = AttributeError(
            "'NssSsl' object has no attribute 'get_server_cert'"
        )
        findings = []
        metrics = {}
        with patch.object(health, "NssSsl", return_value=nss):
            health._check_certificate_health(mcp, MagicMock(), "srv1", findings, metrics, is_local=True)
        assert metrics["certificates"]["available"] is False
        assert "error" in metrics["certificates"]
        assert metrics["certificates"].get("status") != "no certificates found"
        assert mcp.logger.warning.called

    def test_remote_server_skips_check(self):
        findings = []
        metrics = {}
        health._check_certificate_health(_make_mcp(), MagicMock(), "srv1", findings, metrics, is_local=False)
        assert metrics["certificates"]["available"] is False
        assert "reason" in metrics["certificates"]


class TestParseCertExpiry:
    """Unit tests for the cert expiry date parser."""

    def test_lib389_str_datetime_format(self):
        result = health._parse_cert_expiry("2030-06-20 12:34:56")
        assert result == datetime(2030, 6, 20, 12, 34, 56, tzinfo=timezone.utc)

    def test_certutil_raw_format(self):
        result = health._parse_cert_expiry("Mon Jun 20 12:34:56 2030")
        assert result is not None
        assert (result.year, result.month, result.day) == (2030, 6, 20)

    def test_date_only_fallback(self):
        result = health._parse_cert_expiry("2030-06-20")
        assert result == datetime(2030, 6, 20, tzinfo=timezone.utc)

    def test_datetime_passthrough_gets_utc(self):
        naive = datetime(2030, 6, 20, 1, 2, 3)
        result = health._parse_cert_expiry(naive)
        assert result.tzinfo is timezone.utc

    def test_garbage_returns_none(self):
        assert health._parse_cert_expiry("not a date") is None
        assert health._parse_cert_expiry("") is None
        assert health._parse_cert_expiry(None) is None


# Lint discovery tests (Bug 3)


class FakeBackend(DSLint):
    """Child object exposing _lint_* methods, like lib389's Backend."""

    def __init__(self, name):
        self._name = name

    def lint_uid(self):
        return self._name

    def _lint_mappingtree(self):
        yield {
            "dsle": "DSBLE0001",
            "severity": "MEDIUM",
            "description": "Possibly broken mapping tree",
            "items": [self._name],
            "detail": f"Backend {self._name} mapping tree issue",
            "fix": "Fix the mapping tree",
        }

    def _lint_search(self):
        return iter(())


class FakeBackends(DSLints):
    """Collection object with NO _lint_* methods of its own — checks only
    reachable through DSLints.lint_list() recursion, like lib389's Backends."""

    def __init__(self, ds=None):
        pass

    @classmethod
    def lint_uid(cls):
        return "backends"

    def list(self):
        return [FakeBackend("userroot"), FakeBackend("example")]


class FakeConfig(DSLint):
    """Singleton check object, like lib389's Config."""

    def __init__(self, ds=None):
        pass

    @classmethod
    def lint_uid(cls):
        return "config"

    def _lint_passwordscheme(self):
        return iter(())


class FakeBrokenTarget:
    """A check class that cannot be instantiated (must be skipped)."""

    def __init__(self, ds=None):
        raise RuntimeError("cannot instantiate without config")


class TestLintDiscovery:
    """_list_check_targets must use the DSLint lint_list() API."""

    def test_backend_child_checks_are_discovered(self):
        """Backends has no _lint_* itself; its child checks must appear."""
        with patch.object(health, "CHECK_OBJECTS", [FakeConfig, FakeBackends]):
            targets = health._list_check_targets(MagicMock())
        assert "backends" in targets
        names = set(targets["backends"]["checks"])
        assert names == {
            "userroot:mappingtree",
            "userroot:search",
            "example:mappingtree",
            "example:search",
        }
        assert set(targets["config"]["checks"]) == {"passwordscheme"}

    def test_broken_target_is_skipped(self):
        with patch.object(health, "CHECK_OBJECTS", [FakeBrokenTarget, FakeConfig]):
            targets = health._list_check_targets(MagicMock())
        assert list(targets) == ["config"]

    def test_expand_spec_exact_child_check(self):
        with patch.object(health, "CHECK_OBJECTS", [FakeConfig, FakeBackends]):
            targets = health._list_check_targets(MagicMock())
        matched = health._expand_check_spec(targets, "backends:userroot:mappingtree")
        assert [(uid, name) for uid, name, _ in matched] == [("backends", "userroot:mappingtree")]

    def test_expand_spec_short_form_matches_all_backends(self):
        """Legacy 'backends:mappingtree' runs the check on every backend."""
        with patch.object(health, "CHECK_OBJECTS", [FakeConfig, FakeBackends]):
            targets = health._list_check_targets(MagicMock())
        matched = health._expand_check_spec(targets, "backends:mappingtree")
        names = sorted(name for _, name, _ in matched)
        assert names == ["example:mappingtree", "userroot:mappingtree"]

    def test_expand_spec_wildcards(self):
        with patch.object(health, "CHECK_OBJECTS", [FakeConfig, FakeBackends]):
            targets = health._list_check_targets(MagicMock())
        assert len(health._expand_check_spec(targets, "backends:*")) == 4
        assert len(health._expand_check_spec(targets, "*")) == 5
        assert len(health._expand_check_spec(targets, "backends:userroot:*")) == 2

    def test_expand_spec_no_match_returns_empty(self):
        with patch.object(health, "CHECK_OBJECTS", [FakeConfig, FakeBackends]):
            targets = health._list_check_targets(MagicMock())
        assert health._expand_check_spec(targets, "config:nonexistent") == []
        assert health._expand_check_spec(targets, "bogus:*") == []

    def test_offline_dseldif_checks_still_discovered(self, tmp_path):
        """The offline/archive discovery path must keep working."""
        dse = tmp_path / "dse.ldif"
        dse.write_text("dn: cn=config\ncn: config\n\n")
        with patch.object(health, "_get_dse_ldif_path", return_value=str(dse)):
            targets = health._list_check_targets_offline(MagicMock(), is_archive=True)
        assert set(targets) == {"dseldif"}
        assert "nsstate" in targets["dseldif"]["checks"]


# Tool-level tests via in-memory FastMCP client


async def test_run_healthcheck_executes_backend_checks(dirsrv_server):
    """run_healthcheck must execute child Backend checks and report findings."""
    with patch.object(health, "CHECK_OBJECTS", [FakeConfig, FakeBackends]), \
         patch.object(dirsrv_server.connection_manager, "connect", return_value=MagicMock()):
        async with Client(dirsrv_server) as client:
            result = await client.call_tool("run_healthcheck", {"checks": ["backends:*"]})
            data = result.data

    assert "backends:userroot:mappingtree" in data["checks_executed"]
    assert "backends:example:mappingtree" in data["checks_executed"]
    # Both backends yield a DSBLE0001 finding from _lint_mappingtree
    dsles = [f.get("metadata", {}).get("dsle") for f in data["findings"]]
    assert dsles.count("DSBLE0001") == 2
    assert data["medium_count"] == 2


async def test_run_healthcheck_all_checks_include_backends(dirsrv_server):
    """Default (no spec) run must include the recursed backend checks."""
    with patch.object(health, "CHECK_OBJECTS", [FakeConfig, FakeBackends]), \
         patch.object(dirsrv_server.connection_manager, "connect", return_value=MagicMock()):
        async with Client(dirsrv_server) as client:
            result = await client.call_tool("run_healthcheck", {})
            data = result.data

    assert "config:passwordscheme" in data["checks_executed"]
    assert "backends:userroot:mappingtree" in data["checks_executed"]


async def test_run_healthcheck_unknown_spec_raises_tool_error(dirsrv_server):
    """A check spec that matches nothing must raise ToolError, not report
    'HEALTHY, 0 checks passed'."""
    with patch.object(health, "CHECK_OBJECTS", [FakeConfig, FakeBackends]), \
         patch.object(dirsrv_server.connection_manager, "connect", return_value=MagicMock()):
        async with Client(dirsrv_server) as client:
            with pytest.raises(ToolError) as exc_info:
                await client.call_tool("run_healthcheck", {"checks": ["bogus:nope"]})

    assert "bogus:nope" in str(exc_info.value)


async def test_run_healthcheck_exclude_child_check(dirsrv_server):
    """Excluding a child check must skip it while running the rest."""
    with patch.object(health, "CHECK_OBJECTS", [FakeConfig, FakeBackends]), \
         patch.object(dirsrv_server.connection_manager, "connect", return_value=MagicMock()):
        async with Client(dirsrv_server) as client:
            result = await client.call_tool(
                "run_healthcheck",
                {
                    "checks": ["backends:*"],
                    "exclude_checks": ["backends:userroot:mappingtree"],
                },
            )
            data = result.data

    assert "backends:userroot:mappingtree" in data["checks_skipped"]
    assert "backends:userroot:mappingtree" not in data["checks_executed"]
    assert "backends:example:mappingtree" in data["checks_executed"]


async def test_list_healthchecks_includes_backend_child_checks(dirsrv_server):
    """list_healthchecks must list the recursed backend checks."""
    with patch.object(health, "CHECK_OBJECTS", [FakeConfig, FakeBackends]), \
         patch.object(dirsrv_server.connection_manager, "connect", return_value=MagicMock()):
        async with Client(dirsrv_server) as client:
            result = await client.call_tool("list_healthchecks", {})
            data = result.data

    names = [c["name"] for c in data["checks"]]
    assert "backends:userroot:mappingtree" in names
    assert "config:passwordscheme" in names
    assert "backends" in data["categories"]
