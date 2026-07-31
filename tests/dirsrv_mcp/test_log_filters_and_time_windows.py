"""Regression tests: truthful filtered log counts and archive time windows.

Covers:

- Filtered severity / change-type statistics must contain only records that
  matched every active filter; all-source totals are separately named
  (``source_severity_counts`` / ``source_change_type_counts``).
- Relative time ranges ("last 24h") on ARCHIVE evidence anchor to the newest
  timestamp in the dataset instead of the current wall clock, and every
  time-filtered result reports its ``effective_window``.
- Records with missing/unparseable timestamps are kept (fail open) but are
  counted in ``unknown_timestamp_count`` instead of silently blending in.
"""

from __future__ import annotations

import os
from datetime import datetime
from unittest.mock import patch

import pytest
from fastmcp import Client

from ldap_assistant_mcp.core import LDAPServerConfig
from ldap_assistant_mcp.dirsrv_mcp.server import DirSrvMCP
from ldap_assistant_mcp.dirsrv_mcp.tools.logs import (
    _parse_time_range,
    _resolve_time_window,
)

DSE_LDIF = """\
dn: cn=config
cn: config
nsslapd-port: 389
nsslapd-versionstring: 389-Directory/2.4.6

dn: cn=ldbm database,cn=plugins,cn=config
cn: ldbm database

"""

# All sample data is dated 2024-01-01 — far in the past, so a wall-clock
# "last 24h" filter matches nothing while a dataset-end anchor matches all.
SAMPLE_ACCESS_LOG = """\
389-Directory/2.4.6 B2024.123.456
[01/Jan/2024:10:00:02.000000000 +0000] conn=1 op=1 SRCH base="dc=example,dc=com" scope=2 filter="(uid=admin)" attrs=ALL
[01/Jan/2024:10:00:02.100000000 +0000] conn=1 op=1 RESULT err=0 tag=101 nentries=1 wtime=0.000001 optime=0.000200 etime=0.000201
[01/Jan/2024:10:00:03.000000000 +0000] conn=1 op=2 SRCH base="dc=example,dc=com" scope=2 filter="(uid=testuser)" attrs=ALL
[01/Jan/2024:10:00:03.100000000 +0000] conn=1 op=2 RESULT err=32 tag=101 nentries=0 wtime=0.000001 optime=0.000300 etime=0.000301
"""

SAMPLE_ERROR_LOG = """\
[01/Jan/2024:10:00:01.000000000 +0000] - INFO - main - 389-Directory/2.4.6 starting up
[01/Jan/2024:10:00:02.000000000 +0000] - INFO - main - Listening on all interfaces port 389 for LDAP requests
[01/Jan/2024:10:00:03.000000000 +0000] - WARNING - replication - Replication agreement to host1.example.com:636 not responding
[01/Jan/2024:10:00:04.000000000 +0000] - ERR - backend - ldbm_back_ldbm2index: Backend userRoot error reading entry
[01/Jan/2024:10:00:05.000000000 +0000] - INFO - plugins - MemberOf Plugin started
"""

# One record (the WARN line) has an unparseable timestamp
SAMPLE_ERROR_LOG_WITH_UNDATED = """\
[01/Jan/2024:10:00:01.000000000 +0000] - INFO - main - starting up
[not-a-real-timestamp] - WARN - main - clock skew message with broken date
[01/Jan/2024:10:00:03.000000000 +0000] - ERR - backend - something failed
"""

SAMPLE_AUDIT_LOG = """\
time: 20240101100001
dn: cn=config
result: 0
changetype: modify
replace: nsslapd-loglevel
nsslapd-loglevel: 16384
-
modifiersname: cn=Directory Manager
modifytimestamp: 20240101100001Z

time: 20240101100010
dn: uid=testuser,ou=People,dc=example,dc=com
result: 0
changetype: add
objectClass: top
uid: testuser
creatorsname: cn=Directory Manager
createtimestamp: 20240101100010Z

time: 20240101100020
dn: uid=olduser,ou=People,dc=example,dc=com
result: 0
changetype: delete
modifiersname: cn=Directory Manager
modifytimestamp: 20240101100020Z
"""


@pytest.fixture
def archive_env():
    env = {
        "LDAP_MCP_EXPOSE_SENSITIVE_DATA": "true",
        "LDAP_SERVERS_CONFIG": "",
    }
    with patch.dict(os.environ, env):
        yield


def _build_archive(tmp_path, error_log=SAMPLE_ERROR_LOG):
    inst = "slapd-t002inst"
    config_dir = tmp_path / "etc" / "dirsrv" / inst
    config_dir.mkdir(parents=True)
    (config_dir / "dse.ldif").write_text(DSE_LDIF)
    logs_dir = tmp_path / "var" / "log" / "dirsrv" / inst
    logs_dir.mkdir(parents=True)
    (logs_dir / "access").write_text(SAMPLE_ACCESS_LOG)
    (logs_dir / "errors").write_text(error_log)
    (logs_dir / "audit").write_text(SAMPLE_AUDIT_LOG)
    return tmp_path


@pytest.fixture
def archive_mcp(archive_env, tmp_path):
    _build_archive(tmp_path)
    config = LDAPServerConfig(
        name="t002-archive",
        hostname="archive",
        port=0,
        is_archive=True,
        archive_path=str(tmp_path),
    )
    return DirSrvMCP(servers=[config], include_env_fallback=False)


@pytest.fixture
def archive_mcp_undated(archive_env, tmp_path):
    _build_archive(tmp_path, error_log=SAMPLE_ERROR_LOG_WITH_UNDATED)
    config = LDAPServerConfig(
        name="t002-archive",
        hostname="archive",
        port=0,
        is_archive=True,
        archive_path=str(tmp_path),
    )
    return DirSrvMCP(servers=[config], include_env_fallback=False)


async def _call(server, tool, args):
    async with Client(server) as client:
        result = await client.call_tool(tool, args)
        return result.data


# ---------------------------------------------------------------------------
# Archive relative ranges anchor to dataset end
# ---------------------------------------------------------------------------


class TestArchiveTimeAnchoring:
    async def test_last_24h_matches_old_archive_evidence(self, archive_mcp):
        """The core defect: 'last 24h' on a 2024 SOS archive returned
        zero entries because it anchored to the current wall clock."""
        data = await _call(archive_mcp, "parse_access_log", {"time_range": "last 24h"})
        assert data["matched_count"] > 0
        assert data["effective_window"]["anchor"] == "dataset_end"
        # The effective window must be reported and anchored in 2024
        assert data["effective_window"]["start"].startswith("2023-12-31")

    async def test_analyze_access_log_reports_effective_window(self, archive_mcp):
        data = await _call(archive_mcp, "analyze_access_log", {"time_range": "last 24h"})
        assert data["matched_count"] > 0
        assert data["effective_window"]["anchor"] == "dataset_end"
        assert data["unknown_timestamp_count"] == 0

    async def test_absolute_range_is_labelled_absolute(self, archive_mcp):
        data = await _call(
            archive_mcp, "parse_access_log",
            {"time_range": "2024-01-01 to 2024-01-02"},
        )
        assert data["matched_count"] > 0
        assert data["effective_window"]["anchor"] == "absolute"

    async def test_audit_log_last_range_anchors_to_dataset(self, archive_mcp):
        data = await _call(archive_mcp, "analyze_audit_log", {"time_range": "last 1h"})
        # Only the record at 10:00:20 minus 1h window: all three are within
        # [09:00:20, None] so all match
        assert data["matched_count"] == 3
        assert data["effective_window"]["anchor"] == "dataset_end"

    async def test_no_time_range_has_no_window_keys(self, archive_mcp):
        data = await _call(archive_mcp, "parse_access_log", {})
        assert "effective_window" not in data
        assert "unknown_timestamp_count" not in data

    def test_parse_time_range_uses_anchor(self):
        anchor = datetime(2024, 1, 2, 10, 0, 0)
        start, end = _parse_time_range("last 24h", anchor=anchor)
        assert start == datetime(2024, 1, 1, 10, 0, 0)
        assert end is None

    def test_resolve_window_wall_clock_for_live(self, tmp_path):
        log = tmp_path / "access"
        log.write_text(SAMPLE_ACCESS_LOG)
        start, _end, window = _resolve_time_window(
            "last 24h", str(log), "access", anchor_to_dataset_end=False
        )
        assert window["anchor"] == "wall_clock"
        # Wall-clock anchored start is recent, not 2024
        assert start.year >= 2026

    def test_resolve_window_dataset_end_unavailable_falls_back(self, tmp_path):
        log = tmp_path / "access"
        log.write_text("no timestamps in this file at all\n")
        _start, _end, window = _resolve_time_window(
            "last 24h", str(log), "access", anchor_to_dataset_end=True
        )
        assert window["anchor"] == "dataset_end_unavailable"


# ---------------------------------------------------------------------------
# Filtered counts contain only matched records
# ---------------------------------------------------------------------------


class TestFilteredCounts:
    async def test_error_severity_counts_are_post_filter(self, archive_mcp):
        data = await _call(archive_mcp, "analyze_error_log", {"severity": "ERR"})
        assert data["matched_count"] == 1
        # Matched-only counts
        assert data["severity_counts"] == {"ERR": 1}
        # All-source totals separately named
        assert data["source_severity_counts"]["INFO"] == 3
        assert data["source_severity_counts"]["WARNING"] == 1
        assert data["source_severity_counts"]["ERR"] == 1

    async def test_error_counts_equal_when_unfiltered(self, archive_mcp):
        data = await _call(archive_mcp, "analyze_error_log", {})
        assert data["severity_counts"] == data["source_severity_counts"]
        assert data["matched_count"] == data["total_parsed"]

    async def test_audit_change_type_stats_are_post_filter(self, archive_mcp):
        data = await _call(archive_mcp, "analyze_audit_log", {"operation": "add"})
        assert data["matched_count"] == 1
        assert data["change_type_stats"] == {"add": 1}
        assert data["source_change_type_counts"] == {
            "modify": 1, "add": 1, "delete": 1,
        }

    async def test_audit_counts_equal_when_unfiltered(self, archive_mcp):
        data = await _call(archive_mcp, "analyze_audit_log", {})
        assert data["change_type_stats"] == data["source_change_type_counts"]

    async def test_parse_error_log_also_reports_source_counts(self, archive_mcp):
        data = await _call(archive_mcp, "parse_error_log", {"severity": "WARNING"})
        assert data["severity_counts"] == {"WARNING": 1}
        assert sum(data["source_severity_counts"].values()) == data["total_parsed"]


# ---------------------------------------------------------------------------
# Unknown timestamps are counted, not silently included
# ---------------------------------------------------------------------------


class TestUnknownTimestamps:
    async def test_undated_records_counted_in_time_filter(self, archive_mcp_undated):
        data = await _call(
            archive_mcp_undated, "analyze_error_log",
            {"time_range": "2024-01-01 to 2024-01-02"},
        )
        # The undated record is kept (fail open) and counted
        assert data["unknown_timestamp_count"] == 1
        assert data["matched_count"] == 3

    async def test_no_unknown_timestamps_reports_zero(self, archive_mcp):
        data = await _call(
            archive_mcp, "analyze_error_log",
            {"time_range": "2024-01-01 to 2024-01-02"},
        )
        assert data["unknown_timestamp_count"] == 0


# ---------------------------------------------------------------------------
# analyze_archive reports log time spans
# ---------------------------------------------------------------------------


class TestArchiveLogCoverage:
    async def test_analyze_archive_reports_log_coverage(self, archive_mcp):
        data = await _call(archive_mcp, "analyze_archive", {})
        cov = data["log_coverage"]
        assert cov["access"]["first_timestamp"].startswith("2024-01-01T10:00:02")
        assert cov["access"]["last_timestamp"].startswith("2024-01-01T10:00:03")
        assert cov["error"]["first_timestamp"].startswith("2024-01-01T10:00:01")
        assert cov["audit"]["last_timestamp"].startswith("2024-01-01T10:00:20")
        assert cov["access"]["includes_rotated"] is False
