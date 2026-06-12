"""Phase 0 regression tests for find_unindexed_searches (tools/indexes.py).

Covers two formerly silent bugs:

1. lib389's ``DirsrvAccessLog.match()`` anchors patterns at line start, so
   the old ``notes=(U|A)`` pattern never matched real access-log lines
   (they start with ``[timestamp]``) and the tool always reported HEALTHY.
   The tool now scans lines with ``re.search()`` and must find notes=U /
   notes=A RESULT lines.

2. The old time filter compared an epoch-seconds cutoff (~1.7e9) against
   lib389's ``get_time_in_secs()`` (seconds since midnight, 0-86399), so
   every line was discarded.  The tool now parses each line's real
   timestamp, and an invalid time_range raises ToolError instead of
   silently matching nothing.

Tests use a fake archive directory (tmp_path) with real-format access-log
lines — no live server or 389ds instance required.
"""

from __future__ import annotations

import asyncio
import os
from datetime import datetime, timedelta, timezone
from unittest.mock import patch

import pytest
from fastmcp import Client
from fastmcp.exceptions import ToolError

from ldap_assistant_mcp.core import LDAPServerConfig
from ldap_assistant_mcp.dirsrv_mcp.server import DirSrvMCP
from ldap_assistant_mcp.dirsrv_mcp.tools.indexes import (
    _parse_access_log_timestamp,
    _parse_time_range,
)


# Fixture data

DSE_LDIF = """\
dn: cn=config
objectClass: top
objectClass: extensibleObject
objectClass: nsslapdConfig
cn: config
nsslapd-port: 389
nsslapd-localhost: localhost.localdomain

dn: cn=plugins,cn=config
objectClass: top
objectClass: nsContainer
cn: plugins

dn: cn=ldbm database,cn=plugins,cn=config
objectClass: top
objectClass: nsSlapdPlugin
cn: ldbm database
nsslapd-pluginEnabled: on
nsslapd-pluginType: database

dn: cn=userRoot,cn=ldbm database,cn=plugins,cn=config
objectClass: top
objectClass: extensibleObject
objectClass: nsBackendInstance
cn: userRoot
nsslapd-suffix: dc=example,dc=com
"""

# A timestamp safely outside any short time_range window.
OLD_TIME = datetime(2020, 3, 15, 8, 30, 0, tzinfo=timezone.utc)


def _ts(dt: datetime) -> str:
    """Format a datetime as a traditional access-log timestamp."""
    return dt.strftime("[%d/%b/%Y:%H:%M:%S.392560011 %z]")


def _default_access_log() -> str:
    """Access log with real-format lines: recent notes=U and notes=A RESULT
    lines (filters on the correlated SRCH lines), a clean indexed search,
    and an old (2020) unindexed search for time-range testing.
    """
    recent = _ts(datetime.now(timezone.utc) - timedelta(minutes=5))
    old = _ts(OLD_TIME)
    return "\n".join(
        [
            "389-Directory/2.4.6 B2024.123.456",
            f"{recent} conn=1 fd=64 slot=64 connection from 127.0.0.1 to 127.0.0.1",
            f'{recent} conn=1 op=1 SRCH base="dc=example,dc=com" scope=2 filter="(cn=user1)" attrs=ALL',
            f"{recent} conn=1 op=1 RESULT err=0 tag=101 nentries=5000 wtime=0.000033222 optime=0.500000000 etime=0.500160000 notes=U",
            f'{recent} conn=2 op=3 SRCH base="ou=people,dc=example,dc=com" scope=2 filter="(telephoneNumber=555*)" attrs=ALL',
            f"{recent} conn=2 op=3 RESULT err=0 tag=101 nentries=20000 wtime=0.000100000 optime=1.500000000 etime=1.600000000 notes=A",
            f'{recent} conn=3 op=1 SRCH base="dc=example,dc=com" scope=2 filter="(uid=indexeduser)" attrs=ALL',
            f"{recent} conn=3 op=1 RESULT err=0 tag=101 nentries=1 wtime=0.000001000 optime=0.000100000 etime=0.000101000",
            f'{old} conn=9 op=1 SRCH base="dc=example,dc=com" scope=2 filter="(description=old box)" attrs=ALL',
            f"{old} conn=9 op=1 RESULT err=0 tag=101 nentries=100 wtime=0.000100000 optime=0.900000000 etime=0.900100000 notes=U",
            "",
        ]
    )


def _clean_access_log() -> str:
    """Access log with no notes=U/A lines at all."""
    recent = _ts(datetime.now(timezone.utc) - timedelta(minutes=2))
    return "\n".join(
        [
            "389-Directory/2.4.6 B2024.123.456",
            f'{recent} conn=1 op=1 SRCH base="dc=example,dc=com" scope=2 filter="(uid=admin)" attrs=ALL',
            f"{recent} conn=1 op=1 RESULT err=0 tag=101 nentries=1 wtime=0.000001000 optime=0.000100000 etime=0.000101000",
            f"{recent} conn=1 op=2 UNBIND",
            "",
        ]
    )


# Fixtures

@pytest.fixture(autouse=True)
def archive_env():
    """Ensure no external config leaks into tests and data is not sanitized."""
    env = {
        "LDAP_MCP_EXPOSE_SENSITIVE_DATA": "true",
        "LDAP_SERVERS_CONFIG": "",
    }
    with patch.dict(os.environ, env):
        yield


def _make_archive_mcp(tmp_path, access_log_content: str) -> DirSrvMCP:
    """Build a fake SOS-style archive directory and a DirSrvMCP over it."""
    inst = "slapd-testinst"

    config_dir = tmp_path / "etc" / "dirsrv" / inst
    config_dir.mkdir(parents=True)
    (config_dir / "dse.ldif").write_text(DSE_LDIF)

    logs_dir = tmp_path / "var" / "log" / "dirsrv" / inst
    logs_dir.mkdir(parents=True)
    (logs_dir / "access").write_text(access_log_content)

    config = LDAPServerConfig(
        name="test-archive",
        hostname="archive",
        port=0,
        is_archive=True,
        archive_path=str(tmp_path),
    )
    return DirSrvMCP(servers=[config], include_env_fallback=False)


def _call_find_unindexed(mcp: DirSrvMCP, args: dict) -> dict:
    """Call find_unindexed_searches via in-memory client and return data."""

    async def run():
        async with Client(mcp) as client:
            result = await client.call_tool("find_unindexed_searches", args)
            return result.data

    return asyncio.run(run())


# Bug 1: notes=U/A detection on real-format log lines


class TestUnindexedSearchDetection:

    def test_notes_u_and_a_lines_found(self, tmp_path):
        """Real-format notes=U and notes=A RESULT lines must be detected."""
        mcp = _make_archive_mcp(tmp_path, _default_access_log())
        data = _call_find_unindexed(
            mcp, {"server_name": "test-archive", "time_range": "1h"}
        )

        assert "error" not in data
        assert data["type"] == "unindexed_searches"
        # Two recent unindexed ops (notes=U + notes=A); the old one is
        # outside the 1h window.
        assert data["total_unindexed_count"] == 2
        assert data["unique_patterns"] == 2
        assert data["status"] != "healthy"

    def test_filters_correlated_from_srch_lines(self, tmp_path):
        """notes=U/A is on the RESULT line; base/filter must come from the
        matching SRCH line (same conn/op)."""
        mcp = _make_archive_mcp(tmp_path, _default_access_log())
        data = _call_find_unindexed(
            mcp, {"server_name": "test-archive", "time_range": "1h"}
        )

        examples = {p["example_filter"]: p for p in data["patterns"]}
        assert "(cn=user1)" in examples
        assert "(telephoneNumber=555*)" in examples
        assert examples["(cn=user1)"]["base_dn"] == "dc=example,dc=com"
        assert examples["(telephoneNumber=555*)"]["base_dn"] == "ou=people,dc=example,dc=com"

        # Index recommendations are derived from the correlated filter.
        rec_attrs = [
            r["attribute"]
            for r in examples["(cn=user1)"]["recommended_indexes"]
        ]
        assert "cn" in rec_attrs

    def test_clean_log_reports_healthy(self, tmp_path):
        """Lines without notes=U/A must not be counted."""
        mcp = _make_archive_mcp(tmp_path, _clean_access_log())
        data = _call_find_unindexed(
            mcp, {"server_name": "test-archive", "time_range": "1h"}
        )

        assert "error" not in data
        assert data["total_unindexed_count"] == 0
        assert data["status"] == "healthy"

    def test_combined_notes_flag_detected(self, tmp_path):
        """notes=P,U (paged + unindexed) must also be detected."""
        recent = _ts(datetime.now(timezone.utc) - timedelta(minutes=1))
        log = "\n".join(
            [
                f'{recent} conn=4 op=2 SRCH base="dc=example,dc=com" scope=2 filter="(mail=*@example.com)" attrs=ALL',
                f"{recent} conn=4 op=2 RESULT err=0 tag=101 nentries=900 wtime=0.000100000 optime=0.300000000 etime=0.300100000 notes=P,U",
                "",
            ]
        )
        mcp = _make_archive_mcp(tmp_path, log)
        data = _call_find_unindexed(
            mcp, {"server_name": "test-archive", "time_range": "1h"}
        )

        assert data["total_unindexed_count"] == 1
        assert data["patterns"][0]["example_filter"] == "(mail=*@example.com)"

    def test_result_without_matching_srch_still_counted(self, tmp_path):
        """An unindexed RESULT with no recoverable SRCH line must still be
        counted (as 'unknown'), not silently dropped."""
        recent = _ts(datetime.now(timezone.utc) - timedelta(minutes=1))
        log = "\n".join(
            [
                f"{recent} conn=7 op=4 RESULT err=0 tag=101 nentries=4000 wtime=0.000100000 optime=0.700000000 etime=0.700100000 notes=U",
                "",
            ]
        )
        mcp = _make_archive_mcp(tmp_path, log)
        data = _call_find_unindexed(
            mcp, {"server_name": "test-archive", "time_range": "1h"}
        )

        assert data["total_unindexed_count"] == 1
        assert data["patterns"][0]["filter_pattern"] == "unknown"


# Bug 2: time-range filtering with real timestamps


class TestTimeRangeFiltering:

    def test_old_lines_excluded_with_short_range(self, tmp_path):
        """A 2020-dated notes=U line must be excluded from a 1h window."""
        mcp = _make_archive_mcp(tmp_path, _default_access_log())
        data = _call_find_unindexed(
            mcp, {"server_name": "test-archive", "time_range": "1h"}
        )

        assert data["total_unindexed_count"] == 2
        filters = [p["example_filter"] for p in data["patterns"]]
        assert "(description=old box)" not in filters

    def test_large_range_includes_old_lines(self, tmp_path):
        """A wide window must include the old unindexed search too."""
        mcp = _make_archive_mcp(tmp_path, _default_access_log())
        data = _call_find_unindexed(
            mcp, {"server_name": "test-archive", "time_range": "36500d"}
        )

        assert data["total_unindexed_count"] == 3
        filters = [p["example_filter"] for p in data["patterns"]]
        assert "(description=old box)" in filters

    def test_invalid_time_range_raises_tool_error(self, tmp_path):
        """An unparseable time_range must be an explicit error, not a
        filter that silently matches nothing."""
        mcp = _make_archive_mcp(tmp_path, _default_access_log())

        async def run():
            async with Client(mcp) as client:
                with pytest.raises(ToolError) as exc_info:
                    await client.call_tool(
                        "find_unindexed_searches",
                        {"server_name": "test-archive", "time_range": "yesterday"},
                    )
                assert "Invalid time_range" in str(exc_info.value)

        asyncio.run(run())

    def test_unsupported_unit_raises_tool_error(self, tmp_path):
        """Only h/d units are documented; minutes must be rejected."""
        mcp = _make_archive_mcp(tmp_path, _default_access_log())

        async def run():
            async with Client(mcp) as client:
                with pytest.raises(ToolError):
                    await client.call_tool(
                        "find_unindexed_searches",
                        {"server_name": "test-archive", "time_range": "30m"},
                    )

        asyncio.run(run())


# Unit tests for the timestamp helpers


class TestTimestampHelpers:

    def test_parse_access_log_timestamp_full_precision(self):
        """Minutes and seconds must be preserved (lib389's parse_timestamp
        drops them with current dateutil versions)."""
        line = (
            "[28/Jan/2024:11:01:31.392560011 -0500] conn=1 op=2 RESULT "
            "err=0 tag=101 nentries=1 wtime=0.000033222 optime=0.000123456 "
            "etime=0.000160000 notes=U"
        )
        dt = _parse_access_log_timestamp(line)
        assert dt is not None
        assert (dt.year, dt.month, dt.day) == (2024, 1, 28)
        assert (dt.hour, dt.minute, dt.second) == (11, 1, 31)
        assert dt.utcoffset() == timedelta(hours=-5)

    def test_parse_access_log_timestamp_rejects_non_log_lines(self):
        assert _parse_access_log_timestamp("389-Directory/2.4.6 B2024.123.456") is None
        assert _parse_access_log_timestamp('{"local_time": "2025-02-12T17:00:47"}') is None
        assert _parse_access_log_timestamp("") is None

    def test_parse_time_range_valid(self):
        now = datetime.now(timezone.utc)
        cutoff = _parse_time_range("1h")
        assert cutoff is not None
        assert abs((now - timedelta(hours=1)) - cutoff) < timedelta(seconds=5)

        cutoff = _parse_time_range("7d")
        assert cutoff is not None
        assert abs((now - timedelta(days=7)) - cutoff) < timedelta(seconds=5)

    def test_parse_time_range_invalid(self):
        for bad in ("", "bogus", "1w", "h1", "yesterday", "-1h", "1.5h"):
            assert _parse_time_range(bad) is None
