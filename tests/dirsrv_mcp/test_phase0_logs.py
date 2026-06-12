"""Phase 0 regression tests for log tool fixes (tools/logs.py).

Covers four fixes:

1. time_range filtering parses per-format timestamps into datetimes
   (traditional access/error ``[%d/%b/%Y:%H:%M:%S.%f %z]``, audit
   ``%Y%m%d%H%M%S``, ISO for JSON logs) instead of comparing raw line
   prefixes lexicographically; invalid values raise ToolError.
2. parse_access_log(result_code=N) skips entries without an ``err``
   field instead of passing every non-RESULT line through.
3. analyze_error_log ``common_patterns`` text is scrubbed with the
   PrivacySanitizer (hostnames, paths, DNs) when privacy is on.
4. analyze_*_log rejects the ``pattern`` parameter in privacy mode
   (matched_count substring-oracle).

Tests use tmp_path archive fixtures — no live server required.
"""

from __future__ import annotations

import asyncio
import os
from datetime import datetime
from unittest.mock import patch

import pytest
from fastmcp import Client
from fastmcp.exceptions import ToolError

from ldap_assistant_mcp.dirsrv_mcp.server import DirSrvMCP
from ldap_assistant_mcp.dirsrv_mcp.tools.logs import (
    _parse_log_timestamp,
    _parse_time_range,
    _timestamp_in_range,
)
from ldap_assistant_mcp.core import LDAPServerConfig


# Fixture data

DSE_LDIF = """\
dn: cn=config
objectClass: top
objectClass: extensibleObject
objectClass: nsslapdConfig
cn: config
nsslapd-port: 389
nsslapd-localhost: localhost.localdomain
nsslapd-security: on

dn: cn=plugins,cn=config
objectClass: top
objectClass: nsContainer
cn: plugins
"""

# Two days of access log data: 4 lines on Jan 1, 2 lines on Jan 2.
ACCESS_LOG_TWO_DAYS = """\
[01/Jan/2024:10:00:01.000000000 +0000] conn=1 op=0 BIND dn="cn=Directory Manager" method=128 version=3
[01/Jan/2024:10:00:01.200000000 +0000] conn=1 op=0 RESULT err=0 tag=97 nentries=0 wtime=0.000001 optime=0.000100 etime=0.000101
[01/Jan/2024:10:00:02.000000000 +0000] conn=1 op=1 SRCH base="dc=example,dc=com" scope=2 filter="(uid=admin)" attrs=ALL
[01/Jan/2024:10:00:02.100000000 +0000] conn=1 op=1 RESULT err=32 tag=101 nentries=0 wtime=0.000001 optime=0.000300 etime=0.000301
[02/Jan/2024:11:00:00.000000000 +0000] conn=2 op=0 SRCH base="dc=example,dc=com" scope=2 filter="(cn=x)" attrs=ALL
[02/Jan/2024:11:00:00.100000000 +0000] conn=2 op=0 RESULT err=0 tag=101 nentries=1 wtime=0.000001 optime=0.000200 etime=0.000201
"""

# Two days of error log data with sensitive hostnames, paths, and DNs.
ERROR_LOG_TWO_DAYS = """\
[01/Jan/2024:10:00:01.000000000 +0000] - INFO - main - server starting up
[01/Jan/2024:10:00:03.000000000 +0000] - WARNING - replication - Replication agreement to host1.example.com:636 not responding
[02/Jan/2024:11:00:00.000000000 +0000] - ERR - backend - Failed to read /var/lib/dirsrv/slapd-x/db/userRoot/id2entry.db
[02/Jan/2024:11:00:05.000000000 +0000] - ERR - backend - uid=admin,ou=people,dc=example,dc=com failed login for uid=admin
"""

# Three days of audit log data.
AUDIT_LOG_THREE_DAYS = """\
time: 20240101100001
dn: cn=config
result: 0
changetype: modify
replace: nsslapd-loglevel
nsslapd-loglevel: 16384
-
modifiersname: cn=Directory Manager
modifytimestamp: 20240101100001Z

time: 20240102110000
dn: uid=testuser,ou=People,dc=example,dc=com
result: 0
changetype: add
objectClass: top
uid: testuser
creatorsname: cn=Directory Manager
createtimestamp: 20240102110000Z

time: 20240103120000
dn: uid=olduser,ou=People,dc=example,dc=com
result: 0
changetype: delete
modifiersname: cn=Directory Manager
modifytimestamp: 20240103120000Z
"""


# Fixtures

@pytest.fixture
def archive_env():
    """Ensure no external config leaks into tests; privacy OFF."""
    env = {
        "LDAP_MCP_EXPOSE_SENSITIVE_DATA": "true",
        "LDAP_SERVERS_CONFIG": "",
    }
    with patch.dict(os.environ, env):
        yield


@pytest.fixture
def archive_dir(tmp_path):
    """Create an archive directory with multi-day log fixture data."""
    inst = "slapd-phase0"

    config_dir = tmp_path / "etc" / "dirsrv" / inst
    config_dir.mkdir(parents=True)
    (config_dir / "dse.ldif").write_text(DSE_LDIF)

    logs_dir = tmp_path / "var" / "log" / "dirsrv" / inst
    logs_dir.mkdir(parents=True)
    (logs_dir / "access").write_text(ACCESS_LOG_TWO_DAYS)
    (logs_dir / "errors").write_text(ERROR_LOG_TWO_DAYS)
    (logs_dir / "audit").write_text(AUDIT_LOG_THREE_DAYS)

    return tmp_path


@pytest.fixture
def archive_mcp(archive_env, archive_dir):
    """DirSrvMCP with archive server, privacy OFF."""
    config = LDAPServerConfig(
        name="phase0-archive",
        hostname="archive",
        port=0,
        is_archive=True,
        archive_path=str(archive_dir),
    )
    return DirSrvMCP(servers=[config], include_env_fallback=False)


@pytest.fixture
def privacy_archive_mcp(archive_dir):
    """DirSrvMCP with privacy mode ON."""
    env = {
        "LDAP_MCP_EXPOSE_SENSITIVE_DATA": "false",
        "LDAP_SERVERS_CONFIG": "",
    }
    with patch.dict(os.environ, env):
        config = LDAPServerConfig(
            name="phase0-priv",
            hostname="archive",
            port=0,
            is_archive=True,
            archive_path=str(archive_dir),
        )
        yield DirSrvMCP(servers=[config], include_env_fallback=False)


# Bug 1 — time_range timestamp parsing helpers (unit level)

class TestTimestampParsing:
    """_parse_log_timestamp must handle every supported log format."""

    def test_access_log_format_with_brackets(self):
        dt = _parse_log_timestamp("[01/Jan/2024:10:00:01.000000000 +0000]")
        assert dt == datetime(2024, 1, 1, 10, 0, 1)

    def test_error_log_format_no_brackets(self):
        dt = _parse_log_timestamp("28/Jan/2024:11:01:31.123456789 +0000")
        assert dt == datetime(2024, 1, 28, 11, 1, 31, 123456)

    def test_timezone_offset_normalized_to_utc(self):
        dt = _parse_log_timestamp("[01/Jan/2024:10:00:00.000000000 -0500]")
        assert dt == datetime(2024, 1, 1, 15, 0, 0)

    def test_audit_log_format(self):
        dt = _parse_log_timestamp("20240101100001")
        assert dt == datetime(2024, 1, 1, 10, 0, 1)

    def test_iso_format_with_z(self):
        dt = _parse_log_timestamp("2024-01-01T10:00:01Z")
        assert dt == datetime(2024, 1, 1, 10, 0, 1)

    def test_json_log_local_time_with_space_offset(self):
        # Real DS JSON log local_time format: nanoseconds + space + offset
        dt = _parse_log_timestamp("2025-02-12T17:00:47.699153015 -0500")
        assert dt == datetime(2025, 2, 12, 22, 0, 47, 699153)

    def test_unparseable_returns_none(self):
        assert _parse_log_timestamp("not a timestamp") is None
        assert _parse_log_timestamp("") is None

    def test_range_end_date_is_inclusive(self):
        # The pre-fix lexicographic bug: '[01/Jan/2024...]' > '2024-01-01'
        # meant the end bound filtered out EVERYTHING.
        start, end = _parse_time_range("2024-01-01 to 2024-01-01")
        assert _timestamp_in_range(
            "[01/Jan/2024:10:00:01.000000000 +0000]", start, end
        ) is True

    def test_range_excludes_other_days(self):
        start, end = _parse_time_range("2024-01-02 to 2024-01-03")
        assert _timestamp_in_range(
            "[01/Jan/2024:10:00:01.000000000 +0000]", start, end
        ) is False

    def test_last_hours_returns_datetime_start(self):
        start, end = _parse_time_range("last 24h")
        assert isinstance(start, datetime)
        assert end is None

    def test_last_minutes(self):
        start, end = _parse_time_range("last 30m")
        assert isinstance(start, datetime)

    def test_invalid_time_range_raises_tool_error(self):
        with pytest.raises(ToolError, match="time_range"):
            _parse_time_range("garbage value")

    def test_invalid_range_end_raises_tool_error(self):
        with pytest.raises(ToolError, match="time_range"):
            _parse_time_range("2024-01-01 to nonsense")

    def test_invalid_date_raises_tool_error(self):
        with pytest.raises(ToolError, match="time_range"):
            _parse_time_range("2024-99-99")

    def test_unparseable_log_timestamp_fails_open(self):
        # Entries with unparseable timestamps are kept, never hidden.
        start, end = _parse_time_range("2024-01-01 to 2024-01-02")
        assert _timestamp_in_range("weird-timestamp", start, end) is True


# Bug 1 — time_range filtering through the tools

class TestAccessLogTimeRange:

    def test_start_only_filters_first_day_out(self, archive_mcp):
        async def run():
            async with Client(archive_mcp) as client:
                result = await client.call_tool(
                    "parse_access_log",
                    {"server_name": "phase0-archive", "time_range": "2024-01-02"},
                )
                data = result.data
                assert "error" not in data
                assert data["matched_count"] == 2
                for entry in data["entries"]:
                    assert "02/Jan/2024" in entry["timestamp"]

        asyncio.run(run())

    def test_end_bound_does_not_filter_everything(self, archive_mcp):
        """Pre-fix, the end bound lexicographically excluded ALL lines."""
        async def run():
            async with Client(archive_mcp) as client:
                result = await client.call_tool(
                    "parse_access_log",
                    {
                        "server_name": "phase0-archive",
                        "time_range": "2024-01-01 to 2024-01-01",
                    },
                )
                data = result.data
                assert "error" not in data
                assert data["matched_count"] == 4
                for entry in data["entries"]:
                    assert "01/Jan/2024" in entry["timestamp"]

        asyncio.run(run())

    def test_range_covering_both_days(self, archive_mcp):
        async def run():
            async with Client(archive_mcp) as client:
                result = await client.call_tool(
                    "parse_access_log",
                    {
                        "server_name": "phase0-archive",
                        "time_range": "2024-01-01 to 2024-01-02",
                    },
                )
                data = result.data
                assert "error" not in data
                assert data["matched_count"] == 6

        asyncio.run(run())

    def test_datetime_precision_bound(self, archive_mcp):
        async def run():
            async with Client(archive_mcp) as client:
                result = await client.call_tool(
                    "parse_access_log",
                    {
                        "server_name": "phase0-archive",
                        "time_range": "2024-01-01 10:00:02 to 2024-01-02",
                    },
                )
                data = result.data
                assert "error" not in data
                # SRCH + RESULT err=32 on Jan 1 (>= 10:00:02), plus 2 on Jan 2
                assert data["matched_count"] == 4

        asyncio.run(run())

    def test_invalid_time_range_rejected(self, archive_mcp):
        async def run():
            async with Client(archive_mcp) as client:
                with pytest.raises(ToolError) as exc_info:
                    await client.call_tool(
                        "parse_access_log",
                        {
                            "server_name": "phase0-archive",
                            "time_range": "not a real range",
                        },
                    )
                assert "time_range" in str(exc_info.value)

        asyncio.run(run())

    def test_analyze_invalid_time_range_rejected(self, archive_mcp):
        async def run():
            async with Client(archive_mcp) as client:
                with pytest.raises(ToolError) as exc_info:
                    await client.call_tool(
                        "analyze_access_log",
                        {
                            "server_name": "phase0-archive",
                            "time_range": "yesterday-ish",
                        },
                    )
                assert "time_range" in str(exc_info.value)

        asyncio.run(run())


class TestErrorLogTimeRange:

    def test_second_day_only(self, archive_mcp):
        async def run():
            async with Client(archive_mcp) as client:
                result = await client.call_tool(
                    "parse_error_log",
                    {
                        "server_name": "phase0-archive",
                        "time_range": "2024-01-02 to 2024-01-02",
                    },
                )
                data = result.data
                assert "error" not in data
                assert data["matched_count"] == 2
                for entry in data["entries"]:
                    assert "02/Jan/2024" in entry["timestamp"]

        asyncio.run(run())

    def test_first_day_only(self, archive_mcp):
        async def run():
            async with Client(archive_mcp) as client:
                result = await client.call_tool(
                    "parse_error_log",
                    {
                        "server_name": "phase0-archive",
                        "time_range": "2024-01-01 to 2024-01-01",
                    },
                )
                data = result.data
                assert "error" not in data
                assert data["matched_count"] == 2
                for entry in data["entries"]:
                    assert "01/Jan/2024" in entry["timestamp"]

        asyncio.run(run())

    def test_invalid_time_range_rejected(self, archive_mcp):
        async def run():
            async with Client(archive_mcp) as client:
                with pytest.raises(ToolError) as exc_info:
                    await client.call_tool(
                        "parse_error_log",
                        {
                            "server_name": "phase0-archive",
                            "time_range": "????",
                        },
                    )
                assert "time_range" in str(exc_info.value)

        asyncio.run(run())


class TestAuditLogTimeRange:

    def test_middle_day_only(self, archive_mcp):
        async def run():
            async with Client(archive_mcp) as client:
                result = await client.call_tool(
                    "parse_audit_log",
                    {
                        "server_name": "phase0-archive",
                        "time_range": "2024-01-02 to 2024-01-02",
                    },
                )
                data = result.data
                assert "error" not in data
                assert data["matched_count"] == 1
                assert data["changes"][0]["changetype"] == "add"

        asyncio.run(run())

    def test_start_only(self, archive_mcp):
        async def run():
            async with Client(archive_mcp) as client:
                result = await client.call_tool(
                    "parse_audit_log",
                    {
                        "server_name": "phase0-archive",
                        "time_range": "2024-01-03",
                    },
                )
                data = result.data
                assert "error" not in data
                assert data["matched_count"] == 1
                assert data["changes"][0]["changetype"] == "delete"

        asyncio.run(run())

    def test_full_range(self, archive_mcp):
        async def run():
            async with Client(archive_mcp) as client:
                result = await client.call_tool(
                    "parse_audit_log",
                    {
                        "server_name": "phase0-archive",
                        "time_range": "2024-01-01 to 2024-01-03",
                    },
                )
                data = result.data
                assert "error" not in data
                assert data["matched_count"] == 3

        asyncio.run(run())

    def test_invalid_time_range_rejected(self, archive_mcp):
        async def run():
            async with Client(archive_mcp) as client:
                with pytest.raises(ToolError) as exc_info:
                    await client.call_tool(
                        "parse_audit_log",
                        {
                            "server_name": "phase0-archive",
                            "time_range": "whenever",
                        },
                    )
                assert "time_range" in str(exc_info.value)

        asyncio.run(run())


# Bug 2 — result_code must skip entries without an err field

class TestResultCodeFilter:

    def test_only_entries_with_err_returned(self, archive_mcp):
        async def run():
            async with Client(archive_mcp) as client:
                result = await client.call_tool(
                    "parse_access_log",
                    {"server_name": "phase0-archive", "result_code": 0},
                )
                data = result.data
                assert "error" not in data
                entries = data["entries"]
                assert len(entries) > 0
                for entry in entries:
                    # Pre-fix: BIND/SRCH lines (no err field) leaked through
                    assert "err" in entry, f"entry without err leaked: {entry}"
                    assert int(entry["err"]) == 0

        asyncio.run(run())

    def test_err_32_returns_exactly_one(self, archive_mcp):
        async def run():
            async with Client(archive_mcp) as client:
                result = await client.call_tool(
                    "parse_access_log",
                    {"server_name": "phase0-archive", "result_code": 32},
                )
                data = result.data
                assert "error" not in data
                assert data["matched_count"] == 1
                assert len(data["entries"]) == 1
                entry = data["entries"][0]
                assert entry["action"] == "RESULT"
                assert int(entry["err"]) == 32

        asyncio.run(run())

    def test_matched_count_consistent_with_entries(self, archive_mcp):
        async def run():
            async with Client(archive_mcp) as client:
                result = await client.call_tool(
                    "parse_access_log",
                    {"server_name": "phase0-archive", "result_code": 0},
                )
                data = result.data
                # 2 RESULT err=0 lines (Jan 1 BIND result + Jan 2 SRCH result)
                assert data["matched_count"] == 2
                assert len(data["entries"]) == 2

        asyncio.run(run())

    def test_analyze_result_code_stats(self, archive_mcp):
        async def run():
            async with Client(archive_mcp) as client:
                result = await client.call_tool(
                    "analyze_access_log",
                    {"server_name": "phase0-archive", "result_code": 32},
                )
                data = result.data
                assert "error" not in data
                assert data["matched_count"] == 1
                assert data["failed_operations"] == {"32": 1}
                # Only RESULT lines can carry err — nothing else counted
                assert set(data["operation_stats"]) == {"RESULT"}

        asyncio.run(run())


# Leak 4 — pattern parameter rejected in privacy mode

class TestPatternRejectedInPrivacyMode:

    def test_analyze_access_log_pattern_rejected(self, privacy_archive_mcp):
        async def run():
            async with Client(privacy_archive_mcp) as client:
                with pytest.raises(ToolError) as exc_info:
                    await client.call_tool(
                        "analyze_access_log",
                        {"server_name": "phase0-priv", "pattern": "uid=a"},
                    )
                msg = str(exc_info.value)
                assert "privacy" in msg.lower()
                assert "pattern" in msg.lower()

        asyncio.run(run())

    def test_analyze_error_log_pattern_rejected(self, privacy_archive_mcp):
        async def run():
            async with Client(privacy_archive_mcp) as client:
                with pytest.raises(ToolError) as exc_info:
                    await client.call_tool(
                        "analyze_error_log",
                        {"server_name": "phase0-priv", "pattern": "secret"},
                    )
                msg = str(exc_info.value)
                assert "privacy" in msg.lower()
                assert "pattern" in msg.lower()

        asyncio.run(run())

    def test_analyze_without_pattern_still_works_in_privacy(self, privacy_archive_mcp):
        async def run():
            async with Client(privacy_archive_mcp) as client:
                result = await client.call_tool(
                    "analyze_access_log",
                    {"server_name": "phase0-priv"},
                )
                data = result.data
                assert "error" not in data
                assert data["matched_count"] > 0

        asyncio.run(run())

    def test_pattern_allowed_when_privacy_off(self, archive_mcp):
        async def run():
            async with Client(archive_mcp) as client:
                result = await client.call_tool(
                    "analyze_access_log",
                    {"server_name": "phase0-archive", "pattern": "SRCH"},
                )
                data = result.data
                assert "error" not in data

        asyncio.run(run())


# Leak 3 — common_patterns sanitized via PrivacySanitizer

class TestCommonPatternsSanitized:

    def test_privacy_on_scrubs_sensitive_text(self, privacy_archive_mcp):
        async def run():
            async with Client(privacy_archive_mcp) as client:
                result = await client.call_tool(
                    "analyze_error_log",
                    {"server_name": "phase0-priv"},
                )
                data = result.data
                assert "error" not in data
                patterns = data["common_patterns"]
                assert len(patterns) > 0
                joined = " ".join(p["pattern"] for p in patterns)
                # FQDN hostnames scrubbed (digits are normalised to N first)
                assert "example.com" not in joined
                # Absolute paths scrubbed
                assert "/var/lib" not in joined
                # DNs and bare attr=value usernames scrubbed
                assert "uid=admin" not in joined
                assert "ou=people" not in joined

        asyncio.run(run())

    def test_privacy_off_keeps_raw_text(self, archive_mcp):
        async def run():
            async with Client(archive_mcp) as client:
                result = await client.call_tool(
                    "analyze_error_log",
                    {"server_name": "phase0-archive"},
                )
                data = result.data
                assert "error" not in data
                joined = " ".join(p["pattern"] for p in data["common_patterns"])
                # _track_pattern normalises digits to N: host1 -> hostN
                assert "hostN.example.com" in joined

        asyncio.run(run())
