"""Tests for log parsing tools and healthcheck parser.

Tests cover:
- Healthcheck parser (archive/healthcheck_parser.py)
- parse_access_log, parse_error_log, parse_audit_log (tools/logs.py)
- Privacy sanitization for log tools

Tests use tmp_path with inline fixture data — no external files needed.
"""

from __future__ import annotations

import asyncio
import os
from unittest.mock import patch

import pytest
from fastmcp import Client

from ldap_assistant_mcp.dirsrv_mcp.archive.healthcheck_parser import parse_healthcheck_output
from ldap_assistant_mcp.dirsrv_mcp.server import DirSrvMCP
from ldap_assistant_mcp.core import LDAPServerConfig


# Fixture data

DSE_LDIF = """\
dn: cn=config
objectClass: top
objectClass: extensibleObject
objectClass: nsslapdConfig
cn: config
nsslapd-port: 389
nsslapd-secureport: 636
nsslapd-versionstring: 389-Directory/2.4.6
nsslapd-localhost: localhost.localdomain
nsslapd-security: on
nsslapd-rootpwstoragescheme: PBKDF2_SHA256
nsslapd-maxdescriptors: 4096
nsslapd-threadnumber: 16
nsslapd-cachememsize: 10485760
nsslapd-accesslog-logbuffering: on
nsslapd-accesslog-logging-enabled: on
nsslapd-errorlog-logging-enabled: on
nsslapd-auditlog-logging-enabled: off
nsslapd-allow-anonymous-access: rootdse

dn: cn=encryption,cn=config
objectClass: top
objectClass: nsEncryptionConfig
cn: encryption
sslVersionMin: TLS1.2
sslVersionMax: TLS1.3

dn: cn=plugins,cn=config
objectClass: top
objectClass: nsContainer
cn: plugins

dn: cn=MemberOf Plugin,cn=plugins,cn=config
objectClass: top
objectClass: nsSlapdPlugin
cn: MemberOf Plugin
nsslapd-pluginEnabled: on
nsslapd-pluginType: betxnpostoperation
nsslapd-pluginPath: libmemberof-plugin

dn: cn=Referential Integrity Postoperation,cn=plugins,cn=config
objectClass: top
objectClass: nsSlapdPlugin
cn: Referential Integrity Postoperation
nsslapd-pluginEnabled: on
nsslapd-pluginType: betxnpostoperation
nsslapd-pluginPath: libreferint-plugin

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
nsslapd-cachememsize: 209715200
nsslapd-cachesize: -1
nsslapd-dncachememsize: 10485760

dn: cn=index,cn=userRoot,cn=ldbm database,cn=plugins,cn=config
objectClass: top
objectClass: extensibleObject
cn: index

dn: cn=uid,cn=index,cn=userRoot,cn=ldbm database,cn=plugins,cn=config
objectClass: top
objectClass: nsIndex
cn: uid
nsSystemIndex: false
nsIndexType: eq

dn: cn=replica,cn=dc\\=example\\,dc\\=com,cn=mapping tree,cn=config
objectClass: top
objectClass: nsDS5Replica
cn: replica
nsds5replicaroot: dc=example,dc=com
nsds5replicatype: 3
nsds5replicaid: 1
"""

SAMPLE_ACCESS_LOG = """\
389-Directory/2.4.6 B2024.123.456
ldap-assistant-mcp starting up
[01/Jan/2024:10:00:01.000000000 +0000] conn=1 fd=64 slot=64 connection from 127.0.0.1 to 127.0.0.1
[01/Jan/2024:10:00:01.100000000 +0000] conn=1 op=0 BIND dn="cn=Directory Manager" method=128 version=3
[01/Jan/2024:10:00:01.200000000 +0000] conn=1 op=0 RESULT err=0 tag=97 nentries=0 wtime=0.000001 optime=0.000100 etime=0.000101
[01/Jan/2024:10:00:02.000000000 +0000] conn=1 op=1 SRCH base="dc=example,dc=com" scope=2 filter="(uid=admin)" attrs=ALL
[01/Jan/2024:10:00:02.100000000 +0000] conn=1 op=1 RESULT err=0 tag=101 nentries=1 wtime=0.000001 optime=0.000200 etime=0.000201
[01/Jan/2024:10:00:03.000000000 +0000] conn=1 op=2 SRCH base="dc=example,dc=com" scope=2 filter="(uid=testuser)" attrs=ALL
[01/Jan/2024:10:00:03.100000000 +0000] conn=1 op=2 RESULT err=32 tag=101 nentries=0 wtime=0.000001 optime=0.000300 etime=0.000301
[01/Jan/2024:10:00:04.000000000 +0000] conn=2 fd=65 slot=65 connection from 10.0.0.1 to 127.0.0.1
[01/Jan/2024:10:00:04.100000000 +0000] conn=2 op=0 BIND dn="cn=replication manager" method=128 version=3
[01/Jan/2024:10:00:04.200000000 +0000] conn=2 op=0 RESULT err=0 tag=97 nentries=0 wtime=0.000001 optime=0.000100 etime=0.000101
[01/Jan/2024:10:00:05.000000000 +0000] conn=2 op=1 MOD dn="cn=config"
[01/Jan/2024:10:00:05.100000000 +0000] conn=2 op=1 RESULT err=0 tag=103 nentries=0 wtime=0.000001 optime=0.001000 etime=0.001001
[01/Jan/2024:10:00:06.000000000 +0000] conn=1 op=3 fd=64 closed - U1
[01/Jan/2024:10:00:07.000000000 +0000] conn=-1 op=0 SRCH base="cn=config" scope=0 filter="(objectclass=*)" attrs=ALL
[01/Jan/2024:10:00:07.100000000 +0000] conn=-1 op=0 RESULT err=0 tag=101 nentries=1 wtime=0.000000 optime=0.000050 etime=0.000050
[01/Jan/2024:10:00:08.000000000 +0000] conn=3 AUTOBIND dn="cn=Directory Manager"
"""

SAMPLE_ERROR_LOG = """\
[01/Jan/2024:10:00:01.000000000 +0000] - INFO - main - 389-Directory/2.4.6 starting up
[01/Jan/2024:10:00:02.000000000 +0000] - INFO - main - Listening on all interfaces port 389 for LDAP requests
[01/Jan/2024:10:00:03.000000000 +0000] - WARNING - replication - Replication agreement to host1.example.com:636 not responding
[01/Jan/2024:10:00:04.000000000 +0000] - ERR - backend - ldbm_back_ldbm2index: Backend userRoot error reading entry
[01/Jan/2024:10:00:05.000000000 +0000] - INFO - plugins - MemberOf Plugin started
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
objectClass: inetOrgPerson
uid: testuser
cn: Test User
sn: User
creatorsname: cn=Directory Manager
createtimestamp: 20240101100010Z

time: 20240101100020
dn: uid=olduser,ou=People,dc=example,dc=com
result: 0
changetype: delete
modifiersname: cn=Directory Manager
modifytimestamp: 20240101100020Z
"""

SAMPLE_AUDIT_LOG_JSON = """\
{"date": "2024-01-01T10:00:01Z", "gm_time": "2024-01-01T10:00:01Z", "dn": "cn=config", "changetype": "modify", "modifiersname": "cn=Directory Manager"}
{"date": "2024-01-01T10:00:10Z", "gm_time": "2024-01-01T10:00:10Z", "dn": "uid=testuser,ou=People,dc=example,dc=com", "changetype": "add", "modifiersname": "cn=Directory Manager"}
"""

HEALTHCHECK_OUTPUT_PASS = """\
Beginning lint report, this could take a while ...
Checking config...
Checking backends...
Checking encryption...

Health check passed.  No issues found.
"""

HEALTHCHECK_OUTPUT_FINDINGS = """\
Beginning lint report, this could take a while ...
Checking Backends ...
Checking Config ...
2 Issues found!  Generating report ...

[1] DS Lint Error: DSBLE0001
--------------------------------------------------------------------------------
Severity: HIGH
Check: backends:userroot:mappingtree
Affects:
 -- dc=example,dc=com

Details:
-----------
No backup has been taken for the backend 'userRoot'.

Resolution:
-----------
Consider creating regular backups to prevent data loss.

[2] DS Lint Error: DSELE0001
--------------------------------------------------------------------------------
Severity: MEDIUM
Check: encryption:check_tls_version
Affects:
 -- cn=encryption,cn=config

Details:
-----------
The password storage scheme uses a weak algorithm.

Resolution:
-----------
Upgrade to PBKDF2_SHA256 for better security.

===== End Of Report (2 Issues found) =====
"""

HEALTHCHECK_OUTPUT_EMPTY = ""
HEALTHCHECK_OUTPUT_MALFORMED = """\
Some random text
that isn't a healthcheck
output format at all
"""


# Fixtures

@pytest.fixture
def archive_env():
    """Ensure no external config leaks into tests."""
    env = {
        "LDAP_MCP_EXPOSE_SENSITIVE_DATA": "true",
        "LDAP_SERVERS_CONFIG": "",
    }
    with patch.dict(os.environ, env):
        yield


@pytest.fixture
def archive_dir(tmp_path):
    """Create an archive directory with all fixture data."""
    inst = "slapd-testinst"

    # Config
    config_dir = tmp_path / "etc" / "dirsrv" / inst
    config_dir.mkdir(parents=True)
    (config_dir / "dse.ldif").write_text(DSE_LDIF)
    schema_dir = config_dir / "schema"
    schema_dir.mkdir()
    (schema_dir / "99user.ldif").write_text("# custom schema\n")

    # Logs
    logs_dir = tmp_path / "var" / "log" / "dirsrv" / inst
    logs_dir.mkdir(parents=True)
    (logs_dir / "access").write_text(SAMPLE_ACCESS_LOG)
    (logs_dir / "errors").write_text(SAMPLE_ERROR_LOG)
    (logs_dir / "audit").write_text(SAMPLE_AUDIT_LOG)

    return tmp_path


@pytest.fixture
def archive_dir_json_audit(tmp_path):
    """Archive directory with JSON-format audit log."""
    inst = "slapd-jsoninst"

    config_dir = tmp_path / "etc" / "dirsrv" / inst
    config_dir.mkdir(parents=True)
    (config_dir / "dse.ldif").write_text(DSE_LDIF)

    logs_dir = tmp_path / "var" / "log" / "dirsrv" / inst
    logs_dir.mkdir(parents=True)
    (logs_dir / "access").write_text(SAMPLE_ACCESS_LOG)
    (logs_dir / "errors").write_text(SAMPLE_ERROR_LOG)
    (logs_dir / "audit").write_text(SAMPLE_AUDIT_LOG_JSON)

    return tmp_path


@pytest.fixture
def archive_mcp(archive_env, archive_dir):
    """DirSrvMCP with archive server."""
    config = LDAPServerConfig(
        name="test-archive",
        hostname="archive",
        port=0,
        is_archive=True,
        archive_path=str(archive_dir),
    )
    return DirSrvMCP(servers=[config], include_env_fallback=False)


@pytest.fixture
def archive_mcp_json_audit(archive_env, archive_dir_json_audit):
    """DirSrvMCP with JSON audit log archive."""
    config = LDAPServerConfig(
        name="test-json",
        hostname="archive",
        port=0,
        is_archive=True,
        archive_path=str(archive_dir_json_audit),
    )
    return DirSrvMCP(servers=[config], include_env_fallback=False)


@pytest.fixture
def privacy_archive_mcp(archive_dir):
    """DirSrvMCP with privacy mode enabled (no EXPOSE_SENSITIVE_DATA)."""
    env = {
        "LDAP_MCP_EXPOSE_SENSITIVE_DATA": "false",
        "LDAP_SERVERS_CONFIG": "",
    }
    with patch.dict(os.environ, env):
        config = LDAPServerConfig(
            name="priv-archive",
            hostname="archive",
            port=0,
            is_archive=True,
            archive_path=str(archive_dir),
        )
        yield DirSrvMCP(servers=[config], include_env_fallback=False)


# Healthcheck parser tests

class TestHealthcheckParser:

    def test_parse_findings(self):
        result = parse_healthcheck_output(HEALTHCHECK_OUTPUT_FINDINGS)
        assert result["passed"] is False
        assert len(result["findings"]) == 2
        assert result["findings"][0]["code"] == "DSBLE0001"
        assert result["findings"][0]["severity"] == "HIGH"
        assert "userRoot" in result["findings"][0]["description"]
        assert result["findings"][0].get("details") is not None
        assert result["findings"][1]["code"] == "DSELE0001"
        assert result["findings"][1]["severity"] == "MEDIUM"

    def test_parse_no_issues(self):
        result = parse_healthcheck_output(HEALTHCHECK_OUTPUT_PASS)
        assert result["passed"] is True
        assert len(result["findings"]) == 0

    def test_parse_empty(self):
        # Fail-closed: empty content must never be reported as passing.
        result = parse_healthcheck_output(HEALTHCHECK_OUTPUT_EMPTY)
        assert result["passed"] is False
        assert result["parse_status"] == "empty"
        assert result["findings"] == []
        assert result["raw_output"] == ""

    def test_parse_malformed(self):
        # Fail-closed: unrecognized content must never be reported as passing.
        result = parse_healthcheck_output(HEALTHCHECK_OUTPUT_MALFORMED)
        assert result["passed"] is False
        assert result["parse_status"] == "unknown"
        assert len(result["findings"]) == 0

    def test_parse_none(self):
        result = parse_healthcheck_output(None)
        assert result["passed"] is False
        assert result["parse_status"] == "empty"

    def test_unknown_severity_reported_as_unknown(self):
        """A finding block without a Severity: line must not be downgraded silently."""
        content = (
            "[1] DS Lint Error: DSXX0001\n"
            "----------------------------------------\n"
            "Check: config:something\n"
        )
        result = parse_healthcheck_output(content)
        assert result["passed"] is False
        assert len(result["findings"]) == 1
        assert result["findings"][0]["severity"] == "UNKNOWN"

    def test_known_severities_preserved(self):
        """All known severity values should pass through unchanged."""
        for sev in ("CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO", "WARNING"):
            content = (
                f"[1] DS Lint Error: DSXX0001\n"
                f"----------------------------------------\n"
                f"Severity: {sev}\n"
                f"Check: config:something\n"
            )
            result = parse_healthcheck_output(content)
            assert result["findings"][0]["severity"] == sev


# Access log tool tests

class TestParseAccessLog:

    def test_basic_parsing(self, archive_mcp):
        async def run():
            async with Client(archive_mcp) as client:
                result = await client.call_tool(
                    "parse_access_log",
                    {"server_name": "test-archive"},
                )
                data = result.data
                assert data["type"] == "access_log"
                assert "error" not in data
                assert data["total_parsed"] > 0
                assert len(data.get("entries", [])) > 0

        asyncio.run(run())

    def test_operation_filter(self, archive_mcp):
        async def run():
            async with Client(archive_mcp) as client:
                result = await client.call_tool(
                    "parse_access_log",
                    {"server_name": "test-archive", "operation": "SRCH"},
                )
                data = result.data
                assert "error" not in data
                # All matched entries should be SRCH operations
                for entry in data.get("entries", []):
                    action = entry.get("action", "")
                    if action:
                        assert action.upper() == "SRCH"

        asyncio.run(run())

    def test_result_code_filter(self, archive_mcp):
        async def run():
            async with Client(archive_mcp) as client:
                result = await client.call_tool(
                    "parse_access_log",
                    {"server_name": "test-archive", "result_code": 32},
                )
                data = result.data
                assert "error" not in data
                # Should find our "err=32" entry
                entries = data.get("entries", [])
                for entry in entries:
                    if "err" in entry:
                        assert int(entry["err"]) == 32

        asyncio.run(run())

    def test_pattern_filter(self, archive_mcp):
        async def run():
            async with Client(archive_mcp) as client:
                result = await client.call_tool(
                    "parse_access_log",
                    {"server_name": "test-archive", "pattern": "testuser"},
                )
                data = result.data
                assert "error" not in data

        asyncio.run(run())

    def test_limit(self, archive_mcp):
        async def run():
            async with Client(archive_mcp) as client:
                result = await client.call_tool(
                    "parse_access_log",
                    {"server_name": "test-archive", "limit": 2},
                )
                data = result.data
                assert "error" not in data
                assert len(data.get("entries", [])) <= 2

        asyncio.run(run())

    def test_empty_log(self, archive_env, tmp_path):
        """Empty access log should not error."""
        inst = "slapd-empty"
        config_dir = tmp_path / "etc" / "dirsrv" / inst
        config_dir.mkdir(parents=True)
        (config_dir / "dse.ldif").write_text(DSE_LDIF)
        logs_dir = tmp_path / "var" / "log" / "dirsrv" / inst
        logs_dir.mkdir(parents=True)
        (logs_dir / "access").write_text("")
        (logs_dir / "errors").write_text("")

        config = LDAPServerConfig(
            name="empty-log",
            hostname="archive",
            port=0,
            is_archive=True,
            archive_path=str(tmp_path),
        )
        mcp = DirSrvMCP(servers=[config], include_env_fallback=False)

        async def run():
            async with Client(mcp) as client:
                result = await client.call_tool(
                    "parse_access_log",
                    {"server_name": "empty-log"},
                )
                data = result.data
                assert "error" not in data
                assert data["total_parsed"] == 0

        asyncio.run(run())

    def test_missing_log_file(self, archive_env, tmp_path):
        """Missing access log should return error."""
        inst = "slapd-nolog"
        config_dir = tmp_path / "etc" / "dirsrv" / inst
        config_dir.mkdir(parents=True)
        (config_dir / "dse.ldif").write_text(DSE_LDIF)
        # No logs_dir at all

        config = LDAPServerConfig(
            name="no-log",
            hostname="archive",
            port=0,
            is_archive=True,
            config_path=str(config_dir),
        )
        mcp = DirSrvMCP(servers=[config], include_env_fallback=False)

        async def run():
            async with Client(mcp) as client:
                result = await client.call_tool(
                    "parse_access_log",
                    {"server_name": "no-log"},
                )
                data = result.data
                assert "error" in data

        asyncio.run(run())

    def test_operation_stats(self, archive_mcp):
        async def run():
            async with Client(archive_mcp) as client:
                result = await client.call_tool(
                    "parse_access_log",
                    {"server_name": "test-archive"},
                )
                data = result.data
                stats = data.get("operation_stats", {})
                assert isinstance(stats, dict)
                # Should have some operation types counted
                assert len(stats) > 0

        asyncio.run(run())

    def test_disconnect_lines(self, archive_mcp):
        """Disconnect (closed) lines should be parsed with DISCONNECT action."""
        async def run():
            async with Client(archive_mcp) as client:
                result = await client.call_tool(
                    "parse_access_log",
                    {"server_name": "test-archive"},
                )
                data = result.data
                stats = data.get("operation_stats", {})
                assert "DISCONNECT" in stats

        asyncio.run(run())

    def test_internal_ops(self, archive_mcp):
        """Internal operations (conn=-1) should be parsed without crashing."""
        async def run():
            async with Client(archive_mcp) as client:
                result = await client.call_tool(
                    "parse_access_log",
                    {"server_name": "test-archive"},
                )
                data = result.data
                assert "error" not in data
                # Internal SRCH + RESULT should be parsed
                assert data["total_parsed"] > 0

        asyncio.run(run())

    def test_autobind_lines(self, archive_mcp):
        """AUTOBIND lines should be parsed with AUTOBIND action."""
        async def run():
            async with Client(archive_mcp) as client:
                result = await client.call_tool(
                    "parse_access_log",
                    {"server_name": "test-archive", "operation": "AUTOBIND"},
                )
                data = result.data
                assert "error" not in data
                assert data["matched_count"] >= 1

        asyncio.run(run())

    def test_header_lines_skipped(self, archive_mcp):
        """Banner/header lines should be skipped without crashing."""
        async def run():
            async with Client(archive_mcp) as client:
                result = await client.call_tool(
                    "parse_access_log",
                    {"server_name": "test-archive"},
                )
                data = result.data
                assert "error" not in data
                # Header lines are counted in total_parsed but not matched
                # (no timestamp → _parse_access_line returns None)
                assert data["total_parsed"] > data["matched_count"]

        asyncio.run(run())


# Error log tool tests

class TestParseErrorLog:

    def test_basic_parsing(self, archive_mcp):
        async def run():
            async with Client(archive_mcp) as client:
                result = await client.call_tool(
                    "parse_error_log",
                    {"server_name": "test-archive"},
                )
                data = result.data
                assert data["type"] == "error_log"
                assert "error" not in data
                assert data["total_parsed"] > 0
                assert len(data.get("entries", [])) > 0

        asyncio.run(run())

    def test_severity_filter(self, archive_mcp):
        async def run():
            async with Client(archive_mcp) as client:
                result = await client.call_tool(
                    "parse_error_log",
                    {"server_name": "test-archive", "severity": "ERR"},
                )
                data = result.data
                assert "error" not in data
                # Filtered entries should only be ERR
                for entry in data.get("entries", []):
                    assert entry.get("severity", "").upper() == "ERR"

        asyncio.run(run())

    def test_component_filter(self, archive_mcp):
        async def run():
            async with Client(archive_mcp) as client:
                result = await client.call_tool(
                    "parse_error_log",
                    {"server_name": "test-archive", "component": "replication"},
                )
                data = result.data
                assert "error" not in data

        asyncio.run(run())

    def test_pattern_filter(self, archive_mcp):
        async def run():
            async with Client(archive_mcp) as client:
                result = await client.call_tool(
                    "parse_error_log",
                    {"server_name": "test-archive", "pattern": "starting up"},
                )
                data = result.data
                assert "error" not in data
                assert len(data.get("entries", [])) >= 1

        asyncio.run(run())

    def test_severity_counts(self, archive_mcp):
        async def run():
            async with Client(archive_mcp) as client:
                result = await client.call_tool(
                    "parse_error_log",
                    {"server_name": "test-archive"},
                )
                data = result.data
                counts = data.get("severity_counts", {})
                assert isinstance(counts, dict)
                # Should have at least INFO entries
                assert counts.get("INFO", 0) > 0

        asyncio.run(run())


# Audit log tool tests

class TestParseAuditLog:

    def test_traditional_format(self, archive_mcp):
        async def run():
            async with Client(archive_mcp) as client:
                result = await client.call_tool(
                    "parse_audit_log",
                    {"server_name": "test-archive"},
                )
                data = result.data
                assert data["type"] == "audit_log"
                assert "error" not in data
                assert data["total_parsed"] >= 3
                assert len(data.get("changes", [])) >= 3

        asyncio.run(run())

    def test_json_format(self, archive_mcp_json_audit):
        async def run():
            async with Client(archive_mcp_json_audit) as client:
                result = await client.call_tool(
                    "parse_audit_log",
                    {"server_name": "test-json"},
                )
                data = result.data
                assert data["type"] == "audit_log"
                assert "error" not in data
                assert data["total_parsed"] >= 2

        asyncio.run(run())

    def test_operation_filter(self, archive_mcp):
        async def run():
            async with Client(archive_mcp) as client:
                result = await client.call_tool(
                    "parse_audit_log",
                    {"server_name": "test-archive", "operation": "modify"},
                )
                data = result.data
                assert "error" not in data
                for change in data.get("changes", []):
                    assert change.get("changetype", "").lower() == "modify"

        asyncio.run(run())

    def test_bind_dn_filter(self, archive_mcp):
        async def run():
            async with Client(archive_mcp) as client:
                result = await client.call_tool(
                    "parse_audit_log",
                    {"server_name": "test-archive", "bind_dn": "cn=Directory Manager"},
                )
                data = result.data
                assert "error" not in data
                # All our test data has Directory Manager as the actor
                assert data["matched_count"] >= 1

        asyncio.run(run())

    def test_target_dn_filter(self, archive_mcp):
        async def run():
            async with Client(archive_mcp) as client:
                result = await client.call_tool(
                    "parse_audit_log",
                    {"server_name": "test-archive", "target_dn": "cn=config"},
                )
                data = result.data
                assert "error" not in data
                for change in data.get("changes", []):
                    assert "cn=config" in change.get("dn", "").lower()

        asyncio.run(run())

    def test_change_type_stats(self, archive_mcp):
        async def run():
            async with Client(archive_mcp) as client:
                result = await client.call_tool(
                    "parse_audit_log",
                    {"server_name": "test-archive"},
                )
                data = result.data
                stats = data.get("change_type_stats", {})
                assert "modify" in stats
                assert "add" in stats
                assert "delete" in stats

        asyncio.run(run())

    def test_actor_stats(self, archive_mcp):
        async def run():
            async with Client(archive_mcp) as client:
                result = await client.call_tool(
                    "parse_audit_log",
                    {"server_name": "test-archive"},
                )
                data = result.data
                actors = data.get("actor_stats", {})
                assert isinstance(actors, dict)
                assert len(actors) > 0

        asyncio.run(run())


# Parse tools — privacy blocked tests

class TestParseToolsPrivacyBlocked:
    """Parse tools must return a privacy error when privacy mode is ON."""

    def test_parse_access_log_blocked(self, privacy_archive_mcp):
        async def run():
            async with Client(privacy_archive_mcp) as client:
                result = await client.call_tool(
                    "parse_access_log",
                    {"server_name": "priv-archive"},
                )
                data = result.data
                assert data.get("type") == "privacy_restricted"
                assert "error" in data
                assert "privacy" in data["error"].lower()

        asyncio.run(run())

    def test_parse_error_log_blocked(self, privacy_archive_mcp):
        async def run():
            async with Client(privacy_archive_mcp) as client:
                result = await client.call_tool(
                    "parse_error_log",
                    {"server_name": "priv-archive"},
                )
                data = result.data
                assert data.get("type") == "privacy_restricted"
                assert "error" in data

        asyncio.run(run())

    def test_parse_audit_log_blocked(self, privacy_archive_mcp):
        async def run():
            async with Client(privacy_archive_mcp) as client:
                result = await client.call_tool(
                    "parse_audit_log",
                    {"server_name": "priv-archive"},
                )
                data = result.data
                assert data.get("type") == "privacy_restricted"
                assert "error" in data

        asyncio.run(run())


# Analyze tools tests

class TestAnalyzeAccessLog:
    """Tests for the analyze_access_log tool."""

    def test_basic_stats(self, archive_mcp):
        async def run():
            async with Client(archive_mcp) as client:
                result = await client.call_tool(
                    "analyze_access_log",
                    {"server_name": "test-archive"},
                )
                data = result.data
                assert data["type"] == "access_log_analysis"
                assert "error" not in data
                assert data["total_parsed"] > 0
                assert data["matched_count"] > 0
                assert isinstance(data["operation_stats"], dict)
                assert isinstance(data["failed_operations"], dict)
                assert isinstance(data["slow_operation_summary"], dict)
                assert "count" in data["slow_operation_summary"]
                assert "max_etime" in data["slow_operation_summary"]
                assert "avg_etime" in data["slow_operation_summary"]
                assert "unindexed_search_count" in data

        asyncio.run(run())

    def test_no_raw_data_keys(self, archive_mcp):
        """Analyze output must NOT contain individual entry data."""
        async def run():
            async with Client(archive_mcp) as client:
                result = await client.call_tool(
                    "analyze_access_log",
                    {"server_name": "test-archive"},
                )
                data = result.data
                assert "entries" not in data
                assert "slow_operations" not in data
                assert "raw" not in data

        asyncio.run(run())

    def test_operation_filter(self, archive_mcp):
        async def run():
            async with Client(archive_mcp) as client:
                result = await client.call_tool(
                    "analyze_access_log",
                    {"server_name": "test-archive", "operation": "RESULT"},
                )
                data = result.data
                assert "error" not in data
                stats = data.get("operation_stats", {})
                # Only RESULT ops should be counted
                for key in stats:
                    assert key == "RESULT"

        asyncio.run(run())

    def test_privacy_sanitizes_server(self, privacy_archive_mcp):
        """Server name should be sanitized in privacy mode."""
        async def run():
            async with Client(privacy_archive_mcp) as client:
                result = await client.call_tool(
                    "analyze_access_log",
                    {"server_name": "priv-archive"},
                )
                data = result.data
                assert "error" not in data
                assert data.get("server") == "priv-archive"

        asyncio.run(run())

    def test_result_code_filter(self, archive_mcp):
        async def run():
            async with Client(archive_mcp) as client:
                result = await client.call_tool(
                    "analyze_access_log",
                    {"server_name": "test-archive", "result_code": 32},
                )
                data = result.data
                assert "error" not in data
                # err=32 entries should contribute to failed_operations
                failed = data.get("failed_operations", {})
                assert "32" in failed

        asyncio.run(run())


class TestAnalyzeErrorLog:
    """Tests for the analyze_error_log tool."""

    def test_basic_stats(self, archive_mcp):
        async def run():
            async with Client(archive_mcp) as client:
                result = await client.call_tool(
                    "analyze_error_log",
                    {"server_name": "test-archive"},
                )
                data = result.data
                assert data["type"] == "error_log_analysis"
                assert "error" not in data
                assert data["total_parsed"] > 0
                assert isinstance(data["severity_counts"], dict)
                assert isinstance(data["component_counts"], dict)
                assert isinstance(data["common_patterns"], list)
                assert data["severity_counts"].get("INFO", 0) > 0

        asyncio.run(run())

    def test_no_raw_data_keys(self, archive_mcp):
        """Analyze output must NOT contain individual entries."""
        async def run():
            async with Client(archive_mcp) as client:
                result = await client.call_tool(
                    "analyze_error_log",
                    {"server_name": "test-archive"},
                )
                data = result.data
                assert "entries" not in data
                assert "raw" not in data

        asyncio.run(run())

    def test_severity_filter(self, archive_mcp):
        async def run():
            async with Client(archive_mcp) as client:
                result = await client.call_tool(
                    "analyze_error_log",
                    {"server_name": "test-archive", "severity": "ERR"},
                )
                data = result.data
                assert "error" not in data
                assert data["matched_count"] >= 1

        asyncio.run(run())

    def test_component_filter(self, archive_mcp):
        async def run():
            async with Client(archive_mcp) as client:
                result = await client.call_tool(
                    "analyze_error_log",
                    {"server_name": "test-archive", "component": "replication"},
                )
                data = result.data
                assert "error" not in data
                assert data["matched_count"] >= 1

        asyncio.run(run())

    def test_common_patterns_no_example_in_stats(self, archive_mcp):
        """Stats-only common_patterns should NOT contain 'example' field."""
        async def run():
            async with Client(archive_mcp) as client:
                result = await client.call_tool(
                    "analyze_error_log",
                    {"server_name": "test-archive"},
                )
                data = result.data
                for p in data.get("common_patterns", []):
                    assert "example" not in p
                    assert "pattern" in p
                    assert "count" in p

        asyncio.run(run())

    def test_privacy_sanitizes_patterns(self, privacy_archive_mcp):
        """In privacy mode, common_patterns text should be sanitized."""
        async def run():
            async with Client(privacy_archive_mcp) as client:
                result = await client.call_tool(
                    "analyze_error_log",
                    {"server_name": "priv-archive"},
                )
                data = result.data
                assert "error" not in data
                for p in data.get("common_patterns", []):
                    # DN-like strings should be stripped
                    assert "cn=Directory Manager" not in p.get("pattern", "")

        asyncio.run(run())

    def test_privacy_sanitizes_server(self, privacy_archive_mcp):
        async def run():
            async with Client(privacy_archive_mcp) as client:
                result = await client.call_tool(
                    "analyze_error_log",
                    {"server_name": "priv-archive"},
                )
                data = result.data
                assert data.get("server") == "priv-archive"

        asyncio.run(run())


class TestAnalyzeAuditLog:
    """Tests for the analyze_audit_log tool."""

    def test_basic_stats(self, archive_mcp):
        async def run():
            async with Client(archive_mcp) as client:
                result = await client.call_tool(
                    "analyze_audit_log",
                    {"server_name": "test-archive"},
                )
                data = result.data
                assert data["type"] == "audit_log_analysis"
                assert "error" not in data
                assert data["total_parsed"] >= 3
                assert isinstance(data["change_type_stats"], dict)
                assert "modify" in data["change_type_stats"]
                assert "add" in data["change_type_stats"]
                assert "delete" in data["change_type_stats"]
                assert isinstance(data["actor_stats"], dict)
                assert len(data["actor_stats"]) > 0

        asyncio.run(run())

    def test_no_raw_data_keys(self, archive_mcp):
        """Analyze output must NOT contain individual change records."""
        async def run():
            async with Client(archive_mcp) as client:
                result = await client.call_tool(
                    "analyze_audit_log",
                    {"server_name": "test-archive"},
                )
                data = result.data
                assert "changes" not in data
                assert "raw" not in data

        asyncio.run(run())

    def test_operation_filter(self, archive_mcp):
        async def run():
            async with Client(archive_mcp) as client:
                result = await client.call_tool(
                    "analyze_audit_log",
                    {"server_name": "test-archive", "operation": "modify"},
                )
                data = result.data
                assert "error" not in data
                assert data["matched_count"] >= 1

        asyncio.run(run())

    def test_privacy_sanitizes_actor_stats(self, privacy_archive_mcp):
        """In privacy mode, actor_stats keys (DNs) should be anonymized."""
        async def run():
            async with Client(privacy_archive_mcp) as client:
                result = await client.call_tool(
                    "analyze_audit_log",
                    {"server_name": "priv-archive"},
                )
                data = result.data
                assert "error" not in data
                for key in data.get("actor_stats", {}):
                    # Real DNs should not appear
                    assert "cn=Directory Manager" not in key

        asyncio.run(run())

    def test_privacy_off_shows_real_actors(self, archive_mcp):
        """With privacy off, actor_stats should contain real DNs."""
        async def run():
            async with Client(archive_mcp) as client:
                result = await client.call_tool(
                    "analyze_audit_log",
                    {"server_name": "test-archive"},
                )
                data = result.data
                assert "cn=Directory Manager" in data.get("actor_stats", {})

        asyncio.run(run())

    def test_json_format(self, archive_mcp_json_audit):
        async def run():
            async with Client(archive_mcp_json_audit) as client:
                result = await client.call_tool(
                    "analyze_audit_log",
                    {"server_name": "test-json"},
                )
                data = result.data
                assert data["type"] == "audit_log_analysis"
                assert "error" not in data
                assert data["total_parsed"] >= 2

        asyncio.run(run())


# Edge-case tests: regex validation and DN matching


class TestRegexValidation:
    """Verify that invalid regex patterns are handled gracefully."""

    def test_invalid_regex_access_log(self, archive_mcp):
        async def run():
            async with Client(archive_mcp) as client:
                result = await client.call_tool(
                    "parse_access_log",
                    {"server_name": "test-archive", "pattern": "(unclosed"},
                )
                data = result.data
                assert "error" in data
                assert "invalid" in data["error"].lower() or "regex" in data["error"].lower()

        asyncio.run(run())

    def test_invalid_regex_error_log(self, archive_mcp):
        async def run():
            async with Client(archive_mcp) as client:
                result = await client.call_tool(
                    "parse_error_log",
                    {"server_name": "test-archive", "pattern": "[bad"},
                )
                data = result.data
                assert "error" in data
                assert "invalid" in data["error"].lower() or "regex" in data["error"].lower()

        asyncio.run(run())

    def test_overly_long_pattern(self, archive_mcp):
        async def run():
            async with Client(archive_mcp) as client:
                # Pydantic Field(max_length=500) rejects the pattern
                # before the tool code runs, raising a ToolError.
                with pytest.raises(Exception) as exc_info:
                    await client.call_tool(
                        "parse_access_log",
                        {"server_name": "test-archive", "pattern": "a" * 1001},
                    )
                assert "500" in str(exc_info.value) or "too long" in str(exc_info.value).lower()

        asyncio.run(run())


class TestRedosDetection:
    """Verify that _validate_regex rejects known ReDoS-prone patterns."""

    def _validate(self, pattern):
        from ldap_assistant_mcp.dirsrv_mcp.tools.logs import _validate_regex
        return _validate_regex(pattern)

    def test_quantified_group_with_quantifier(self):
        """(a+)+ is a classic ReDoS pattern."""
        compiled, err = self._validate("(a+)+")
        assert err is not None
        assert "nested" in err["error"].lower() or "unsafe" in err["error"].lower()

    def test_quantified_charclass_group(self):
        r"""(\d+)+ should be rejected."""
        compiled, err = self._validate(r"(\d+)+")
        assert err is not None

    def test_star_star_group(self):
        """(x*)*  should be rejected."""
        compiled, err = self._validate("(x*)*")
        assert err is not None

    def test_quantified_alternation_overlapping(self):
        """(a|a)* is ambiguous alternation and should be rejected."""
        compiled, err = self._validate("(a|a)*")
        assert err is not None
        assert "alternation" in err["error"].lower() or "unsafe" in err["error"].lower()

    def test_quantified_alternation_overlap_via_quantifier(self):
        """(a|a?)+ has overlapping arms and should be rejected."""
        compiled, err = self._validate("(a|a?)+")
        assert err is not None

    def test_consecutive_quantifiers(self):
        """a** and a++ should be rejected."""
        for pat in ("a**", "a++", "a*+"):
            compiled, err = self._validate(pat)
            assert err is not None, f"Pattern {pat!r} should be rejected"

    def test_repeated_dotstar(self):
        """.*.*.*  three or more .* sequences."""
        compiled, err = self._validate(".*.*.*")
        assert err is not None

    def test_safe_patterns_pass(self):
        """Normal patterns should be accepted."""
        safe = [
            r"conn=\d+",
            r"RESULT err=\d+",
            r"op=\d+ SRCH",
            r"(ADD|MOD|DEL)",
            r"(ADD|MOD|DEL)+",
            r"(err=0|err=49)*",
            r"uid=[a-z]+",
        ]
        for pat in safe:
            compiled, err = self._validate(pat)
            assert err is None, f"Safe pattern {pat!r} was rejected: {err}"
            assert compiled is not None


class TestAuditDnMatching:
    """Verify proper DN matching in audit log filters."""

    def test_bind_dn_exact_match(self, archive_mcp):
        """bind_dn='cn=Directory Manager' should match exactly."""
        async def run():
            async with Client(archive_mcp) as client:
                result = await client.call_tool(
                    "parse_audit_log",
                    {"server_name": "test-archive", "bind_dn": "cn=Directory Manager"},
                )
                data = result.data
                assert "error" not in data
                assert data["matched_count"] >= 1

        asyncio.run(run())

    def test_target_dn_no_substring_match(self, archive_mcp):
        """target_dn should NOT do substring matching."""
        async def run():
            async with Client(archive_mcp) as client:
                # "cn=conf" should NOT match "cn=config" (not a valid DN ancestor)
                result = await client.call_tool(
                    "parse_audit_log",
                    {"server_name": "test-archive", "target_dn": "cn=conf"},
                )
                data = result.data
                assert "error" not in data
                # Should NOT match cn=config
                assert data["matched_count"] == 0

        asyncio.run(run())

    def test_target_dn_subtree_match(self, archive_mcp):
        """target_dn with a parent DN should match descendants."""
        async def run():
            async with Client(archive_mcp) as client:
                # dc=example,dc=com should match
                # uid=testuser,ou=People,dc=example,dc=com (under it)
                result = await client.call_tool(
                    "parse_audit_log",
                    {"server_name": "test-archive", "target_dn": "dc=example,dc=com"},
                )
                data = result.data
                assert "error" not in data
                # Should match the add/delete under dc=example,dc=com
                assert data["matched_count"] >= 1

        asyncio.run(run())

    def test_dn_filter_helper_no_false_positives(self):
        """_dn_matches_filter should NOT match partial names."""
        from ldap_assistant_mcp.dirsrv_mcp.tools.logs import _dn_matches_filter
        # cn=admin should NOT match cn=administrator
        assert _dn_matches_filter(
            "cn=administrator,dc=example,dc=com", "cn=admin"
        ) is False
        # Exact match should work
        assert _dn_matches_filter("cn=config", "cn=config") is True
        # Subtree match should work
        assert _dn_matches_filter(
            "cn=MemberOf,cn=plugins,cn=config", "cn=plugins,cn=config"
        ) is True
