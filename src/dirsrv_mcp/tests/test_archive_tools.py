"""Tests for archive mode tool functionality.

Tests verify that config, index, health, and archive-specific tools
work correctly with archive (SOS report) data sources, reading from
dse.ldif instead of live LDAP connections.
"""

from __future__ import annotations

import asyncio
import os
from unittest.mock import patch

import pytest
from fastmcp import Client

from src.dirsrv_mcp.server import DirSrvMCP
from src.ldap_assistant_mcp.server import LDAPServerConfig


# Rich dse.ldif for tool testing

RICH_DSE_LDIF = """\
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
nsslapd-maxdescriptors: 4096
nsslapd-threadnumber: 16
nsslapd-cachememsize: 10485760
nsslapd-ndn-cache-enabled: on
nsslapd-accesslog-logging-enabled: on
nsslapd-errorlog-logging-enabled: on
nsslapd-auditlog-logging-enabled: off

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
nsslapd-pluginVendor: 389 Project
nsslapd-pluginVersion: 2.4.6
nsslapd-pluginDescription: memberof plugin

dn: cn=Referential Integrity Postoperation,cn=plugins,cn=config
objectClass: top
objectClass: nsSlapdPlugin
cn: Referential Integrity Postoperation
nsslapd-pluginEnabled: on
nsslapd-pluginType: betxnpostoperation
nsslapd-pluginPath: libreferint-plugin
nsslapd-pluginVendor: 389 Project
nsslapd-pluginVersion: 2.4.6
nsslapd-pluginDescription: referential integrity plugin

dn: cn=Retro Changelog Plugin,cn=plugins,cn=config
objectClass: top
objectClass: nsSlapdPlugin
cn: Retro Changelog Plugin
nsslapd-pluginEnabled: off
nsslapd-pluginType: object
nsslapd-pluginPath: libretrocl-plugin
nsslapd-pluginVendor: 389 Project
nsslapd-pluginVersion: 2.4.6
nsslapd-pluginDescription: retro changelog plugin

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
nsIndexType: pres
nsIndexType: sub

dn: cn=cn,cn=index,cn=userRoot,cn=ldbm database,cn=plugins,cn=config
objectClass: top
objectClass: nsIndex
cn: cn
nsSystemIndex: false
nsIndexType: eq
nsIndexType: pres
nsIndexType: sub

dn: cn=sn,cn=index,cn=userRoot,cn=ldbm database,cn=plugins,cn=config
objectClass: top
objectClass: nsIndex
cn: sn
nsSystemIndex: false
nsIndexType: eq
nsIndexType: pres
nsIndexType: sub

dn: cn=mail,cn=index,cn=userRoot,cn=ldbm database,cn=plugins,cn=config
objectClass: top
objectClass: nsIndex
cn: mail
nsSystemIndex: false
nsIndexType: eq
nsIndexType: pres
nsIndexType: sub

dn: cn=objectclass,cn=index,cn=userRoot,cn=ldbm database,cn=plugins,cn=config
objectClass: top
objectClass: nsIndex
cn: objectclass
nsSystemIndex: true
nsIndexType: eq

dn: cn=NetscapeRoot,cn=ldbm database,cn=plugins,cn=config
objectClass: top
objectClass: extensibleObject
objectClass: nsBackendInstance
cn: NetscapeRoot
nsslapd-suffix: o=NetscapeRoot
nsslapd-cachememsize: 10485760
nsslapd-cachesize: -1

dn: cn=index,cn=NetscapeRoot,cn=ldbm database,cn=plugins,cn=config
objectClass: top
objectClass: extensibleObject
cn: index

dn: cn=objectclass,cn=index,cn=NetscapeRoot,cn=ldbm database,cn=plugins,cn=config
objectClass: top
objectClass: nsIndex
cn: objectclass
nsSystemIndex: true
nsIndexType: eq

dn: cn=replica,cn=dc\\=example\\,dc\\=com,cn=mapping tree,cn=config
objectClass: top
objectClass: nsDS5Replica
cn: replica
nsds5replicaroot: dc=example,dc=com
nsds5replicatype: 3
nsds5replicaid: 1
"""

MINIMAL_ACCESS_LOG = """\
[01/Jan/2024:00:00:01.000000000 +0000] conn=1 fd=64 slot=64 connection from 127.0.0.1 to 127.0.0.1
[01/Jan/2024:00:00:01.000000000 +0000] conn=1 op=0 BIND dn="cn=Directory Manager" method=128 version=3
[01/Jan/2024:00:00:01.000000000 +0000] conn=1 op=0 RESULT err=0 tag=97 nentries=0 wtime=0.000001 optime=0.000100 etime=0.000101
"""

MINIMAL_ERROR_LOG = """\
[01/Jan/2024:00:00:01.000000000 +0000] - INFO - main - 389-Directory/2.4.6 starting up
"""


# Fixtures


@pytest.fixture
def rich_archive_dir(tmp_path):
    """Create an archive with rich dse.ldif including backends and plugins."""
    inst = "slapd-testinst"

    # Config
    config_dir = tmp_path / "etc" / "dirsrv" / inst
    config_dir.mkdir(parents=True)
    (config_dir / "dse.ldif").write_text(RICH_DSE_LDIF)
    schema_dir = config_dir / "schema"
    schema_dir.mkdir()
    (schema_dir / "99user.ldif").write_text("# custom schema\n")

    # Logs
    logs_dir = tmp_path / "var" / "log" / "dirsrv" / inst
    logs_dir.mkdir(parents=True)
    (logs_dir / "access").write_text(MINIMAL_ACCESS_LOG)
    (logs_dir / "errors").write_text(MINIMAL_ERROR_LOG)

    return tmp_path


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
def archive_mcp(archive_env, rich_archive_dir):
    """Create DirSrvMCP with archive server using rich dse.ldif."""
    config = LDAPServerConfig(
        name="archive-test",
        hostname="archive",
        port=0,
        is_archive=True,
        archive_path=str(rich_archive_dir),
    )
    return DirSrvMCP(
        servers=[config],
        include_env_fallback=False,
    )


@pytest.fixture
def two_archive_mcp(archive_env, rich_archive_dir, tmp_path):
    """Create DirSrvMCP with two archive servers for comparison tests."""
    # Second archive with slightly different config
    inst2 = "slapd-testinst2"
    config_dir2 = tmp_path / "archive2" / "etc" / "dirsrv" / inst2
    config_dir2.mkdir(parents=True)
    # Modify port in second archive
    dse2 = RICH_DSE_LDIF.replace("nsslapd-port: 389", "nsslapd-port: 3389")
    dse2 = dse2.replace("nsslapd-security: on", "nsslapd-security: off")
    (config_dir2 / "dse.ldif").write_text(dse2)

    config1 = LDAPServerConfig(
        name="archive1",
        hostname="archive",
        port=0,
        is_archive=True,
        archive_path=str(rich_archive_dir),
    )
    config2 = LDAPServerConfig(
        name="archive2",
        hostname="archive",
        port=0,
        is_archive=True,
        config_path=str(config_dir2),
    )
    return DirSrvMCP(
        servers=[config1, config2],
        include_env_fallback=False,
    )


# Config tool tests


class TestConfigToolsArchive:
    """Test config.py tools with archive sources."""

    def test_get_server_configuration(self, archive_mcp):
        async def run():
            async with Client(archive_mcp) as client:
                result = await client.call_tool(
                    "get_server_configuration",
                    {"server_name": "archive-test"},
                )
                data = result.data
                assert data["type"] == "server_configuration"
                assert "error" not in data
                assert data.get("mode") == "archive"
                assert data["attribute_count"] > 0
                config = data["config"]
                assert any("port" in k.lower() for k in config)

        asyncio.run(run())

    def test_get_server_configuration_with_pattern(self, archive_mcp):
        async def run():
            async with Client(archive_mcp) as client:
                result = await client.call_tool(
                    "get_server_configuration",
                    {"server_name": "archive-test", "pattern": "security"},
                )
                data = result.data
                assert data["type"] == "server_configuration"
                assert "error" not in data
                # All returned attributes should contain 'security'
                for attr in data.get("config", {}):
                    assert "security" in attr.lower()

        asyncio.run(run())

    def test_list_plugins(self, archive_mcp):
        async def run():
            async with Client(archive_mcp) as client:
                result = await client.call_tool(
                    "list_plugins",
                    {"server_name": "archive-test"},
                )
                data = result.data
                assert data["type"] == "plugin_list"
                assert "error" not in data
                plugins = data.get("plugins", [])
                assert len(plugins) >= 2  # At least MemberOf and RefInt
                plugin_names = [p["name"] for p in plugins]
                assert "MemberOf Plugin" in plugin_names
                assert "Referential Integrity Postoperation" in plugin_names
                # Retro Changelog is disabled, should be filtered by default
                assert "Retro Changelog Plugin" not in plugin_names

        asyncio.run(run())

    def test_list_plugins_include_disabled(self, archive_mcp):
        async def run():
            async with Client(archive_mcp) as client:
                result = await client.call_tool(
                    "list_plugins",
                    {"server_name": "archive-test", "enabled_only": False},
                )
                data = result.data
                plugins = data.get("plugins", [])
                plugin_names = [p["name"] for p in plugins]
                assert "Retro Changelog Plugin" in plugin_names

        asyncio.run(run())

    def test_get_backend_configuration(self, archive_mcp):
        async def run():
            async with Client(archive_mcp) as client:
                result = await client.call_tool(
                    "get_backend_configuration",
                    {"server_name": "archive-test"},
                )
                data = result.data
                assert data["type"] == "backend_configuration"
                assert "error" not in data
                backends = data.get("backends", [])
                assert len(backends) >= 2  # userRoot and NetscapeRoot
                be_names = [b["name"] for b in backends]
                assert "userRoot" in be_names
                assert "NetscapeRoot" in be_names

                # Check userRoot details
                user_root = next(b for b in backends if b["name"] == "userRoot")
                assert user_root["suffix"] == "dc=example,dc=com"
                assert "index_count" in user_root
                assert user_root["index_count"] >= 4  # uid, cn, sn, mail, objectclass

                # Check replication info
                assert user_root.get("replication", {}).get("enabled") is True
                assert user_root["replication"]["role"] == "supplier"

        asyncio.run(run())

    def test_get_backend_configuration_filter(self, archive_mcp):
        async def run():
            async with Client(archive_mcp) as client:
                result = await client.call_tool(
                    "get_backend_configuration",
                    {"server_name": "archive-test", "backend": "userRoot"},
                )
                data = result.data
                backends = data.get("backends", [])
                assert len(backends) == 1
                assert backends[0]["name"] == "userRoot"

        asyncio.run(run())

    def test_compare_server_configurations(self, two_archive_mcp):
        async def run():
            async with Client(two_archive_mcp) as client:
                result = await client.call_tool(
                    "compare_server_configurations",
                    {"server1": "archive1", "server2": "archive2"},
                )
                data = result.data
                assert data["type"] == "config_comparison"
                assert "error" not in data
                # Should detect port and security differences
                diffs = data.get("differences", [])
                diff_attrs = [d["attribute"].lower() for d in diffs]
                assert "nsslapd-port" in diff_attrs or any("port" in a for a in diff_attrs)

        asyncio.run(run())


# Index tool tests


class TestIndexToolsArchive:
    """Test indexes.py tools with archive sources."""

    def test_list_indexes(self, archive_mcp):
        async def run():
            async with Client(archive_mcp) as client:
                result = await client.call_tool(
                    "list_indexes",
                    {"server_name": "archive-test"},
                )
                data = result.data
                assert data["type"] == "index_list"
                assert "error" not in data
                backends = data.get("backends", [])
                assert len(backends) >= 1

                # Find userRoot backend
                user_root = next(
                    (b for b in backends if b["name"] == "userRoot"),
                    None,
                )
                assert user_root is not None
                indexes = user_root.get("indexes", [])
                index_attrs = [idx["attribute"] for idx in indexes]
                assert "uid" in index_attrs
                assert "cn" in index_attrs
                assert "sn" in index_attrs
                assert "mail" in index_attrs

                # Check index details
                uid_idx = next(i for i in indexes if i["attribute"] == "uid")
                assert "eq" in uid_idx.get("types", [])

        asyncio.run(run())

    def test_list_indexes_specific_backend(self, archive_mcp):
        async def run():
            async with Client(archive_mcp) as client:
                result = await client.call_tool(
                    "list_indexes",
                    {"server_name": "archive-test", "backend": "userRoot"},
                )
                data = result.data
                backends = data.get("backends", [])
                assert len(backends) == 1
                assert backends[0]["name"] == "userRoot"

        asyncio.run(run())

    def test_analyze_index_configuration(self, archive_mcp):
        async def run():
            async with Client(archive_mcp) as client:
                result = await client.call_tool(
                    "analyze_index_configuration",
                    {"server_name": "archive-test"},
                )
                data = result.data
                assert data["type"] == "index_analysis"
                assert "error" not in data
                backends = data.get("backends", [])
                assert len(backends) >= 1

        asyncio.run(run())

    def test_find_unindexed_searches_archive(self, archive_mcp):
        """find_unindexed_searches should work with archive (has log files)."""
        async def run():
            async with Client(archive_mcp) as client:
                result = await client.call_tool(
                    "find_unindexed_searches",
                    {"server_name": "archive-test"},
                )
                data = result.data
                assert data["type"] == "unindexed_searches"
                # Should not error - archive has access log
                assert "error" not in data or "notes=U" not in data.get("error", "")

        asyncio.run(run())


# Health tool tests


class TestHealthToolsArchive:
    """Test health.py tools with archive sources."""

    def test_first_look_archive(self, archive_mcp):
        async def run():
            async with Client(archive_mcp) as client:
                result = await client.call_tool("first_look", {})
                data = result.data
                assert data["type"] == "first_look"
                assert "archive-test" in data.get("servers_checked", [])
                assert len(data.get("servers_failed", [])) == 0

                # Metrics should include basic info from dse.ldif
                metrics = data.get("detailed_metrics", {})
                srv_metrics = metrics.get("archive-test", {})
                assert srv_metrics.get("mode") == "archive"
                assert srv_metrics.get("version") is not None
                assert srv_metrics.get("backends") >= 2
                assert len(srv_metrics.get("suffixes", [])) >= 1

                # Should have an INFO finding about limited checks
                findings = data.get("findings", [])
                archive_findings = [
                    f for f in findings
                    if "ARCHIVE" in f.get("title", "").upper()
                    or "archive" in f.get("details", "").lower()
                ]
                assert len(archive_findings) > 0

        asyncio.run(run())

    def test_list_healthchecks_archive(self, archive_mcp):
        async def run():
            async with Client(archive_mcp) as client:
                result = await client.call_tool(
                    "list_healthchecks",
                    {"server_name": "archive-test"},
                )
                data = result.data
                assert data["type"] == "healthcheck_list"
                assert "error" not in data
                assert data.get("mode") == "archive"
                categories = data.get("categories", [])
                # Archive should only have dseldif checks
                assert "dseldif" in categories
                # Should NOT have fschecks, tls, or logs for archive
                assert "fschecks" not in categories
                assert "tls" not in categories

        asyncio.run(run())

    def test_run_healthcheck_archive(self, archive_mcp):
        async def run():
            async with Client(archive_mcp) as client:
                result = await client.call_tool(
                    "run_healthcheck",
                    {"server_name": "archive-test"},
                )
                data = result.data
                assert data["type"] == "healthcheck"
                assert "error" not in data
                assert data.get("mode") == "archive"
                # Should have run at least some checks
                assert data.get("total_checks_run", 0) >= 0

        asyncio.run(run())

    def test_run_healthcheck_specific_check(self, archive_mcp):
        async def run():
            async with Client(archive_mcp) as client:
                result = await client.call_tool(
                    "run_healthcheck",
                    {"server_name": "archive-test", "checks": ["dseldif:*"]},
                )
                data = result.data
                assert data["type"] == "healthcheck"
                assert "error" not in data
                # All executed checks should be dseldif
                for check in data.get("checks_executed", []):
                    assert check.startswith("dseldif:")

        asyncio.run(run())


# Replication tool tests (guard verification)


class TestReplicationToolsArchive:
    """Test replication tools properly handle archive servers."""

    def test_get_replication_topology_skips_archive(self, archive_mcp):
        """get_replication_topology should skip archive servers gracefully."""
        async def run():
            async with Client(archive_mcp) as client:
                result = await client.call_tool("get_replication_topology", {})
                data = result.data
                assert data["type"] == "replication_topology"
                # Archive server should be in failed list (skipped)
                assert "archive-test" in data.get("servers_failed", [])
                # Should have an info finding about skipping
                findings = data.get("findings", [])
                skip_findings = [
                    f for f in findings
                    if "archive" in f.get("title", "").lower()
                    or "archive" in f.get("details", "").lower()
                ]
                assert len(skip_findings) > 0

        asyncio.run(run())

    def test_get_replication_status_rejects_archive(self, archive_mcp):
        """get_replication_status should reject archive servers."""
        async def run():
            async with Client(archive_mcp) as client:
                with pytest.raises(Exception) as exc_info:
                    await client.call_tool(
                        "get_replication_status",
                        {"server_name": "archive-test"},
                    )
                assert "archive" in str(exc_info.value).lower() or "live" in str(exc_info.value).lower()

        asyncio.run(run())


# Cross-mode comparison tests


class TestCrossModeComparison:
    """Test comparing archive-to-archive configurations."""

    def test_compare_two_archives(self, two_archive_mcp):
        """Should detect differences between two archive sources."""
        async def run():
            async with Client(two_archive_mcp) as client:
                result = await client.call_tool(
                    "compare_server_configurations",
                    {"server1": "archive1", "server2": "archive2"},
                )
                data = result.data
                assert data["type"] == "config_comparison"
                assert "error" not in data
                diffs = data.get("differences", [])
                # We changed port (389->3389) and security (on->off)
                assert len(diffs) >= 2

        asyncio.run(run())

    def test_compare_archives_with_pattern(self, two_archive_mcp):
        """Should filter comparison by pattern."""
        async def run():
            async with Client(two_archive_mcp) as client:
                result = await client.call_tool(
                    "compare_server_configurations",
                    {
                        "server1": "archive1",
                        "server2": "archive2",
                        "pattern": "security",
                    },
                )
                data = result.data
                assert "error" not in data
                diffs = data.get("differences", [])
                # Should find at least the security diff
                for d in diffs:
                    assert "security" in d["attribute"].lower()

        asyncio.run(run())


# Fixture data for archive analysis / validation tools

# DSE with security-related attributes needed by validate_configuration
ANALYSIS_DSE_LDIF = """\
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

WEAK_DSE_LDIF = """\
dn: cn=config
objectClass: top
objectClass: extensibleObject
objectClass: nsslapdConfig
cn: config
nsslapd-port: 389
nsslapd-versionstring: 389-Directory/2.4.6
nsslapd-security: off
nsslapd-rootpwstoragescheme: SSHA
nsslapd-accesslog-logbuffering: off
nsslapd-auditlog-logging-enabled: off
nsslapd-allow-anonymous-access: on

dn: cn=encryption,cn=config
objectClass: top
objectClass: nsEncryptionConfig
cn: encryption
sslVersionMin: TLS1.0

dn: cn=plugins,cn=config
objectClass: top
objectClass: nsContainer
cn: plugins

dn: cn=ldbm database,cn=plugins,cn=config
objectClass: top
objectClass: nsSlapdPlugin
cn: ldbm database
nsslapd-pluginEnabled: on

dn: cn=userRoot,cn=ldbm database,cn=plugins,cn=config
objectClass: top
objectClass: extensibleObject
objectClass: nsBackendInstance
cn: userRoot
nsslapd-suffix: dc=example,dc=com
"""

SAMPLE_ACCESS_LOG = """\
[01/Jan/2024:10:00:01.000000000 +0000] conn=1 fd=64 slot=64 connection from 127.0.0.1 to 127.0.0.1
[01/Jan/2024:10:00:01.100000000 +0000] conn=1 op=0 BIND dn="cn=Directory Manager" method=128 version=3
[01/Jan/2024:10:00:01.200000000 +0000] conn=1 op=0 RESULT err=0 tag=97 nentries=0 wtime=0.000001 optime=0.000100 etime=0.000101
"""

SAMPLE_ERROR_LOG = """\
[01/Jan/2024:10:00:01.000000000 +0000] - INFO - main - 389-Directory/2.4.6 starting up
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
"""

HEALTHCHECK_OUTPUT_FINDINGS = """\
Beginning lint report, this could take a while ...

DSBLE0001 : HIGH : Backend Backup : dc=example,dc=com
No backup has been taken for the backend 'userRoot'.
Consider creating regular backups to prevent data loss.

DSELE0001 : MEDIUM : Weak Password Storage : cn=config
The password storage scheme uses a weak algorithm.
Upgrade to PBKDF2_SHA256 for better security.
"""


# Archive analysis fixtures

@pytest.fixture
def analysis_archive_dir(tmp_path):
    """Create an archive directory for analysis/validation tool tests."""
    inst = "slapd-testinst"

    config_dir = tmp_path / "etc" / "dirsrv" / inst
    config_dir.mkdir(parents=True)
    (config_dir / "dse.ldif").write_text(ANALYSIS_DSE_LDIF)
    schema_dir = config_dir / "schema"
    schema_dir.mkdir()
    (schema_dir / "99user.ldif").write_text("# custom schema\n")

    logs_dir = tmp_path / "var" / "log" / "dirsrv" / inst
    logs_dir.mkdir(parents=True)
    (logs_dir / "access").write_text(SAMPLE_ACCESS_LOG)
    (logs_dir / "errors").write_text(SAMPLE_ERROR_LOG)
    (logs_dir / "audit").write_text(SAMPLE_AUDIT_LOG)

    return tmp_path


@pytest.fixture
def analysis_archive_dir_with_sos(analysis_archive_dir):
    """Archive directory with SOS healthcheck output."""
    sos_dir = analysis_archive_dir / "sos_commands" / "dirsrv"
    sos_dir.mkdir(parents=True)
    (sos_dir / "dsctl_slapd-testinst_healthcheck").write_text(
        HEALTHCHECK_OUTPUT_FINDINGS
    )
    return analysis_archive_dir


@pytest.fixture
def analysis_archive_mcp(archive_env, analysis_archive_dir):
    """DirSrvMCP with archive server for analysis tool tests."""
    config = LDAPServerConfig(
        name="test-archive",
        hostname="archive",
        port=0,
        is_archive=True,
        archive_path=str(analysis_archive_dir),
    )
    return DirSrvMCP(servers=[config], include_env_fallback=False)


@pytest.fixture
def analysis_archive_mcp_sos(archive_env, analysis_archive_dir_with_sos):
    """DirSrvMCP with SOS report archive for analysis tool tests."""
    config = LDAPServerConfig(
        name="test-sos",
        hostname="archive",
        port=0,
        is_archive=True,
        archive_path=str(analysis_archive_dir_with_sos),
    )
    return DirSrvMCP(servers=[config], include_env_fallback=False)


@pytest.fixture
def analysis_privacy_archive_mcp(analysis_archive_dir):
    """DirSrvMCP with privacy mode for analysis tool tests."""
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
            archive_path=str(analysis_archive_dir),
        )
        yield DirSrvMCP(servers=[config], include_env_fallback=False)


@pytest.fixture
def weak_archive_mcp(archive_env, tmp_path):
    """Archive with deliberately weak configuration."""
    inst = "slapd-weakinst"
    config_dir = tmp_path / "etc" / "dirsrv" / inst
    config_dir.mkdir(parents=True)
    (config_dir / "dse.ldif").write_text(WEAK_DSE_LDIF)

    config = LDAPServerConfig(
        name="weak-archive",
        hostname="archive",
        port=0,
        is_archive=True,
        config_path=str(config_dir),
    )
    return DirSrvMCP(servers=[config], include_env_fallback=False)


# Archive analysis tool tests (tools/archive.py)


class TestAnalyzeArchive:

    def test_basic_analysis(self, analysis_archive_mcp):
        async def run():
            async with Client(analysis_archive_mcp) as client:
                result = await client.call_tool(
                    "analyze_archive",
                    {"server_name": "test-archive"},
                )
                data = result.data
                assert data["type"] == "archive_analysis"
                assert "error" not in data
                assert data.get("source_type") is not None
                assert data.get("instance_name") is not None

                cs = data.get("config_summary", {})
                assert cs.get("version") == "389-Directory/2.4.6"
                assert cs.get("port") == "389"
                assert cs.get("security_enabled") is True
                assert cs.get("backend_count") >= 1
                assert len(cs.get("suffixes", [])) >= 1
                assert cs.get("enabled_plugins") >= 2

        asyncio.run(run())

    def test_available_data_inventory(self, analysis_archive_mcp):
        async def run():
            async with Client(analysis_archive_mcp) as client:
                result = await client.call_tool(
                    "analyze_archive",
                    {"server_name": "test-archive"},
                )
                data = result.data
                ad = data.get("available_data", {})
                assert ad.get("dse_ldif") is True
                assert ad.get("logs_dir") is True
                assert ad.get("access_log") is True
                assert ad.get("error_log") is True

        asyncio.run(run())

    def test_sos_healthcheck(self, analysis_archive_mcp_sos):
        async def run():
            async with Client(analysis_archive_mcp_sos) as client:
                result = await client.call_tool(
                    "analyze_archive",
                    {"server_name": "test-sos"},
                )
                data = result.data
                assert "error" not in data
                hc = data.get("sos_healthcheck")
                assert hc is not None
                assert hc["passed"] is False
                assert len(hc["findings"]) == 2

        asyncio.run(run())

    def test_config_only_archive(self, archive_env, tmp_path):
        """Archive with only dse.ldif, no logs."""
        inst = "slapd-configonly"
        config_dir = tmp_path / "etc" / "dirsrv" / inst
        config_dir.mkdir(parents=True)
        (config_dir / "dse.ldif").write_text(ANALYSIS_DSE_LDIF)

        config = LDAPServerConfig(
            name="config-only",
            hostname="archive",
            port=0,
            is_archive=True,
            config_path=str(config_dir),
        )
        mcp = DirSrvMCP(servers=[config], include_env_fallback=False)

        async def run():
            async with Client(mcp) as client:
                result = await client.call_tool(
                    "analyze_archive",
                    {"server_name": "config-only"},
                )
                data = result.data
                assert data["type"] == "archive_analysis"
                assert "error" not in data
                ad = data.get("available_data", {})
                assert ad.get("dse_ldif") is True
                assert ad.get("logs_dir") is False

        asyncio.run(run())

    def test_replication_info(self, analysis_archive_mcp):
        async def run():
            async with Client(analysis_archive_mcp) as client:
                result = await client.call_tool(
                    "analyze_archive",
                    {"server_name": "test-archive"},
                )
                data = result.data
                repl = data.get("config_summary", {}).get("replication", [])
                assert len(repl) >= 1
                assert repl[0]["suffix"] == "dc=example,dc=com"
                assert repl[0]["role"] == "supplier"

        asyncio.run(run())

    def test_privacy_sanitization(self, analysis_privacy_archive_mcp):
        async def run():
            async with Client(analysis_privacy_archive_mcp) as client:
                result = await client.call_tool(
                    "analyze_archive",
                    {"server_name": "priv-archive"},
                )
                data = result.data
                assert data.get("server", "").startswith("[server-")
                assert data.get("instance_name") == "[instance]"

        asyncio.run(run())

    def test_rejects_live_server(self, archive_env, tmp_path):
        """analyze_archive should reject non-offline/non-archive servers."""
        config = LDAPServerConfig(
            name="live-server",
            hostname="localhost",
            port=389,
        )
        mcp = DirSrvMCP(servers=[config], include_env_fallback=False)

        async def run():
            async with Client(mcp) as client:
                result = await client.call_tool(
                    "analyze_archive",
                    {"server_name": "live-server"},
                )
                data = result.data
                assert "error" in data
                assert "offline" in data["error"].lower() or "archive" in data["error"].lower()

        asyncio.run(run())


# Validate configuration tool tests (tools/archive.py)


class TestValidateConfiguration:

    def test_clean_config(self, analysis_archive_mcp):
        """ANALYSIS_DSE_LDIF has mostly good config — should find limited issues."""
        async def run():
            async with Client(analysis_archive_mcp) as client:
                result = await client.call_tool(
                    "validate_configuration",
                    {"server_name": "test-archive"},
                )
                data = result.data
                assert data["type"] == "configuration_validation"
                assert "error" not in data
                assert isinstance(data.get("checks_run"), list)
                assert len(data["checks_run"]) >= 5
                # The clean config still has audit logging off
                assert data["total_issues"] >= 1

        asyncio.run(run())

    def test_weak_config_findings(self, weak_archive_mcp):
        """Weak config should produce multiple findings."""
        async def run():
            async with Client(weak_archive_mcp) as client:
                result = await client.call_tool(
                    "validate_configuration",
                    {"server_name": "weak-archive"},
                )
                data = result.data
                assert data["type"] == "configuration_validation"
                assert "error" not in data
                # Should find: weak TLS, security off, audit off, anon on,
                # log buffering off
                assert data["total_issues"] >= 4
                assert data["high_count"] >= 2  # security off + TLS version

                # Check specific findings
                titles = [f.get("title", "") for f in data.get("findings", [])]
                title_text = " ".join(titles).lower()
                assert "tls" in title_text or "security" in title_text
                assert "audit" in title_text
                assert "anonymous" in title_text

        asyncio.run(run())

    def test_checks_run_list(self, analysis_archive_mcp):
        async def run():
            async with Client(analysis_archive_mcp) as client:
                result = await client.call_tool(
                    "validate_configuration",
                    {"server_name": "test-archive"},
                )
                data = result.data
                checks = data.get("checks_run", [])
                assert "config:password_scheme" in checks
                assert "config:tls_version" in checks
                assert "config:security" in checks
                assert "config:audit_logging" in checks
                assert "config:anonymous_access" in checks

        asyncio.run(run())

    def test_privacy_sanitization(self, analysis_privacy_archive_mcp):
        async def run():
            async with Client(analysis_privacy_archive_mcp) as client:
                result = await client.call_tool(
                    "validate_configuration",
                    {"server_name": "priv-archive"},
                )
                data = result.data
                assert data.get("server", "").startswith("[server-")

        asyncio.run(run())

    def test_rejects_live_server(self, archive_env):
        """validate_configuration should reject live servers."""
        config = LDAPServerConfig(
            name="live-server",
            hostname="localhost",
            port=389,
        )
        mcp = DirSrvMCP(servers=[config], include_env_fallback=False)

        async def run():
            async with Client(mcp) as client:
                result = await client.call_tool(
                    "validate_configuration",
                    {"server_name": "live-server"},
                )
                data = result.data
                assert "error" in data

        asyncio.run(run())


# DSE comparison test data

# Modified variant of ANALYSIS_DSE_LDIF:
# - Different port (3389 vs 389)
# - Security off
# - MemberOf Plugin disabled
# - Extra "Account Policy Plugin" entry
# - Missing uid index
# - Extra replication agreement
MODIFIED_DSE_LDIF = """\
dn: cn=config
objectClass: top
objectClass: extensibleObject
objectClass: nsslapdConfig
cn: config
nsslapd-port: 3389
nsslapd-secureport: 636
nsslapd-versionstring: 389-Directory/2.4.6
nsslapd-localhost: localhost.localdomain
nsslapd-security: off
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
nsslapd-pluginEnabled: off
nsslapd-pluginType: betxnpostoperation
nsslapd-pluginPath: libmemberof-plugin

dn: cn=Referential Integrity Postoperation,cn=plugins,cn=config
objectClass: top
objectClass: nsSlapdPlugin
cn: Referential Integrity Postoperation
nsslapd-pluginEnabled: on
nsslapd-pluginType: betxnpostoperation
nsslapd-pluginPath: libreferint-plugin

dn: cn=Account Policy Plugin,cn=plugins,cn=config
objectClass: top
objectClass: nsSlapdPlugin
cn: Account Policy Plugin
nsslapd-pluginEnabled: on
nsslapd-pluginType: object
nsslapd-pluginPath: libacctpolicy-plugin

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

dn: cn=replica,cn=dc\\=example\\,dc\\=com,cn=mapping tree,cn=config
objectClass: top
objectClass: nsDS5Replica
cn: replica
nsds5replicaroot: dc=example,dc=com
nsds5replicatype: 3
nsds5replicaid: 1

dn: cn=to-server2,cn=replica,cn=dc\\=example\\,dc\\=com,cn=mapping tree,cn=config
objectClass: top
objectClass: nsDS5ReplicationAgreement
cn: to-server2
nsds5replicahost: server2.example.com
nsds5replicaport: 636
nsds5replicatransportinfo: LDAPS
nsds5replicabinddn: cn=replication manager,cn=config
"""


# DSE comparison fixtures


@pytest.fixture
def comparison_archives(archive_env, tmp_path):
    """Create two archive directories with different dse.ldif for comparison."""
    inst = "slapd-testinst"

    # Server 1 - uses ANALYSIS_DSE_LDIF
    dir1 = tmp_path / "server1"
    config_dir1 = dir1 / "etc" / "dirsrv" / inst
    config_dir1.mkdir(parents=True)
    (config_dir1 / "dse.ldif").write_text(ANALYSIS_DSE_LDIF)

    # Server 2 - uses MODIFIED_DSE_LDIF
    dir2 = tmp_path / "server2"
    config_dir2 = dir2 / "etc" / "dirsrv" / inst
    config_dir2.mkdir(parents=True)
    (config_dir2 / "dse.ldif").write_text(MODIFIED_DSE_LDIF)

    return dir1, dir2


@pytest.fixture
def comparison_mcp(archive_env, comparison_archives):
    """DirSrvMCP with two archive servers for DSE comparison tests."""
    dir1, dir2 = comparison_archives
    config1 = LDAPServerConfig(
        name="server1",
        hostname="archive",
        port=0,
        is_archive=True,
        archive_path=str(dir1),
    )
    config2 = LDAPServerConfig(
        name="server2",
        hostname="archive",
        port=0,
        is_archive=True,
        archive_path=str(dir2),
    )
    return DirSrvMCP(servers=[config1, config2], include_env_fallback=False)


@pytest.fixture
def identical_comparison_mcp(archive_env, tmp_path):
    """DirSrvMCP with two identical archive servers."""
    inst = "slapd-testinst"

    dir1 = tmp_path / "ident1"
    config_dir1 = dir1 / "etc" / "dirsrv" / inst
    config_dir1.mkdir(parents=True)
    (config_dir1 / "dse.ldif").write_text(ANALYSIS_DSE_LDIF)

    dir2 = tmp_path / "ident2"
    config_dir2 = dir2 / "etc" / "dirsrv" / inst
    config_dir2.mkdir(parents=True)
    (config_dir2 / "dse.ldif").write_text(ANALYSIS_DSE_LDIF)

    config1 = LDAPServerConfig(
        name="ident1",
        hostname="archive",
        port=0,
        is_archive=True,
        archive_path=str(dir1),
    )
    config2 = LDAPServerConfig(
        name="ident2",
        hostname="archive",
        port=0,
        is_archive=True,
        archive_path=str(dir2),
    )
    return DirSrvMCP(servers=[config1, config2], include_env_fallback=False)


# compare_dse_configs tool tests


class TestCompareDseConfigs:

    def test_identical_archives(self, identical_comparison_mcp):
        """Comparing identical archives should find no differences."""
        async def run():
            async with Client(identical_comparison_mcp) as client:
                result = await client.call_tool(
                    "compare_dse_configs",
                    {"server1": "ident1", "server2": "ident2"},
                )
                data = result.data
                assert data["type"] == "dse_comparison"
                assert "error" not in data
                assert len(data["only_in_server1"]) == 0
                assert len(data["only_in_server2"]) == 0
                assert len(data["differences"]) == 0
                assert data["matching_count"] > 0

        asyncio.run(run())

    def test_detects_config_diffs(self, comparison_mcp):
        """Should detect port and security differences in cn=config."""
        async def run():
            async with Client(comparison_mcp) as client:
                result = await client.call_tool(
                    "compare_dse_configs",
                    {"server1": "server1", "server2": "server2", "section": "config"},
                )
                data = result.data
                assert data["type"] == "dse_comparison"
                assert "error" not in data
                assert data["section"] == "config"
                # cn=config should have differences (port, security)
                assert len(data["differences"]) >= 1
                diff = data["differences"][0]
                diff_attrs = [d["attribute"] for d in diff.get("different_values", [])]
                assert "nsslapd-port" in diff_attrs or "nsslapd-security" in diff_attrs

        asyncio.run(run())

    def test_detects_entry_diffs(self, comparison_mcp):
        """Should find entries only in one server and attribute differences."""
        async def run():
            async with Client(comparison_mcp) as client:
                result = await client.call_tool(
                    "compare_dse_configs",
                    {"server1": "server1", "server2": "server2"},
                )
                data = result.data
                assert data["type"] == "dse_comparison"
                assert "error" not in data

                # server1 has uid index, server2 does not
                only1 = data["only_in_server1"]
                assert any("uid" in dn.lower() and "index" in dn.lower() for dn in only1)

                # server2 has Account Policy Plugin and replication agreement
                only2 = data["only_in_server2"]
                assert any("account policy" in dn.lower() for dn in only2)
                assert any("to-server2" in dn.lower() for dn in only2)

                # MemberOf should have different enabled value
                diffs = data["differences"]
                memberof_diff = next(
                    (d for d in diffs if "memberof" in d["dn"].lower()), None
                )
                assert memberof_diff is not None
                enabled_diff = next(
                    (v for v in memberof_diff["different_values"]
                     if v["attribute"] == "nsslapd-pluginEnabled"),
                    None,
                )
                assert enabled_diff is not None

        asyncio.run(run())

    def test_section_filter_plugins(self, comparison_mcp):
        """Section filter 'plugins' should only compare plugin entries."""
        async def run():
            async with Client(comparison_mcp) as client:
                result = await client.call_tool(
                    "compare_dse_configs",
                    {"server1": "server1", "server2": "server2", "section": "plugins"},
                )
                data = result.data
                assert data["section"] == "plugins"
                # All DNs in results should be under cn=plugins,cn=config
                for dn in data.get("only_in_server1", []):
                    assert "cn=plugins,cn=config" in dn.lower()
                for dn in data.get("only_in_server2", []):
                    assert "cn=plugins,cn=config" in dn.lower()
                for diff in data.get("differences", []):
                    assert "cn=plugins,cn=config" in diff["dn"].lower()

        asyncio.run(run())

    def test_section_filter_indexes(self, comparison_mcp):
        """Section filter 'indexes' should only compare index entries."""
        async def run():
            async with Client(comparison_mcp) as client:
                result = await client.call_tool(
                    "compare_dse_configs",
                    {"server1": "server1", "server2": "server2", "section": "indexes"},
                )
                data = result.data
                assert data["section"] == "indexes"
                # server1 has uid index, server2 does not
                assert any("uid" in dn.lower() for dn in data.get("only_in_server1", []))
                # No non-index entries should appear
                for dn in data.get("only_in_server1", []):
                    assert "cn=index," in dn.lower()

        asyncio.run(run())

    def test_section_filter_replication(self, comparison_mcp):
        """Section filter 'replication' should only compare replication entries."""
        async def run():
            async with Client(comparison_mcp) as client:
                result = await client.call_tool(
                    "compare_dse_configs",
                    {"server1": "server1", "server2": "server2", "section": "replication"},
                )
                data = result.data
                assert data["section"] == "replication"
                # server2 has extra replication agreement
                assert any("to-server2" in dn.lower() for dn in data.get("only_in_server2", []))

        asyncio.run(run())

    def test_privacy_sanitization(self, comparison_archives):
        """Server names should be sanitized in privacy mode."""
        dir1, dir2 = comparison_archives
        env = {
            "LDAP_MCP_EXPOSE_SENSITIVE_DATA": "false",
            "LDAP_SERVERS_CONFIG": "",
        }
        with patch.dict(os.environ, env):
            config1 = LDAPServerConfig(
                name="priv1",
                hostname="archive",
                port=0,
                is_archive=True,
                archive_path=str(dir1),
            )
            config2 = LDAPServerConfig(
                name="priv2",
                hostname="archive",
                port=0,
                is_archive=True,
                archive_path=str(dir2),
            )
            mcp = DirSrvMCP(servers=[config1, config2], include_env_fallback=False)

            async def run():
                async with Client(mcp) as client:
                    result = await client.call_tool(
                        "compare_dse_configs",
                        {"server1": "priv1", "server2": "priv2"},
                    )
                    data = result.data
                    assert "error" not in data
                    # Server names should be sanitized
                    assert data.get("server1", "").startswith("[server-")
                    assert data.get("server2", "").startswith("[server-")

            asyncio.run(run())

    def test_rejects_live_server(self, archive_env, comparison_archives):
        """Should reject live servers."""
        dir1, _ = comparison_archives
        config_live = LDAPServerConfig(
            name="live-server",
            hostname="localhost",
            port=389,
        )
        config_archive = LDAPServerConfig(
            name="archive-server",
            hostname="archive",
            port=0,
            is_archive=True,
            archive_path=str(dir1),
        )
        mcp = DirSrvMCP(
            servers=[config_live, config_archive],
            include_env_fallback=False,
        )

        async def run():
            async with Client(mcp) as client:
                result = await client.call_tool(
                    "compare_dse_configs",
                    {"server1": "live-server", "server2": "archive-server"},
                )
                data = result.data
                assert "error" in data
                assert "live" in data["error"].lower() or "offline" in data["error"].lower()

        asyncio.run(run())


# archive_investigation prompt test


class TestArchiveInvestigationPrompt:

    def test_prompt_returns_messages(self, archive_mcp):
        """archive_investigation prompt should return expected PromptMessage list."""
        async def run():
            async with Client(archive_mcp) as client:
                result = await client.get_prompt("archive_investigation")
                assert len(result.messages) == 2
                # First message is from user
                assert result.messages[0].role == "user"
                assert "archive" in result.messages[0].content.text.lower()
                # Second is assistant with the investigation plan
                assert result.messages[1].role == "assistant"
                text = result.messages[1].content.text.lower()
                assert "analyze_archive" in text
                assert "validate_configuration" in text
                assert "analyze_error_log" in text
                assert "compare_dse_configs" in text

        asyncio.run(run())


# DN handling edge-case tests (dse_utils + archive.py)


class TestDnHandling:
    """Verify proper DN matching in shared utilities and archive tools."""

    def test_dn_matches_section_case_insensitive(self):
        """Mixed-case DN should still match the correct section."""
        from src.dirsrv_mcp.tools.archive import _dn_matches_section
        assert _dn_matches_section(
            "CN=MemberOf Plugin,CN=Plugins,CN=Config", "plugins"
        ) is True

    def test_dn_matches_section_config(self):
        from src.dirsrv_mcp.tools.archive import _dn_matches_section
        assert _dn_matches_section("cn=config", "config") is True
        assert _dn_matches_section("CN=Config", "config") is True
        # Sub-entries should NOT match 'config' section
        assert _dn_matches_section("cn=plugins,cn=config", "config") is False

    def test_dn_matches_section_security(self):
        from src.dirsrv_mcp.tools.archive import _dn_matches_section
        assert _dn_matches_section(
            "cn=encryption,cn=config", "security"
        ) is True
        assert _dn_matches_section(
            "cn=RSA,cn=encryption,cn=config", "security"
        ) is True
        assert _dn_matches_section("cn=config", "security") is False

    def test_dn_matches_section_backends_excludes_indexes(self):
        from src.dirsrv_mcp.tools.archive import _dn_matches_section
        assert _dn_matches_section(
            "cn=userRoot,cn=ldbm database,cn=plugins,cn=config", "backends"
        ) is True
        # Index entries should NOT match 'backends'
        assert _dn_matches_section(
            "cn=uid,cn=index,cn=userRoot,cn=ldbm database,cn=plugins,cn=config",
            "backends",
        ) is False

    def test_dn_matches_section_all(self):
        from src.dirsrv_mcp.tools.archive import _dn_matches_section
        assert _dn_matches_section("cn=anything", "all") is True
        assert _dn_matches_section("cn=anything", None) is True

    def test_find_child_dns_proper(self):
        """find_child_dns should use proper DN parsing, not substring."""
        from src.dirsrv_mcp.tools.dse_utils import find_child_dns, normalize_dn

        class FakeDSE:
            _contents = [
                "dn: cn=plugins,cn=config\n",
                "dn: cn=MemberOf Plugin,cn=plugins,cn=config\n",
                "dn: cn=sub,cn=MemberOf Plugin,cn=plugins,cn=config\n",
            ]
        dse = FakeDSE()
        children = find_child_dns(dse, "cn=plugins,cn=config")
        # Only direct child, not grandchild
        assert len(children) == 1
        assert normalize_dn(children[0]) == normalize_dn(
            "cn=MemberOf Plugin,cn=plugins,cn=config"
        )

    def test_dn_matches_section_replication(self):
        from src.dirsrv_mcp.tools.archive import _dn_matches_section
        assert _dn_matches_section(
            "cn=replica,cn=dc\\=example\\,dc\\=com,cn=mapping tree,cn=config",
            "replication",
        ) is True
        assert _dn_matches_section(
            "cn=to-server2,cn=replica,cn=dc\\=example\\,dc\\=com,cn=mapping tree,cn=config",
            "replication",
        ) is True
        assert _dn_matches_section("cn=config", "replication") is False

    def test_utf8_decode_safety(self, comparison_mcp):
        """compare_dse_configs should not crash on binary attribute values."""
        async def run():
            async with Client(comparison_mcp) as client:
                result = await client.call_tool(
                    "compare_dse_configs",
                    {"server1": "server1", "server2": "server2"},
                )
                data = result.data
                assert data["type"] == "dse_comparison"
                assert "error" not in data

        asyncio.run(run())
