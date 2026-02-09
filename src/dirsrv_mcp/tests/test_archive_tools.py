"""Tests for archive mode tool functionality.

Tests verify that config, index, and health tools work correctly
with archive (SOS report) data sources, reading from dse.ldif
instead of live LDAP connections.
"""

from __future__ import annotations

import asyncio
import os
from unittest.mock import patch

import pytest
from fastmcp import Client

from src.dirsrv_mcp.server import DirSrvMCP
from src.ldap_assistant_mcp.server import LDAPServerConfig


# ============================================================================
# Rich dse.ldif for tool testing
# ============================================================================

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


# ============================================================================
# Fixtures
# ============================================================================


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


# ============================================================================
# Config tool tests
# ============================================================================


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


# ============================================================================
# Index tool tests
# ============================================================================


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


# ============================================================================
# Health tool tests
# ============================================================================


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


# ============================================================================
# Replication tool tests (guard verification)
# ============================================================================


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


# ============================================================================
# Cross-mode comparison tests
# ============================================================================


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
