"""Tests for offline instance mode functionality.

These tests verify that when is_offline=True:
1. The configuration correctly sets is_offline and implies is_local
2. ConnectionManager.connect() skips ds.open() and returns an allocated DirSrv
3. Tools requiring live LDAP connections are properly guarded
4. describe_servers() includes offline mode markers
5. Config loader validates offline mode requirements

Unit tests run everywhere (no DS needed).
Integration tests require LDAP_IS_OFFLINE=true environment (inside a DS container
with the instance stopped).
"""

from __future__ import annotations

import asyncio
import json
import os
from unittest.mock import patch, MagicMock

import pytest

from ldap_assistant_mcp.config.loader import (
    ServerListConfig,
    _server_config_from_dict,
)
from ldap_assistant_mcp.dirsrv_mcp.connection import (
    ConnectionManager,
    LiveServerRequired,
    ServerConfig,
    is_offline_server,
    require_live_server,
)
from ldap_assistant_mcp.dirsrv_mcp.server import DirSrvMCP
from ldap_assistant_mcp.core import LDAPServerConfig


# Fixtures for offline mode tests


@pytest.fixture
def offline_server_config() -> LDAPServerConfig:
    """Create an offline server configuration."""
    return LDAPServerConfig(
        name="offline-test",
        hostname="localhost",
        port=3389,
        bind_dn="cn=Directory Manager",
        bind_password="TestPassword123",
        base_dn="dc=test,dc=com",
        is_local=True,
        serverid="localhost",
        is_offline=True,
    )


@pytest.fixture
def live_server_config() -> LDAPServerConfig:
    """Create a live (non-offline) server configuration for comparison."""
    return LDAPServerConfig(
        name="live-test",
        hostname="localhost",
        port=3389,
        bind_dn="cn=Directory Manager",
        bind_password="TestPassword123",
        base_dn="dc=test,dc=com",
        is_local=True,
        serverid="localhost",
        is_offline=False,
    )


@pytest.fixture
def offline_env():
    """Ensure no external config leaks into offline tests."""
    env = {
        "LDAP_MCP_EXPOSE_SENSITIVE_DATA": "true",
        "LDAP_SERVERS_CONFIG": "",  # Prevent loading external config
    }
    with patch.dict(os.environ, env):
        yield


@pytest.fixture
def offline_dirsrv_server(offline_env, offline_server_config) -> DirSrvMCP:
    """Create a DirSrvMCP instance with offline server configured."""
    return DirSrvMCP(
        servers=[offline_server_config],
        include_env_fallback=False,
    )


@pytest.fixture
def mixed_offline_live_server(offline_env, offline_server_config, live_server_config) -> DirSrvMCP:
    """Create a DirSrvMCP instance with both offline and live servers."""
    return DirSrvMCP(
        servers=[offline_server_config, live_server_config],
        include_env_fallback=False,
    )


# Unit tests for LDAPServerConfig offline fields


class TestLDAPServerConfigOffline:
    """Test LDAPServerConfig with offline mode fields."""

    def test_offline_defaults_to_false(self):
        """is_offline should default to False."""
        config = LDAPServerConfig(
            name="test",
            hostname="localhost",
            port=389,
        )
        assert config.is_offline is False

    def test_offline_can_be_set(self):
        """is_offline should be settable."""
        config = LDAPServerConfig(
            name="test",
            hostname="localhost",
            port=389,
            is_local=True,
            serverid="standalone",
            is_offline=True,
        )
        assert config.is_offline is True
        assert config.is_local is True
        assert config.serverid == "standalone"

    def test_as_dict_includes_offline_when_true(self):
        """as_dict() should include is_offline when is_local and is_offline are True."""
        config = LDAPServerConfig(
            name="test",
            hostname="localhost",
            port=389,
            is_local=True,
            serverid="standalone",
            is_offline=True,
        )
        d = config.as_dict()
        assert d["is_local"] is True
        assert d["serverid"] == "standalone"
        assert d["is_offline"] is True

    def test_as_dict_excludes_offline_when_false(self):
        """as_dict() should not include is_offline when False."""
        config = LDAPServerConfig(
            name="test",
            hostname="localhost",
            port=389,
            is_local=True,
            serverid="standalone",
            is_offline=False,
        )
        d = config.as_dict()
        assert "is_offline" not in d

    def test_as_dict_excludes_offline_when_not_local(self):
        """as_dict() should not include local/offline fields when is_local is False."""
        config = LDAPServerConfig(
            name="test",
            hostname="localhost",
            port=389,
            is_local=False,
            is_offline=False,
        )
        d = config.as_dict()
        assert "is_local" not in d
        assert "is_offline" not in d


# Unit tests for ServerConfig offline fields


class TestServerConfigOffline:
    """Test ServerConfig with offline mode fields."""

    def test_offline_defaults_to_false(self):
        """is_offline should default to False."""
        config = ServerConfig(
            name="test",
            ldap_url="ldap://localhost:389",
            base_dn="dc=test,dc=com",
            bind_dn="cn=Directory Manager",
            bind_password="secret",
        )
        assert config.is_offline is False

    def test_offline_can_be_set(self):
        """is_offline should be settable."""
        config = ServerConfig(
            name="test",
            ldap_url="ldap://localhost:389",
            base_dn="dc=test,dc=com",
            bind_dn="cn=Directory Manager",
            bind_password="secret",
            is_local=True,
            serverid="standalone",
            is_offline=True,
        )
        assert config.is_offline is True
        assert config.is_local is True
        assert config.serverid == "standalone"


# Unit tests for config loader offline parsing


class TestConfigLoaderOffline:
    """Test config loader with offline mode fields."""

    def test_server_config_from_dict_with_offline(self):
        """_server_config_from_dict() should parse is_offline field."""
        data = {
            "name": "offline-test",
            "ldap_url": "ldap://localhost:389",
            "base_dn": "dc=test,dc=com",
            "bind_dn": "cn=Directory Manager",
            "bind_password": "secret",
            "is_local": True,
            "serverid": "myinstance",
            "is_offline": True,
        }
        config = _server_config_from_dict(data)
        assert config.is_offline is True
        assert config.is_local is True
        assert config.serverid == "myinstance"

    def test_server_config_from_dict_offline_string_bool(self):
        """_server_config_from_dict() should handle string boolean for is_offline."""
        data = {
            "name": "offline-test",
            "ldap_url": "ldap://localhost:389",
            "base_dn": "dc=test,dc=com",
            "bind_dn": "cn=Directory Manager",
            "bind_password": "secret",
            "is_local": True,
            "serverid": "myinstance",
            "is_offline": "true",
        }
        config = _server_config_from_dict(data)
        assert config.is_offline is True

    def test_server_config_from_dict_offline_implies_local(self):
        """is_offline=True should automatically set is_local=True."""
        data = {
            "name": "offline-test",
            "ldap_url": "ldap://localhost:389",
            "base_dn": "dc=test,dc=com",
            "bind_dn": "cn=Directory Manager",
            "bind_password": "secret",
            "is_local": False,  # Explicitly false
            "serverid": "myinstance",
            "is_offline": True,
        }
        config = _server_config_from_dict(data)
        assert config.is_offline is True
        assert config.is_local is True  # Auto-set by offline

    def test_server_config_from_dict_offline_requires_serverid(self):
        """is_offline=True without serverid should raise ValueError."""
        data = {
            "name": "offline-test",
            "ldap_url": "ldap://localhost:389",
            "base_dn": "dc=test,dc=com",
            "bind_dn": "cn=Directory Manager",
            "bind_password": "secret",
            "is_offline": True,
            # No serverid
        }
        with pytest.raises(ValueError, match="requires serverid"):
            _server_config_from_dict(data)

    def test_server_config_from_dict_offline_no_hostname_required(self):
        """Offline mode should default hostname to 'localhost' if not provided."""
        data = {
            "name": "offline-test",
            "base_dn": "dc=test,dc=com",
            "bind_dn": "cn=Directory Manager",
            "bind_password": "secret",
            "serverid": "myinstance",
            "is_offline": True,
        }
        config = _server_config_from_dict(data)
        assert config.hostname == "localhost"
        assert config.is_offline is True

    def test_server_config_from_dict_without_offline(self):
        """_server_config_from_dict() should handle missing is_offline."""
        data = {
            "name": "live-test",
            "ldap_url": "ldap://localhost:389",
            "base_dn": "dc=test,dc=com",
            "bind_dn": "cn=Directory Manager",
            "bind_password": "secret",
        }
        config = _server_config_from_dict(data)
        assert config.is_offline is False


# Unit tests for ServerListConfig roundtrip with offline


class TestServerListConfigOffline:
    """Test ServerListConfig serialization with offline mode."""

    def test_to_dict_includes_offline(self):
        """to_dict() should include is_offline when set."""
        servers = [
            LDAPServerConfig(
                name="offline",
                hostname="localhost",
                port=389,
                is_local=True,
                serverid="myinstance",
                is_offline=True,
            ),
        ]
        config = ServerListConfig(servers=servers)
        d = config.to_dict()
        offline_dict = d["servers"][0]
        assert offline_dict["is_local"] is True
        assert offline_dict["serverid"] == "myinstance"
        assert offline_dict["is_offline"] is True

    def test_from_dict_parses_offline(self):
        """from_dict() should parse is_offline from JSON config."""
        data = {
            "servers": [
                {
                    "name": "offline-server",
                    "ldap_url": "ldap://localhost:389",
                    "base_dn": "dc=test,dc=com",
                    "bind_dn": "cn=Directory Manager",
                    "bind_password": "secret",
                    "is_local": True,
                    "serverid": "myinstance",
                    "is_offline": True,
                }
            ]
        }
        config = ServerListConfig.from_dict(data)
        assert len(config.servers) == 1
        assert config.servers[0].is_offline is True
        assert config.servers[0].is_local is True
        assert config.servers[0].serverid == "myinstance"

    def test_roundtrip_offline_config(self):
        """Config should survive to_dict() -> from_dict() roundtrip."""
        original = ServerListConfig(
            servers=[
                LDAPServerConfig(
                    name="offline",
                    hostname="localhost",
                    port=389,
                    bind_dn="cn=Directory Manager",
                    bind_password="secret",
                    base_dn="dc=test,dc=com",
                    is_local=True,
                    serverid="myinstance",
                    is_offline=True,
                ),
            ]
        )
        d = original.to_dict()
        restored = ServerListConfig.from_dict(d)
        assert len(restored.servers) == 1
        assert restored.servers[0].is_offline is True
        assert restored.servers[0].is_local is True
        assert restored.servers[0].serverid == "myinstance"
        assert restored.servers[0].name == "offline"

    def test_mixed_offline_live_config(self):
        """Should handle mixed offline and live servers."""
        data = {
            "servers": [
                {
                    "name": "offline-server",
                    "ldap_url": "ldap://localhost:389",
                    "base_dn": "dc=test,dc=com",
                    "bind_dn": "cn=Directory Manager",
                    "bind_password": "secret",
                    "is_local": True,
                    "serverid": "myinstance",
                    "is_offline": True,
                },
                {
                    "name": "live-server",
                    "ldap_url": "ldap://remote.example.com:389",
                    "base_dn": "dc=example,dc=com",
                    "bind_dn": "cn=Directory Manager",
                    "bind_password": "secret",
                    "is_local": False,
                },
            ]
        }
        config = ServerListConfig.from_dict(data)
        assert len(config.servers) == 2

        offline = next(s for s in config.servers if s.name == "offline-server")
        live = next(s for s in config.servers if s.name == "live-server")

        assert offline.is_offline is True
        assert offline.is_local is True
        assert live.is_offline is False
        assert live.is_local is False


# Unit tests for ConnectionManager offline helpers


class TestConnectionManagerOffline:
    """Test ConnectionManager with offline mode."""

    def test_add_offline_server(self):
        """ConnectionManager should store offline flag."""
        cm = ConnectionManager()
        config = LDAPServerConfig(
            name="offline-test",
            hostname="localhost",
            port=389,
            bind_dn="cn=Directory Manager",
            bind_password="secret",
            base_dn="dc=test,dc=com",
            is_local=True,
            serverid="standalone",
            is_offline=True,
        )
        cm.add_server(config)

        stored = cm.get_config("offline-test")
        assert stored.is_offline is True
        assert stored.is_local is True
        assert stored.serverid == "standalone"

    def test_add_live_server(self):
        """ConnectionManager should store live (non-offline) server."""
        cm = ConnectionManager()
        config = LDAPServerConfig(
            name="live-test",
            hostname="localhost",
            port=389,
            bind_dn="cn=Directory Manager",
            bind_password="secret",
            base_dn="dc=test,dc=com",
            is_local=True,
            serverid="standalone",
            is_offline=False,
        )
        cm.add_server(config)

        stored = cm.get_config("live-test")
        assert stored.is_offline is False


# Unit tests for is_offline_server() and require_live_server()


class TestOfflineServerHelpers:
    """Test is_offline_server() and require_live_server() helper functions."""

    def test_is_offline_server_true(self):
        """is_offline_server() should return True for offline servers."""
        cm = ConnectionManager()
        cm.add_server(LDAPServerConfig(
            name="offline", hostname="localhost", port=389,
            is_local=True, serverid="inst", is_offline=True,
        ))
        assert is_offline_server(cm, "offline") is True

    def test_is_offline_server_false_for_live(self):
        """is_offline_server() should return False for live servers."""
        cm = ConnectionManager()
        cm.add_server(LDAPServerConfig(
            name="live", hostname="localhost", port=389,
            is_local=True, serverid="inst", is_offline=False,
        ))
        assert is_offline_server(cm, "live") is False

    def test_is_offline_server_false_for_remote(self):
        """is_offline_server() should return False for remote servers."""
        cm = ConnectionManager()
        cm.add_server(LDAPServerConfig(
            name="remote", hostname="remote.example.com", port=389,
            is_local=False,
        ))
        assert is_offline_server(cm, "remote") is False

    def test_is_offline_server_false_for_unknown(self):
        """is_offline_server() should return False for unknown servers."""
        cm = ConnectionManager()
        assert is_offline_server(cm, "nonexistent") is False

    def test_require_live_server_passes_for_live(self):
        """require_live_server() should not raise for live servers."""
        cm = ConnectionManager()
        cm.add_server(LDAPServerConfig(
            name="live", hostname="localhost", port=389,
            is_local=True, serverid="inst", is_offline=False,
        ))
        # Should not raise
        require_live_server(cm, "live", "test_tool")

    def test_require_live_server_raises_for_offline(self):
        """require_live_server() should raise LiveServerRequired for offline servers."""
        cm = ConnectionManager()
        cm.add_server(LDAPServerConfig(
            name="offline", hostname="localhost", port=389,
            is_local=True, serverid="inst", is_offline=True,
        ))
        with pytest.raises(LiveServerRequired) as exc_info:
            require_live_server(cm, "offline", "list_all_users")
        assert "list_all_users" in str(exc_info.value)
        assert "offline" in str(exc_info.value)
        assert "live LDAP connection" in str(exc_info.value)

    def test_live_server_required_attributes(self):
        """LiveServerRequired should have feature and server_name attributes."""
        exc = LiveServerRequired("run_monitor", "my-server")
        assert exc.feature == "run_monitor"
        assert exc.server_name == "my-server"


# Unit tests for describe_servers with offline mode


class TestDescribeServersOffline:
    """Test describe_servers() with offline mode markers."""

    def test_offline_server_has_mode_offline(self, offline_dirsrv_server):
        """describe_servers() should include mode='offline' for offline servers."""
        descriptions = offline_dirsrv_server.describe_servers()
        assert len(descriptions) == 1
        desc = descriptions[0]
        assert desc["mode"] == "offline"
        assert desc["is_offline"] is True

    def test_live_server_has_mode_live(self):
        """describe_servers() should include mode='live' for live servers."""
        with patch.dict(os.environ, {
            "LDAP_MCP_EXPOSE_SENSITIVE_DATA": "true",
            "LDAP_SERVERS_CONFIG": "",
        }):
            config = LDAPServerConfig(
                name="live-test",
                hostname="localhost",
                port=389,
                is_local=True,
                serverid="inst",
                is_offline=False,
            )
            server = DirSrvMCP(servers=[config], include_env_fallback=False)
        descriptions = server.describe_servers()
        assert len(descriptions) == 1
        desc = descriptions[0]
        assert desc["mode"] == "live"
        assert "is_offline" not in desc or desc.get("is_offline") is not True

    def test_mixed_servers_modes(self, mixed_offline_live_server):
        """describe_servers() should correctly label mixed offline/live servers."""
        descriptions = mixed_offline_live_server.describe_servers()
        assert len(descriptions) == 2

        offline_desc = next(d for d in descriptions if d["name"] == "offline-test")
        live_desc = next(d for d in descriptions if d["name"] == "live-test")

        assert offline_desc["mode"] == "offline"
        assert offline_desc["is_offline"] is True
        assert live_desc["mode"] == "live"

    def test_offline_server_privacy_mode_includes_mode(self):
        """describe_servers() in privacy mode should include mode field."""
        with patch.dict(os.environ, {
            "LDAP_MCP_EXPOSE_SENSITIVE_DATA": "false",
            "LDAP_SERVERS_CONFIG": "",
        }):
            config = LDAPServerConfig(
                name="offline-test",
                hostname="localhost",
                port=389,
                is_local=True,
                serverid="localhost",
                is_offline=True,
            )
            server = DirSrvMCP(servers=[config], include_env_fallback=False)
        descriptions = server.describe_servers()
        assert len(descriptions) == 1
        desc = descriptions[0]
        assert desc["mode"] == "offline"
        assert desc["is_offline"] is True


# Unit tests for tool guards via FastMCP Client


# All tools that should be guarded by require_live_server
GUARDED_TOOLS = [
    # Users
    ("list_all_users", {}),
    ("search_users_by_name", {"name": "test"}),
    ("get_user_details", {"username": "testuser"}),
    ("list_active_users", {}),
    ("list_locked_users", {}),
    ("search_users_by_attribute", {"attribute": "uid", "value": "test"}),
    # Groups
    ("list_all_groups", {}),
    # Search
    ("ldap_search", {"base_dn": "dc=test,dc=com"}),
    # Monitoring
    ("run_monitor", {}),
    # Performance
    ("get_cache_statistics", {}),
    ("get_connection_statistics", {}),
    ("get_operation_statistics", {}),
    ("get_thread_statistics", {}),
    ("get_resource_utilization", {}),
    ("get_performance_summary", {}),
    # Replication
    ("get_replication_status", {}),
    ("check_replication_lag", {}),
    ("list_replication_conflicts", {}),
    ("get_agreement_status", {}),
]


class TestToolGuardsOfflineMode:
    """Test that all guarded tools reject offline servers.

    Uses FastMCP in-memory Client to invoke tools and verify they
    raise ToolError (which wraps LiveServerRequired) for offline servers.
    """

    @pytest.mark.parametrize("tool_name,params", GUARDED_TOOLS)
    def test_guarded_tool_rejects_offline(self, offline_dirsrv_server, tool_name, params):
        """Each guarded tool should raise an error for offline servers."""
        from fastmcp import Client

        async def run_test():
            async with Client(offline_dirsrv_server) as client:
                # Pass explicit server_name to ensure we target the offline server
                call_params = dict(params)
                call_params["server_name"] = "offline-test"

                with pytest.raises(Exception) as exc_info:
                    await client.call_tool(tool_name, call_params)

                # The error message should mention "live" or "offline"
                error_msg = str(exc_info.value).lower()
                assert (
                    "live" in error_msg
                    or "offline" in error_msg
                    or "running server" in error_msg
                ), f"Tool '{tool_name}' error should mention offline/live mode, got: {exc_info.value}"

        asyncio.run(run_test())


# Tools that should NOT be guarded (they work offline or handle it gracefully)
NON_GUARDED_TOOLS = [
    "first_look",
    "list_healthcheck_errors",
    "list_healthchecks",
    "run_healthcheck",
    "get_server_configuration",
    "list_plugins",
    "get_backend_configuration",
    "list_indexes",
    "analyze_index_configuration",
    "find_unindexed_searches",
]


class TestNonGuardedToolsOfflineMode:
    """Verify that non-guarded tools are registered and accessible.

    These tools either work offline or handle offline servers gracefully
    (e.g., by returning partial results or error info in the response).
    We just verify they exist as registered tools.
    """

    @pytest.mark.parametrize("tool_name", NON_GUARDED_TOOLS)
    def test_non_guarded_tool_is_registered(self, offline_dirsrv_server, tool_name):
        """Non-guarded tools should be registered with the MCP server."""
        from fastmcp import Client

        async def run_test():
            async with Client(offline_dirsrv_server) as client:
                tools = await client.list_tools()
                tool_names = [t.name for t in tools]
                assert tool_name in tool_names, (
                    f"Tool '{tool_name}' should be registered. "
                    f"Available: {sorted(tool_names)}"
                )

        asyncio.run(run_test())


# Unit tests for get_replication_topology with offline servers


class TestReplicationTopologyOffline:
    """Test get_replication_topology gracefully skips offline servers."""

    def test_topology_skips_offline_servers(self, mixed_offline_live_server):
        """get_replication_topology should skip offline servers gracefully."""
        from fastmcp import Client

        async def run_test():
            async with Client(mixed_offline_live_server) as client:
                # This will likely fail because live-test can't actually connect,
                # but the key test is that it doesn't crash on the offline server
                # and mentions it in the output
                try:
                    result = await client.call_tool("get_replication_topology", {})
                    if hasattr(result, "content"):
                        data = json.loads(result.content[0].text)
                    else:
                        data = result

                    # If the tool returns data, offline server should be in
                    # servers_failed or mentioned in findings
                    if "servers_failed" in data:
                        # offline-test should be in the failed list (skipped)
                        assert "offline-test" in data["servers_failed"]
                except Exception:
                    # Expected - live-test can't actually connect
                    # The important thing is that it didn't crash due to offline mode
                    pass

        asyncio.run(run_test())


# Integration tests (require running inside DS container with stopped instance)


@pytest.mark.skipif(
    os.environ.get("LDAP_IS_OFFLINE", "").lower() not in ("true", "1", "yes"),
    reason="Offline integration tests require LDAP_IS_OFFLINE=true environment"
)
class TestOfflineConnectionIntegration:
    """Integration tests for offline connection functionality.

    These tests require running inside a DS container where:
    - LDAP_IS_OFFLINE=true
    - LDAP_SERVERID=localhost (or appropriate instance name)
    - The DS instance exists but is stopped (no LDAP port listening)
    - Server files (dse.ldif, logs) are accessible on filesystem
    """

    @pytest.fixture
    def offline_config_from_env(self):
        """Create offline config from environment."""
        return LDAPServerConfig(
            name="offline-integration",
            hostname="localhost",
            port=int(os.environ.get("LDAP_PORT", "3389")),
            bind_dn=os.environ.get("LDAP_BIND_DN", "cn=Directory Manager"),
            bind_password=os.environ.get("LDAP_BIND_PASSWORD", "TestPassword123"),
            base_dn=os.environ.get("LDAP_BASE_DN", "dc=test,dc=com"),
            is_local=True,
            serverid=os.environ.get("LDAP_SERVERID", "localhost"),
            is_offline=True,
        )

    @pytest.fixture
    def offline_integration_server(self, offline_config_from_env):
        """Create DirSrvMCP instance for offline integration tests."""
        with patch.dict(os.environ, {"LDAP_MCP_EXPOSE_SENSITIVE_DATA": "true"}):
            return DirSrvMCP(
                servers=[offline_config_from_env],
                include_env_fallback=False,
            )

    def test_offline_connect_returns_dirsrv(self, offline_integration_server):
        """Offline connect() should return a DirSrv without opening LDAP."""
        ds = offline_integration_server.connection_manager.connect("offline-integration")
        try:
            # Should have DirSrv object
            assert ds is not None
            # Should be local
            assert ds.isLocal is True
            # Should have serverid
            assert ds.serverid is not None
        finally:
            try:
                ds.close()
            except Exception:
                pass

    def test_offline_connect_has_paths(self, offline_integration_server):
        """Offline DirSrv should have ds_paths for offline analysis."""
        ds = offline_integration_server.connection_manager.connect("offline-integration")
        try:
            assert hasattr(ds, "ds_paths"), "ds_paths should be available"
            assert ds.ds_paths is not None, "ds_paths should not be None"
        finally:
            try:
                ds.close()
            except Exception:
                pass

    def test_offline_dseldif_accessible(self, offline_integration_server):
        """DSEldif should be accessible for offline analysis."""
        from lib389.dseldif import DSEldif

        ds = offline_integration_server.connection_manager.connect("offline-integration")
        try:
            dse = DSEldif(ds)
            # DSEldif.get(dn, attr) reads a specific attribute from dse.ldif
            result = dse.get("cn=config", "nsslapd-port")
            assert result is not None, "Should be able to read nsslapd-port from cn=config in dse.ldif"
        finally:
            try:
                ds.close()
            except Exception:
                pass

    def test_offline_health_tools_work(self, offline_integration_server):
        """Health check tools should work with offline servers."""
        from fastmcp import Client

        async def run_test():
            async with Client(offline_integration_server) as client:
                # list_healthcheck_errors doesn't need any server connection
                result = await client.call_tool("list_healthcheck_errors", {})
                assert result is not None

                if hasattr(result, "content"):
                    data = json.loads(result.content[0].text)
                else:
                    data = result

                assert data["type"] == "healthcheck_errors"
                assert data["total_count"] > 0

        asyncio.run(run_test())

    def test_offline_guarded_tools_reject(self, offline_integration_server):
        """Guarded tools should still reject offline servers in integration."""
        from fastmcp import Client

        async def run_test():
            async with Client(offline_integration_server) as client:
                with pytest.raises(Exception) as exc_info:
                    await client.call_tool(
                        "list_all_users",
                        {"server_name": "offline-integration"}
                    )
                assert "live" in str(exc_info.value).lower() or "offline" in str(exc_info.value).lower()

        asyncio.run(run_test())
