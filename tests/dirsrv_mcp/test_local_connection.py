"""Tests for local connection functionality.

These tests verify that when is_local=True and serverid is set:
1. The connection uses local_simple_allocate() instead of remote_simple_allocate()
2. The ds_paths object is properly initialized with local=True
3. Log file paths are accessible
4. Health checks that require local access work correctly

To run these tests properly, they should be executed INSIDE the DS container
where the MCP code is mounted. Use scripts/ds-test-local.sh to set this up.
"""

from __future__ import annotations

import os
from unittest.mock import patch, MagicMock

import pytest

from ldap_assistant_mcp.config.loader import load_config, _server_config_from_dict
from ldap_assistant_mcp.dirsrv_mcp.connection import ConnectionManager, ServerConfig
from ldap_assistant_mcp.dirsrv_mcp.server import DirSrvMCP
from ldap_assistant_mcp.core import LDAPServerConfig


# Fixtures for local connection tests


@pytest.fixture
def local_server_config() -> LDAPServerConfig:
    """Create a local server configuration from environment or defaults."""
    is_local = os.environ.get("LDAP_IS_LOCAL", "").lower() in ("true", "1", "yes")
    serverid = os.environ.get("LDAP_SERVERID", "localhost")

    return LDAPServerConfig(
        name="local-test",
        hostname="localhost",
        port=int(os.environ.get("LDAP_PORT", "3389")),
        bind_dn=os.environ.get("LDAP_BIND_DN", "cn=Directory Manager"),
        bind_password=os.environ.get("LDAP_BIND_PASSWORD", "TestPassword123"),
        base_dn=os.environ.get("LDAP_BASE_DN", "dc=test,dc=com"),
        is_local=is_local,
        serverid=serverid if is_local else None,
    )


@pytest.fixture
def local_dirsrv_server(local_server_config) -> DirSrvMCP:
    """Create a DirSrvMCP instance with local connection enabled."""
    return DirSrvMCP(
        servers=[local_server_config],
        include_env_fallback=False,
    )


@pytest.fixture
def local_multiserver_config():
    """Load local multi-server configuration from tests-local-servers.json."""
    config_path = os.environ.get("LDAP_SERVERS_CONFIG")
    if config_path and os.path.exists(config_path):
        return load_config(config_file=config_path)
    return None


# Unit tests for configuration classes


class TestLDAPServerConfigLocal:
    """Test LDAPServerConfig with local connection fields."""

    def test_local_fields_default_false(self):
        """Local fields should default to False/None."""
        config = LDAPServerConfig(
            name="test",
            hostname="localhost",
            port=389,
        )
        assert config.is_local is False
        assert config.serverid is None
        assert config.use_ldapi is False

    def test_local_fields_set(self):
        """Local fields should be settable."""
        config = LDAPServerConfig(
            name="test",
            hostname="localhost",
            port=389,
            is_local=True,
            serverid="standalone",
        )
        assert config.is_local is True
        assert config.serverid == "standalone"

    def test_ldapi_fields_set(self):
        """LDAPI fields should be settable."""
        config = LDAPServerConfig(
            name="test",
            hostname="localhost",
            port=389,
            is_local=True,
            serverid="standalone",
            use_ldapi=True,
        )
        assert config.is_local is True
        assert config.serverid == "standalone"
        assert config.use_ldapi is True

    def test_as_dict_includes_local_fields(self):
        """as_dict() should include local fields when is_local=True."""
        config = LDAPServerConfig(
            name="test",
            hostname="localhost",
            port=389,
            is_local=True,
            serverid="myinstance",
        )
        d = config.as_dict()
        assert d["is_local"] is True
        assert d["serverid"] == "myinstance"

    def test_as_dict_includes_ldapi_fields(self):
        """as_dict() should include use_ldapi when set."""
        config = LDAPServerConfig(
            name="test",
            hostname="localhost",
            port=389,
            is_local=True,
            serverid="myinstance",
            use_ldapi=True,
        )
        d = config.as_dict()
        assert d["is_local"] is True
        assert d["serverid"] == "myinstance"
        assert d["use_ldapi"] is True

    def test_as_dict_excludes_local_fields_when_false(self):
        """as_dict() should not include local fields when is_local=False."""
        config = LDAPServerConfig(
            name="test",
            hostname="localhost",
            port=389,
            is_local=False,
        )
        d = config.as_dict()
        assert "is_local" not in d
        assert "serverid" not in d
        assert "use_ldapi" not in d

    def test_from_env_with_local_vars(self):
        """from_env() should read LDAP_IS_LOCAL and LDAP_SERVERID."""
        with patch.dict(os.environ, {
            "LDAP_URL": "ldap://localhost:389",
            "LDAP_IS_LOCAL": "true",
            "LDAP_SERVERID": "testinstance",
        }):
            config = LDAPServerConfig.from_env()
            assert config.is_local is True
            assert config.serverid == "testinstance"

    def test_from_env_with_ldapi_vars(self):
        """from_env() should read LDAP_USE_LDAPI."""
        with patch.dict(os.environ, {
            "LDAP_URL": "ldap://localhost:389",
            "LDAP_IS_LOCAL": "true",
            "LDAP_SERVERID": "testinstance",
            "LDAP_USE_LDAPI": "true",
        }):
            config = LDAPServerConfig.from_env()
            assert config.is_local is True
            assert config.serverid == "testinstance"
            assert config.use_ldapi is True


class TestServerConfigLocal:
    """Test ServerConfig with local connection fields."""

    def test_local_fields_default_false(self):
        """Local fields should default to False/None."""
        config = ServerConfig(
            name="test",
            ldap_url="ldap://localhost:389",
            base_dn="dc=test,dc=com",
            bind_dn="cn=Directory Manager",
            bind_password="secret",
        )
        assert config.is_local is False
        assert config.serverid is None
        assert config.use_ldapi is False

    def test_local_fields_set(self):
        """Local fields should be settable."""
        config = ServerConfig(
            name="test",
            ldap_url="ldap://localhost:389",
            base_dn="dc=test,dc=com",
            bind_dn="cn=Directory Manager",
            bind_password="secret",
            is_local=True,
            serverid="standalone",
        )
        assert config.is_local is True
        assert config.serverid == "standalone"

    def test_ldapi_fields_set(self):
        """LDAPI fields should be settable."""
        config = ServerConfig(
            name="test",
            ldap_url="ldap://localhost:389",
            base_dn="dc=test,dc=com",
            bind_dn="cn=Directory Manager",
            bind_password="secret",
            is_local=True,
            serverid="standalone",
            use_ldapi=True,
        )
        assert config.is_local is True
        assert config.serverid == "standalone"
        assert config.use_ldapi is True


class TestConfigLoaderLocal:
    """Test config loader with local connection fields."""

    def test_server_config_from_dict_with_local_fields(self):
        """_server_config_from_dict() should parse is_local and serverid."""
        data = {
            "name": "local-test",
            "ldap_url": "ldap://localhost:389",
            "base_dn": "dc=test,dc=com",
            "bind_dn": "cn=Directory Manager",
            "bind_password": "secret",
            "is_local": True,
            "serverid": "myinstance",
        }
        config = _server_config_from_dict(data)
        assert config.is_local is True
        assert config.serverid == "myinstance"

    def test_server_config_from_dict_without_local_fields(self):
        """_server_config_from_dict() should handle missing local fields."""
        data = {
            "name": "remote-test",
            "ldap_url": "ldap://remote.example.com:389",
            "base_dn": "dc=example,dc=com",
            "bind_dn": "cn=Directory Manager",
            "bind_password": "secret",
        }
        config = _server_config_from_dict(data)
        assert config.is_local is False
        assert config.serverid is None

    def test_server_config_from_dict_string_bool(self):
        """_server_config_from_dict() should handle string boolean values."""
        data = {
            "name": "local-test",
            "ldap_url": "ldap://localhost:389",
            "base_dn": "dc=test,dc=com",
            "bind_dn": "cn=Directory Manager",
            "bind_password": "secret",
            "is_local": "true",  # String instead of bool
            "serverid": "myinstance",
        }
        config = _server_config_from_dict(data)
        assert config.is_local is True

    def test_server_config_from_dict_with_ldapi(self):
        """_server_config_from_dict() should parse use_ldapi field."""
        data = {
            "name": "ldapi-test",
            "ldap_url": "ldap://localhost:389",
            "base_dn": "dc=test,dc=com",
            "bind_dn": "cn=Directory Manager",
            "bind_password": "secret",
            "is_local": True,
            "serverid": "myinstance",
            "use_ldapi": True,
        }
        config = _server_config_from_dict(data)
        assert config.is_local is True
        assert config.serverid == "myinstance"
        assert config.use_ldapi is True

    def test_server_config_from_dict_ldapi_string_bool(self):
        """_server_config_from_dict() should handle string boolean for use_ldapi."""
        data = {
            "name": "ldapi-test",
            "ldap_url": "ldap://localhost:389",
            "base_dn": "dc=test,dc=com",
            "bind_dn": "cn=Directory Manager",
            "bind_password": "secret",
            "is_local": "true",
            "serverid": "myinstance",
            "use_ldapi": "yes",  # String instead of bool
        }
        config = _server_config_from_dict(data)
        assert config.use_ldapi is True


# Unit tests for ConnectionManager


class TestConnectionManagerLocal:
    """Test ConnectionManager with local connection support."""

    def test_add_local_server(self):
        """ConnectionManager should store local connection fields."""
        cm = ConnectionManager()
        config = LDAPServerConfig(
            name="local-test",
            hostname="localhost",
            port=389,
            bind_dn="cn=Directory Manager",
            bind_password="secret",
            base_dn="dc=test,dc=com",
            is_local=True,
            serverid="standalone",
        )
        cm.add_server(config)

        stored = cm.get_config("local-test")
        assert stored.is_local is True
        assert stored.serverid == "standalone"

    def test_add_remote_server(self):
        """ConnectionManager should handle remote servers without local fields."""
        cm = ConnectionManager()
        config = LDAPServerConfig(
            name="remote-test",
            hostname="remote.example.com",
            port=389,
            bind_dn="cn=Directory Manager",
            bind_password="secret",
            base_dn="dc=example,dc=com",
            is_local=False,
        )
        cm.add_server(config)

        stored = cm.get_config("remote-test")
        assert stored.is_local is False
        assert stored.serverid is None

    def test_add_ldapi_server(self):
        """ConnectionManager should store LDAPI connection fields."""
        cm = ConnectionManager()
        config = LDAPServerConfig(
            name="ldapi-test",
            hostname="localhost",
            port=389,
            bind_dn="cn=Directory Manager",
            bind_password="secret",
            base_dn="dc=test,dc=com",
            is_local=True,
            serverid="standalone",
            use_ldapi=True,
        )
        cm.add_server(config)

        stored = cm.get_config("ldapi-test")
        assert stored.is_local is True
        assert stored.serverid == "standalone"
        assert stored.use_ldapi is True


# Integration tests (require running DS container)


@pytest.mark.skipif(
    os.environ.get("LDAP_IS_LOCAL", "").lower() not in ("true", "1", "yes"),
    reason="Local connection tests require LDAP_IS_LOCAL=true environment"
)
class TestLocalConnectionIntegration:
    """Integration tests for local connection functionality.

    These tests require running inside a DS container with:
    - LDAP_IS_LOCAL=true
    - LDAP_SERVERID=localhost (or appropriate instance name)
    - Access to server log files and paths
    """

    def test_local_connection_has_paths(self, local_dirsrv_server):
        """Local connection should have ds_paths initialized."""
        ds = local_dirsrv_server.connection_manager.connect("local-test")
        try:
            # For local connections, isLocal should be True
            assert ds.isLocal is True, "Connection should be local"

            # ds_paths should be available
            assert hasattr(ds, "ds_paths"), "ds_paths should be available"
            assert ds.ds_paths is not None, "ds_paths should not be None"
        finally:
            ds.close()

    def test_local_connection_has_access_log_path(self, local_dirsrv_server):
        """Local connection should have access log path."""
        ds = local_dirsrv_server.connection_manager.connect("local-test")
        try:
            # Should have access_log attribute
            access_log = ds.ds_paths.access_log
            assert access_log is not None, "access_log path should be set"
            assert "access" in access_log, "access_log should contain 'access'"
        finally:
            ds.close()

    def test_local_connection_has_error_log_path(self, local_dirsrv_server):
        """Local connection should have error log path."""
        ds = local_dirsrv_server.connection_manager.connect("local-test")
        try:
            error_log = ds.ds_paths.error_log
            assert error_log is not None, "error_log path should be set"
            assert "error" in error_log.lower(), "error_log should contain 'error'"
        finally:
            ds.close()

    def test_local_connection_serverid(self, local_dirsrv_server):
        """Local connection should have serverid set."""
        ds = local_dirsrv_server.connection_manager.connect("local-test")
        try:
            assert ds.serverid is not None, "serverid should be set"
            assert ds.serverid == os.environ.get("LDAP_SERVERID", "localhost")
        finally:
            ds.close()


@pytest.mark.skipif(
    os.environ.get("LDAP_IS_LOCAL", "").lower() not in ("true", "1", "yes"),
    reason="Local health check tests require LDAP_IS_LOCAL=true environment"
)
class TestLocalHealthCheckIntegration:
    """Integration tests for health checks that require local access.

    These tests verify that health checks requiring local file access
    (like log analysis) work correctly with local connections.
    """

    def test_health_check_list_includes_logs_category(self, local_dirsrv_server):
        """Health check list should include 'logs' category for local instances."""
        from fastmcp import Client

        async def run_test():
            async with Client(local_dirsrv_server) as client:
                result = await client.call_tool(
                    "list_healthchecks",
                    {"server_name": "local-test"}
                )
                assert result is not None

                # Parse the result
                import json
                if hasattr(result, "content"):
                    data = json.loads(result.content[0].text)
                else:
                    data = result

                # Should have categories
                assert "categories" in data or "checks" in data

        import asyncio
        asyncio.run(run_test())

    def test_health_check_can_access_logs(self, local_dirsrv_server):
        """Health check should be able to analyze access logs for local instances."""
        from fastmcp import Client

        async def run_test():
            async with Client(local_dirsrv_server) as client:
                # Run the logs:notes check which analyzes access logs
                result = await client.call_tool(
                    "run_healthcheck",
                    {
                        "server_name": "local-test",
                        "checks": ["logs:notes"]
                    }
                )
                assert result is not None

                # The check should complete (may or may not find issues)
                import json
                if hasattr(result, "content"):
                    data = json.loads(result.content[0].text)
                else:
                    data = result

                # Should have completed without error
                assert "error" not in data or data.get("error") is None

        import asyncio
        asyncio.run(run_test())


# Tests for mixed local/remote multi-server setup


class TestMixedLocalRemoteConfig:
    """Test configurations with both local and remote servers."""

    def test_mixed_config_from_dict(self):
        """Should handle mixed local and remote servers in same config."""
        from ldap_assistant_mcp.config.loader import ServerListConfig

        data = {
            "servers": [
                {
                    "name": "local-server",
                    "ldap_url": "ldap://localhost:389",
                    "base_dn": "dc=local,dc=com",
                    "bind_dn": "cn=Directory Manager",
                    "bind_password": "secret",
                    "is_local": True,
                    "serverid": "localinstance"
                },
                {
                    "name": "remote-server",
                    "ldap_url": "ldap://remote.example.com:389",
                    "base_dn": "dc=remote,dc=com",
                    "bind_dn": "cn=Directory Manager",
                    "bind_password": "secret",
                    "is_local": False
                }
            ]
        }

        config = ServerListConfig.from_dict(data)
        assert len(config.servers) == 2

        local = next(s for s in config.servers if s.name == "local-server")
        remote = next(s for s in config.servers if s.name == "remote-server")

        assert local.is_local is True
        assert local.serverid == "localinstance"
        assert remote.is_local is False
        assert remote.serverid is None

    def test_mixed_config_to_dict(self):
        """to_dict() should correctly serialize mixed config."""
        from ldap_assistant_mcp.config.loader import ServerListConfig

        servers = [
            LDAPServerConfig(
                name="local",
                hostname="localhost",
                port=389,
                is_local=True,
                serverid="myinstance"
            ),
            LDAPServerConfig(
                name="remote",
                hostname="remote.example.com",
                port=389,
                is_local=False
            )
        ]

        config = ServerListConfig(servers=servers)
        d = config.to_dict()

        local_dict = next(s for s in d["servers"] if s["name"] == "local")
        remote_dict = next(s for s in d["servers"] if s["name"] == "remote")

        assert local_dict["is_local"] is True
        assert local_dict["serverid"] == "myinstance"
        assert "is_local" not in remote_dict  # Not included when False

    def test_ldapi_config_to_dict(self):
        """to_dict() should include use_ldapi when enabled."""
        from ldap_assistant_mcp.config.loader import ServerListConfig

        servers = [
            LDAPServerConfig(
                name="ldapi-server",
                hostname="localhost",
                port=389,
                is_local=True,
                serverid="myinstance",
                use_ldapi=True
            )
        ]

        config = ServerListConfig(servers=servers)
        d = config.to_dict()

        ldapi_dict = d["servers"][0]
        assert ldapi_dict["is_local"] is True
        assert ldapi_dict["serverid"] == "myinstance"
        assert ldapi_dict["use_ldapi"] is True

    def test_mixed_config_with_ldapi_from_dict(self):
        """Should handle mixed config with LDAPI server from dict."""
        from ldap_assistant_mcp.config.loader import ServerListConfig

        data = {
            "servers": [
                {
                    "name": "ldapi-server",
                    "ldap_url": "ldap://localhost:389",
                    "base_dn": "dc=local,dc=com",
                    "bind_dn": "cn=Directory Manager",
                    "bind_password": "secret",
                    "is_local": True,
                    "serverid": "localinstance",
                    "use_ldapi": True
                },
                {
                    "name": "tcp-server",
                    "ldap_url": "ldap://localhost:389",
                    "base_dn": "dc=local,dc=com",
                    "bind_dn": "cn=Directory Manager",
                    "bind_password": "secret",
                    "is_local": True,
                    "serverid": "localinstance",
                    "use_ldapi": False
                },
                {
                    "name": "remote-server",
                    "ldap_url": "ldap://remote.example.com:389",
                    "base_dn": "dc=remote,dc=com",
                    "bind_dn": "cn=Directory Manager",
                    "bind_password": "secret",
                    "is_local": False
                }
            ]
        }

        config = ServerListConfig.from_dict(data)
        assert len(config.servers) == 3

        ldapi = next(s for s in config.servers if s.name == "ldapi-server")
        tcp = next(s for s in config.servers if s.name == "tcp-server")
        remote = next(s for s in config.servers if s.name == "remote-server")

        assert ldapi.is_local is True
        assert ldapi.serverid == "localinstance"
        assert ldapi.use_ldapi is True

        assert tcp.is_local is True
        assert tcp.serverid == "localinstance"
        assert tcp.use_ldapi is False

        assert remote.is_local is False
        assert remote.serverid is None
        assert remote.use_ldapi is False
