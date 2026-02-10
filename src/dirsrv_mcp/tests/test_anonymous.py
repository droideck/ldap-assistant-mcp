"""Tests for anonymous LDAP connection support."""

from __future__ import annotations

import os
from unittest.mock import MagicMock, patch

import ldap
import pytest
from fastmcp import Client

from src.dirsrv_mcp.connection import ConnectionManager, ServerConfig
from src.dirsrv_mcp.server import DirSrvMCP
from src.ldap_assistant_mcp.server import LDAPAuthMethod, LDAPServerConfig

pytestmark = pytest.mark.asyncio


# Unit tests for LDAPAuthMethod enum


def test_anonymous_auth_method_exists():
    """Test that ANONYMOUS is a valid auth method."""
    assert LDAPAuthMethod.ANONYMOUS.value == "anonymous"


def test_anonymous_auth_method_from_string():
    """Test that anonymous auth method can be created from string."""
    method = LDAPAuthMethod("anonymous")
    assert method == LDAPAuthMethod.ANONYMOUS


# Unit tests for ServerConfig with auth_method


def test_server_config_has_auth_method():
    """Test that ServerConfig includes auth_method field."""
    config = ServerConfig(
        name="test",
        ldap_url="ldap://localhost:389",
        base_dn="dc=test,dc=com",
        bind_dn="",
        bind_password="",
        auth_method="anonymous",
    )
    assert config.auth_method == "anonymous"


def test_server_config_default_auth_method():
    """Test that ServerConfig defaults to simple auth."""
    config = ServerConfig(
        name="test",
        ldap_url="ldap://localhost:389",
        base_dn="dc=test,dc=com",
        bind_dn="cn=admin",
        bind_password="secret",
    )
    assert config.auth_method == "simple"


# Unit tests for LDAPServerConfig.from_env with anonymous


def test_ldap_server_config_from_env_anonymous():
    """Test that from_env() handles LDAP_AUTH_METHOD=anonymous correctly."""
    env_vars = {
        "LDAP_URL": "ldap://localhost:389",
        "LDAP_BASE_DN": "dc=test,dc=com",
        "LDAP_AUTH_METHOD": "anonymous",
    }
    with patch.dict(os.environ, env_vars, clear=False):
        config = LDAPServerConfig.from_env()

    assert config.auth_method == LDAPAuthMethod.ANONYMOUS
    assert config.bind_dn is None
    assert config.bind_password is None


def test_ldap_server_config_from_env_simple():
    """Test that from_env() handles simple auth with defaults."""
    # Clear all LDAP_ vars and set only what we need to test defaults
    env_vars = {
        "LDAP_URL": "ldap://localhost:389",
        "LDAP_BASE_DN": "dc=test,dc=com",
        "LDAP_AUTH_METHOD": "simple",
    }
    # Remove any existing LDAP_ env vars that might interfere
    clean_env = {k: v for k, v in os.environ.items() if not k.startswith("LDAP_")}
    clean_env.update(env_vars)

    with patch.dict(os.environ, clean_env, clear=True):
        config = LDAPServerConfig.from_env()

    assert config.auth_method == LDAPAuthMethod.SIMPLE
    assert config.bind_dn == "cn=Directory Manager"
    assert config.bind_password == "Password123"


# Unit tests for ConnectionManager with anonymous


def test_connection_manager_preserves_auth_method():
    """Test that ConnectionManager preserves auth_method from LDAPServerConfig."""
    manager = ConnectionManager()
    ldap_config = LDAPServerConfig(
        name="anon-server",
        hostname="localhost",
        port=389,
        auth_method=LDAPAuthMethod.ANONYMOUS,
    )
    manager.add_server(ldap_config)

    config = manager.get_config("anon-server")
    assert config.auth_method == "anonymous"
    assert config.bind_dn == ""
    assert config.bind_password == ""


def test_connection_manager_preserves_simple_auth():
    """Test that ConnectionManager preserves simple auth credentials."""
    manager = ConnectionManager()
    ldap_config = LDAPServerConfig(
        name="auth-server",
        hostname="localhost",
        port=389,
        bind_dn="cn=admin",
        bind_password="secret",
        auth_method=LDAPAuthMethod.SIMPLE,
    )
    manager.add_server(ldap_config)

    config = manager.get_config("auth-server")
    assert config.auth_method == "simple"
    assert config.bind_dn == "cn=admin"
    assert config.bind_password == "secret"


# Unit tests for anonymous access denied error handling


def test_anonymous_access_denied_inappropriate_auth():
    """Test that INAPPROPRIATE_AUTH is handled with clear error message."""
    manager = ConnectionManager()
    manager.add_server(
        ServerConfig(
            name="test-server",
            ldap_url="ldap://localhost:389",
            base_dn="dc=test,dc=com",
            bind_dn="",
            bind_password="",
            auth_method="anonymous",
        )
    )

    # Mock DirSrv to raise INAPPROPRIATE_AUTH on open()
    with patch("src.dirsrv_mcp.connection.DirSrv") as mock_dirsrv:
        mock_ds = MagicMock()
        mock_ds.open.side_effect = ldap.INAPPROPRIATE_AUTH(
            {"desc": "Anonymous access not allowed"}
        )
        mock_dirsrv.return_value = mock_ds

        with pytest.raises(ConnectionError) as exc_info:
            manager.connect("test-server")

        error_msg = str(exc_info.value)
        assert "Anonymous access denied" in error_msg
        assert "nsslapd-allow-anonymous-access" in error_msg


def test_anonymous_access_denied_unwilling_to_perform():
    """Test that UNWILLING_TO_PERFORM is handled with clear error message."""
    manager = ConnectionManager()
    manager.add_server(
        ServerConfig(
            name="test-server",
            ldap_url="ldap://localhost:389",
            base_dn="dc=test,dc=com",
            bind_dn="",
            bind_password="",
            auth_method="anonymous",
        )
    )

    # Mock DirSrv to raise UNWILLING_TO_PERFORM on open()
    with patch("src.dirsrv_mcp.connection.DirSrv") as mock_dirsrv:
        mock_ds = MagicMock()
        mock_ds.open.side_effect = ldap.UNWILLING_TO_PERFORM(
            {"desc": "Server unwilling to perform"}
        )
        mock_dirsrv.return_value = mock_ds

        with pytest.raises(ConnectionError) as exc_info:
            manager.connect("test-server")

        error_msg = str(exc_info.value)
        assert "refused anonymous bind" in error_msg
        assert "rootdse only" in error_msg


def test_simple_auth_inappropriate_auth_not_caught():
    """Test that INAPPROPRIATE_AUTH is re-raised for non-anonymous auth."""
    manager = ConnectionManager()
    manager.add_server(
        ServerConfig(
            name="test-server",
            ldap_url="ldap://localhost:389",
            base_dn="dc=test,dc=com",
            bind_dn="cn=admin",
            bind_password="wrong",
            auth_method="simple",
        )
    )

    # Mock DirSrv to raise INAPPROPRIATE_AUTH on open()
    with patch("src.dirsrv_mcp.connection.DirSrv") as mock_dirsrv:
        mock_ds = MagicMock()
        mock_ds.open.side_effect = ldap.INAPPROPRIATE_AUTH(
            {"desc": "Invalid credentials"}
        )
        mock_dirsrv.return_value = mock_ds

        # Should re-raise the original exception, not wrap it
        with pytest.raises(ldap.INAPPROPRIATE_AUTH):
            manager.connect("test-server")


# Integration tests (require running 389 DS with anonymous access enabled)


async def test_anonymous_ldap_search_base_dn(dirsrv_anonymous_server):
    """Test that ldap_search works with anonymous bind on base DN."""
    async with Client(dirsrv_anonymous_server) as client:
        result = await client.call_tool(
            "ldap_search",
            {
                "base_dn": "dc=test,dc=com",
                "scope": "BASE",
                "filter": "(objectClass=*)",
                "limit": 1,
            },
        )
        data = result.data

        assert data["type"] == "ldap_search"
        # Should get at least the base entry
        assert data["total_returned"] >= 1


async def test_anonymous_root_dse_access(dirsrv_anonymous_server):
    """Test that anonymous can access Root DSE.

    Note: lib389's search_s may return empty results for root DSE with certain
    attribute filters. We use '*' to get operational attributes.
    """
    async with Client(dirsrv_anonymous_server) as client:
        result = await client.call_tool(
            "ldap_search",
            {
                "base_dn": "",
                "scope": "BASE",
                "filter": "(objectClass=*)",
                "attributes": "*",
                "limit": 1,
            },
        )
        data = result.data

        # Root DSE search should succeed (may return 0 or 1 depending on lib389)
        assert data["type"] == "ldap_search"
        # If results returned, verify structure
        if data["total_returned"] > 0:
            root_dse = data["items"][0]
            assert "dn" in root_dse


async def test_anonymous_user_search(dirsrv_anonymous_server, expected_test_users):
    """Test that anonymous can search for users (if ACIs allow)."""
    async with Client(dirsrv_anonymous_server) as client:
        result = await client.call_tool(
            "ldap_search",
            {
                "base_dn": "ou=people,dc=test,dc=com",
                "scope": "SUBTREE",
                "filter": "(objectClass=inetOrgPerson)",
                "attributes": "uid,cn",
                "limit": 50,
            },
        )
        data = result.data

        assert data["type"] == "ldap_search"
        # Default 389 DS allows anonymous read access
        assert data["total_returned"] >= 1

        # Verify we can find test users
        found_uids = []
        for item in data["items"]:
            if "uid" in item.get("attrs", {}):
                uid_values = item["attrs"]["uid"]
                if isinstance(uid_values, list):
                    found_uids.extend(uid_values)
                else:
                    found_uids.append(uid_values)

        # At least some test users should be found
        for expected_user in expected_test_users[:2]:  # Check first 2
            assert expected_user in found_uids, f"Expected user {expected_user} not found"


async def test_anonymous_subtree_search(dirsrv_anonymous_server):
    """Test anonymous subtree search from base DN."""
    async with Client(dirsrv_anonymous_server) as client:
        result = await client.call_tool(
            "ldap_search",
            {
                "base_dn": "dc=test,dc=com",
                "scope": "SUBTREE",
                "filter": "(objectClass=organizationalUnit)",
                "attributes": "ou",
                "limit": 10,
            },
        )
        data = result.data

        assert data["type"] == "ldap_search"
        # Should find organizational units (people, groups, etc.)
        assert data["total_returned"] >= 1
