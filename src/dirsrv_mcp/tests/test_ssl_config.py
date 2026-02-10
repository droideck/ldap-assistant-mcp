"""Tests for LDAP vs LDAPS (SSL/TLS) configuration support.

These tests verify that:
1. use_ssl field works correctly in LDAPServerConfig
2. ldaps:// URLs are parsed correctly
3. Port defaults are correct (389 for LDAP, 636 for LDAPS)
4. Environment variables for SSL work correctly
5. Config loader handles SSL fields properly
"""

from __future__ import annotations

import os
from unittest.mock import patch

import pytest

from src.config.loader import _server_config_from_dict, ServerListConfig
from src.dirsrv_mcp.connection import ConnectionManager, ServerConfig
from src.ldap_assistant_mcp.server import LDAPServerConfig


# Unit tests for LDAPServerConfig SSL support


class TestLDAPServerConfigSSL:
    """Test LDAPServerConfig with SSL/TLS fields."""

    def test_use_ssl_default_false(self):
        """use_ssl should default to False."""
        config = LDAPServerConfig(
            name="test",
            hostname="localhost",
            port=389,
        )
        assert config.use_ssl is False

    def test_use_ssl_explicit_true(self):
        """use_ssl can be explicitly set to True."""
        config = LDAPServerConfig(
            name="test",
            hostname="localhost",
            port=636,
            use_ssl=True,
        )
        assert config.use_ssl is True
        assert config.port == 636

    def test_ldap_url_property_without_ssl(self):
        """ldap_url property should return ldap:// when use_ssl=False."""
        config = LDAPServerConfig(
            name="test",
            hostname="ldap.example.com",
            port=389,
            use_ssl=False,
        )
        assert config.ldap_url == "ldap://ldap.example.com:389"

    def test_ldap_url_property_with_ssl(self):
        """ldap_url property should return ldaps:// when use_ssl=True."""
        config = LDAPServerConfig(
            name="test",
            hostname="ldap.example.com",
            port=636,
            use_ssl=True,
        )
        assert config.ldap_url == "ldaps://ldap.example.com:636"

    def test_as_dict_includes_use_ssl(self):
        """as_dict() should include use_ssl field."""
        config = LDAPServerConfig(
            name="test",
            hostname="localhost",
            port=636,
            use_ssl=True,
        )
        d = config.as_dict()
        assert d["use_ssl"] is True

    def test_as_dict_includes_use_ssl_false(self):
        """as_dict() should include use_ssl=False."""
        config = LDAPServerConfig(
            name="test",
            hostname="localhost",
            port=389,
            use_ssl=False,
        )
        d = config.as_dict()
        assert d["use_ssl"] is False

    def test_from_env_with_ldaps_url(self):
        """from_env() should detect SSL from ldaps:// URL."""
        with patch.dict(os.environ, {
            "LDAP_URL": "ldaps://secure.example.com:636",
        }, clear=True):
            config = LDAPServerConfig.from_env()
            assert config.use_ssl is True
            assert config.hostname == "secure.example.com"
            assert config.port == 636

    def test_from_env_with_ldap_url(self):
        """from_env() should not enable SSL for ldap:// URL."""
        with patch.dict(os.environ, {
            "LDAP_URL": "ldap://plain.example.com:389",
        }, clear=True):
            config = LDAPServerConfig.from_env()
            assert config.use_ssl is False
            assert config.hostname == "plain.example.com"
            assert config.port == 389

    def test_from_env_with_ldaps_url_default_port(self):
        """from_env() should default to port 636 for ldaps:// URL without port."""
        with patch.dict(os.environ, {
            "LDAP_URL": "ldaps://secure.example.com",
        }, clear=True):
            config = LDAPServerConfig.from_env()
            assert config.use_ssl is True
            assert config.port == 636

    def test_from_env_with_ldap_url_default_port(self):
        """from_env() should default to port 389 for ldap:// URL without port."""
        with patch.dict(os.environ, {
            "LDAP_URL": "ldap://plain.example.com",
        }, clear=True):
            config = LDAPServerConfig.from_env()
            assert config.use_ssl is False
            assert config.port == 389

    def test_from_env_with_use_ssl_env_var(self):
        """from_env() should read LDAP_USE_SSL environment variable."""
        with patch.dict(os.environ, {
            "LDAP_HOSTNAME": "localhost",
            "LDAP_USE_SSL": "true",
        }, clear=True):
            config = LDAPServerConfig.from_env()
            assert config.use_ssl is True
            assert config.port == 636  # Default SSL port

    def test_from_env_with_use_ssl_false(self):
        """from_env() should handle LDAP_USE_SSL=false."""
        with patch.dict(os.environ, {
            "LDAP_HOSTNAME": "localhost",
            "LDAP_USE_SSL": "false",
        }, clear=True):
            config = LDAPServerConfig.from_env()
            assert config.use_ssl is False
            assert config.port == 389

    def test_from_env_with_custom_ssl_port(self):
        """from_env() should allow custom port with SSL."""
        with patch.dict(os.environ, {
            "LDAP_HOSTNAME": "localhost",
            "LDAP_PORT": "6360",
            "LDAP_USE_SSL": "true",
        }, clear=True):
            config = LDAPServerConfig.from_env()
            assert config.use_ssl is True
            assert config.port == 6360

    def test_copy_with_use_ssl(self):
        """copy_with() should allow changing use_ssl."""
        config = LDAPServerConfig(
            name="test",
            hostname="localhost",
            port=389,
            use_ssl=False,
        )
        updated = config.copy_with(use_ssl=True, port=636)
        assert updated.use_ssl is True
        assert updated.port == 636
        # Original unchanged
        assert config.use_ssl is False


# Unit tests for ServerConfig SSL support


class TestServerConfigSSL:
    """Test ServerConfig (connection.py) with SSL support."""

    def test_server_config_ldaps_url(self):
        """ServerConfig should accept ldaps:// URL."""
        config = ServerConfig(
            name="test",
            ldap_url="ldaps://secure.example.com:636",
            base_dn="dc=test,dc=com",
            bind_dn="cn=Directory Manager",
            bind_password="secret",
        )
        assert config.ldap_url == "ldaps://secure.example.com:636"

    def test_server_config_ldap_url(self):
        """ServerConfig should accept ldap:// URL."""
        config = ServerConfig(
            name="test",
            ldap_url="ldap://plain.example.com:389",
            base_dn="dc=test,dc=com",
            bind_dn="cn=Directory Manager",
            bind_password="secret",
        )
        assert config.ldap_url == "ldap://plain.example.com:389"


# Unit tests for config loader SSL support


class TestConfigLoaderSSL:
    """Test config loader with SSL fields."""

    def test_server_config_from_dict_with_ldaps_url(self):
        """_server_config_from_dict() should parse ldaps:// URL."""
        data = {
            "name": "ssl-test",
            "ldap_url": "ldaps://secure.example.com:636",
            "base_dn": "dc=test,dc=com",
            "bind_dn": "cn=Directory Manager",
            "bind_password": "secret",
        }
        config = _server_config_from_dict(data)
        assert config.use_ssl is True
        assert config.hostname == "secure.example.com"
        assert config.port == 636

    def test_server_config_from_dict_with_ldap_url(self):
        """_server_config_from_dict() should parse ldap:// URL."""
        data = {
            "name": "plain-test",
            "ldap_url": "ldap://plain.example.com:389",
            "base_dn": "dc=test,dc=com",
            "bind_dn": "cn=Directory Manager",
            "bind_password": "secret",
        }
        config = _server_config_from_dict(data)
        assert config.use_ssl is False
        assert config.hostname == "plain.example.com"
        assert config.port == 389

    def test_server_config_from_dict_with_explicit_use_ssl(self):
        """_server_config_from_dict() should handle explicit use_ssl field."""
        data = {
            "name": "ssl-test",
            "hostname": "secure.example.com",
            "port": 636,
            "use_ssl": True,
            "base_dn": "dc=test,dc=com",
            "bind_dn": "cn=Directory Manager",
            "bind_password": "secret",
        }
        config = _server_config_from_dict(data)
        assert config.use_ssl is True

    def test_server_config_from_dict_use_ssl_string_true(self):
        """_server_config_from_dict() should handle string 'true' for use_ssl."""
        data = {
            "name": "ssl-test",
            "hostname": "secure.example.com",
            "port": 636,
            "use_ssl": "true",
            "base_dn": "dc=test,dc=com",
            "bind_dn": "cn=Directory Manager",
            "bind_password": "secret",
        }
        config = _server_config_from_dict(data)
        assert config.use_ssl is True

    def test_server_config_from_dict_use_ssl_string_false(self):
        """_server_config_from_dict() should handle string 'false' for use_ssl."""
        data = {
            "name": "plain-test",
            "hostname": "plain.example.com",
            "port": 389,
            "use_ssl": "false",
            "base_dn": "dc=test,dc=com",
            "bind_dn": "cn=Directory Manager",
            "bind_password": "secret",
        }
        config = _server_config_from_dict(data)
        assert config.use_ssl is False

    def test_server_config_from_dict_ldaps_default_port(self):
        """_server_config_from_dict() should default to 636 for ldaps:// without port."""
        data = {
            "name": "ssl-test",
            "ldap_url": "ldaps://secure.example.com",
            "base_dn": "dc=test,dc=com",
            "bind_dn": "cn=Directory Manager",
            "bind_password": "secret",
        }
        config = _server_config_from_dict(data)
        assert config.use_ssl is True
        assert config.port == 636

    def test_server_config_from_dict_ldap_default_port(self):
        """_server_config_from_dict() should default to 389 for ldap:// without port."""
        data = {
            "name": "plain-test",
            "ldap_url": "ldap://plain.example.com",
            "base_dn": "dc=test,dc=com",
            "bind_dn": "cn=Directory Manager",
            "bind_password": "secret",
        }
        config = _server_config_from_dict(data)
        assert config.use_ssl is False
        assert config.port == 389

    def test_server_config_from_dict_explicit_use_ssl_overrides_url(self):
        """Explicit use_ssl should override URL scheme inference."""
        # This tests edge case: ldap:// URL but use_ssl=true
        data = {
            "name": "override-test",
            "ldap_url": "ldap://localhost:636",
            "use_ssl": True,
            "base_dn": "dc=test,dc=com",
            "bind_dn": "cn=Directory Manager",
            "bind_password": "secret",
        }
        config = _server_config_from_dict(data)
        assert config.use_ssl is True


# Unit tests for ConnectionManager SSL support


class TestConnectionManagerSSL:
    """Test ConnectionManager with SSL configurations."""

    def test_add_ldaps_server(self):
        """ConnectionManager should store LDAPS server config."""
        cm = ConnectionManager()
        config = LDAPServerConfig(
            name="ssl-test",
            hostname="secure.example.com",
            port=636,
            use_ssl=True,
            bind_dn="cn=Directory Manager",
            bind_password="secret",
            base_dn="dc=test,dc=com",
        )
        cm.add_server(config)

        stored = cm.get_config("ssl-test")
        assert "ldaps://" in stored.ldap_url
        assert stored.ldap_url == "ldaps://secure.example.com:636"

    def test_add_ldap_server(self):
        """ConnectionManager should store LDAP server config."""
        cm = ConnectionManager()
        config = LDAPServerConfig(
            name="plain-test",
            hostname="plain.example.com",
            port=389,
            use_ssl=False,
            bind_dn="cn=Directory Manager",
            bind_password="secret",
            base_dn="dc=test,dc=com",
        )
        cm.add_server(config)

        stored = cm.get_config("plain-test")
        assert "ldap://" in stored.ldap_url
        assert "ldaps://" not in stored.ldap_url
        assert stored.ldap_url == "ldap://plain.example.com:389"


# Tests for mixed LDAP/LDAPS multi-server configurations


class TestMixedSSLConfig:
    """Test configurations with both LDAP and LDAPS servers."""

    def test_mixed_ssl_config_from_dict(self):
        """Should handle mixed LDAP and LDAPS servers in same config."""
        data = {
            "servers": [
                {
                    "name": "secure-server",
                    "ldap_url": "ldaps://secure.example.com:636",
                    "base_dn": "dc=secure,dc=com",
                    "bind_dn": "cn=Directory Manager",
                    "bind_password": "secret",
                },
                {
                    "name": "plain-server",
                    "ldap_url": "ldap://plain.example.com:389",
                    "base_dn": "dc=plain,dc=com",
                    "bind_dn": "cn=Directory Manager",
                    "bind_password": "secret",
                }
            ]
        }

        config = ServerListConfig.from_dict(data)
        assert len(config.servers) == 2

        secure = next(s for s in config.servers if s.name == "secure-server")
        plain = next(s for s in config.servers if s.name == "plain-server")

        assert secure.use_ssl is True
        assert secure.port == 636
        assert plain.use_ssl is False
        assert plain.port == 389

    def test_mixed_ssl_config_to_dict(self):
        """to_dict() should correctly serialize mixed SSL config."""
        servers = [
            LDAPServerConfig(
                name="secure",
                hostname="secure.example.com",
                port=636,
                use_ssl=True,
            ),
            LDAPServerConfig(
                name="plain",
                hostname="plain.example.com",
                port=389,
                use_ssl=False,
            )
        ]

        config = ServerListConfig(servers=servers)
        d = config.to_dict()

        secure_dict = next(s for s in d["servers"] if s["name"] == "secure")
        plain_dict = next(s for s in d["servers"] if s["name"] == "plain")

        assert secure_dict["use_ssl"] is True
        assert secure_dict["port"] == 636
        assert plain_dict["use_ssl"] is False
        assert plain_dict["port"] == 389

    def test_ssl_with_local_connection(self):
        """SSL should work together with local connection settings."""
        config = LDAPServerConfig(
            name="local-ssl",
            hostname="localhost",
            port=636,
            use_ssl=True,
            is_local=True,
            serverid="standalone",
        )
        assert config.use_ssl is True
        assert config.is_local is True
        assert config.ldap_url == "ldaps://localhost:636"

    def test_ssl_with_ldapi_not_typical(self):
        """LDAPI typically doesn't use SSL (Unix socket), but config allows it."""
        # This is an edge case - LDAPI uses Unix sockets, so SSL isn't typical
        # but the config should still allow the combination
        config = LDAPServerConfig(
            name="ldapi-ssl",
            hostname="localhost",
            port=636,
            use_ssl=True,
            is_local=True,
            serverid="standalone",
            use_ldapi=True,
        )
        # Config is accepted, but in practice LDAPI ignores use_ssl
        assert config.use_ssl is True
        assert config.use_ldapi is True
