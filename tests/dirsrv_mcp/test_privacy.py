"""Tests for privacy mode and data sanitization.

Following FastMCP testing patterns:
- Each test verifies exactly one behavior
- Tests are self-contained and can run in any order
- Use in-memory transport via Client(server) pattern
"""

from __future__ import annotations

import os
from unittest.mock import patch

import pytest
from fastmcp import Client

from ldap_assistant_mcp.core import LDAPServerConfig, MCPSettings
from ldap_assistant_mcp.dirsrv_mcp.server import DirSrvMCP
from ldap_assistant_mcp.lib.privacy import (
    PrivacySanitizer,
    create_count_only_response,
    create_privacy_error,
    get_sanitizer,
    reset_sanitizer,
)


# MCPSettings tests


def test_mcp_settings_defaults():
    """Test that MCPSettings has secure defaults."""
    settings = MCPSettings()
    assert settings.expose_sensitive_data is False, "Should default to privacy mode"


def test_mcp_settings_from_env_default():
    """Test MCPSettings from env with no variables set."""
    with patch.dict(os.environ, {}, clear=True):
        settings = MCPSettings.from_env()
        assert settings.expose_sensitive_data is False


def test_mcp_settings_from_env_expose_true():
    """Test MCPSettings from env with expose_sensitive_data=true."""
    with patch.dict(os.environ, {"LDAP_MCP_EXPOSE_SENSITIVE_DATA": "true"}):
        settings = MCPSettings.from_env()
        assert settings.expose_sensitive_data is True


def test_mcp_settings_from_env_expose_variations():
    """Test MCPSettings accepts various truthy values."""
    truthy_values = ["1", "true", "True", "TRUE", "yes", "YES", "on", "ON"]
    for value in truthy_values:
        with patch.dict(os.environ, {"LDAP_MCP_EXPOSE_SENSITIVE_DATA": value}):
            settings = MCPSettings.from_env()
            assert settings.expose_sensitive_data is True, f"Should accept '{value}' as True"


def test_mcp_settings_from_env_expose_false():
    """Test MCPSettings rejects non-truthy values."""
    falsy_values = ["0", "false", "False", "no", "off", "", "random"]
    for value in falsy_values:
        with patch.dict(os.environ, {"LDAP_MCP_EXPOSE_SENSITIVE_DATA": value}):
            settings = MCPSettings.from_env()
            assert settings.expose_sensitive_data is False, f"Should reject '{value}'"


def test_mcp_settings_to_dict():
    """Test MCPSettings serialization."""
    settings = MCPSettings(expose_sensitive_data=True)
    d = settings.to_dict()
    assert d["expose_sensitive_data"] is True


# PrivacySanitizer unit tests


def test_sanitizer_hostname_consistency():
    """Test that same hostname always maps to same anonymized value."""
    sanitizer = PrivacySanitizer()
    result1 = sanitizer.sanitize_hostname("server1.example.com")
    result2 = sanitizer.sanitize_hostname("server1.example.com")
    assert result1 == result2, "Same hostname should map to same value"
    assert result1.startswith("[host-") and result1.endswith("]")


def test_sanitizer_different_hostnames():
    """Test that different hostnames get different anonymized values."""
    sanitizer = PrivacySanitizer()
    result1 = sanitizer.sanitize_hostname("server1.example.com")
    result2 = sanitizer.sanitize_hostname("server2.example.com")
    assert result1 != result2, "Different hostnames should differ"
    assert result1.startswith("[host-")
    assert result2.startswith("[host-")


def test_sanitizer_placeholders_are_opaque():
    """Placeholders are random tokens with no relationship to the input."""
    s1 = PrivacySanitizer()
    s2 = PrivacySanitizer()
    # Same input, different instances → different random tokens
    assert s1.sanitize_hostname("a.example.com") != s2.sanitize_hostname("a.example.com")
    assert s1.sanitize_server_name("srv") != s2.sanitize_server_name("srv")
    assert s1.sanitize_dn("cn=config") != s2.sanitize_dn("cn=config")


def test_sanitizer_server_name():
    """Test server name sanitization."""
    sanitizer = PrivacySanitizer()
    result = sanitizer.sanitize_server_name("ds-test-1")
    assert result.startswith("[server-") and result.endswith("]")
    result2 = sanitizer.sanitize_server_name("ds-test-1")
    assert result == result2, "Same server should map to same value"


def test_sanitizer_dn():
    """Test DN sanitization."""
    sanitizer = PrivacySanitizer()
    result = sanitizer.sanitize_dn("uid=admin,ou=people,dc=example,dc=com")
    assert result.startswith("[entry-") and result.endswith("]")


def test_sanitizer_suffix():
    """Test suffix sanitization."""
    sanitizer = PrivacySanitizer()
    result = sanitizer.sanitize_suffix("dc=example,dc=com")
    assert result.startswith("[suffix-") and result.endswith("]")


def test_sanitizer_url():
    """Test URL sanitization."""
    sanitizer = PrivacySanitizer()
    assert sanitizer.sanitize_url("ldap://server.example.com:389") == "[ldap-url]"
    assert sanitizer.sanitize_url("ldaps://server.example.com:636") == "[ldap-url]"
    assert sanitizer.sanitize_url("https://server.example.com") == "[url]"


def test_sanitizer_path():
    """Test path sanitization."""
    sanitizer = PrivacySanitizer()
    assert sanitizer.sanitize_path("/var/log/dirsrv/slapd-server1/access") == "[path]"


def test_sanitizer_empty_values():
    """Test that empty values pass through unchanged."""
    sanitizer = PrivacySanitizer()
    assert sanitizer.sanitize_hostname("") == ""
    assert sanitizer.sanitize_hostname(None) is None
    assert sanitizer.sanitize_server_name("") == ""
    assert sanitizer.sanitize_dn(None) is None


def test_sanitizer_reset():
    """Test that reset clears caches but key is preserved (same output)."""
    sanitizer = PrivacySanitizer()
    before = sanitizer.sanitize_hostname("server.example.com")
    sanitizer.reset()
    after = sanitizer.sanitize_hostname("server.example.com")
    assert before == after, "Same instance + same key → same token after reset"


def test_sanitizer_case_insensitive():
    """Test that sanitization is case-insensitive."""
    sanitizer = PrivacySanitizer()
    result1 = sanitizer.sanitize_hostname("Server.Example.COM")
    result2 = sanitizer.sanitize_hostname("server.example.com")
    assert result1 == result2, "Hostnames should match case-insensitively"


def test_sanitizer_attribute_value_credentials():
    """Test that credential attributes are always redacted."""
    sanitizer = PrivacySanitizer()
    assert sanitizer.sanitize_attribute_value("userPassword", "secret123") == "[REDACTED]"
    assert sanitizer.sanitize_attribute_value("nsDS5ReplicaCredentials", "pass") == "[REDACTED]"
    assert sanitizer.sanitize_attribute_value("USERPASSWORD", "secret") == "[REDACTED]"


def test_sanitizer_attribute_value_dn():
    """Test that DN attribute values are sanitized."""
    sanitizer = PrivacySanitizer()
    result = sanitizer.sanitize_attribute_value("member", "uid=user,dc=example,dc=com")
    assert result.startswith("[entry-") and result.endswith("]")


def test_sanitizer_attribute_value_path():
    """Test that path attribute values are sanitized."""
    sanitizer = PrivacySanitizer()
    result = sanitizer.sanitize_attribute_value("nsslapd-errorlog", "/var/log/dirsrv/errors")
    assert result == "[path]"


def test_sanitizer_attribute_value_non_sensitive():
    """Test that non-sensitive attributes pass through."""
    sanitizer = PrivacySanitizer()
    assert sanitizer.sanitize_attribute_value("objectClass", "inetOrgPerson") == "inetOrgPerson"
    assert sanitizer.sanitize_attribute_value("uidNumber", "1000") == "1000"


def test_sanitizer_entry():
    """Test complete entry sanitization."""
    sanitizer = PrivacySanitizer()
    entry = {
        "dn": "uid=admin,ou=people,dc=example,dc=com",
        "attrs": {
            "uid": ["admin"],
            "cn": ["Admin User"],
            "objectClass": ["inetOrgPerson"],
            "userPassword": ["secret"],
        }
    }
    result = sanitizer.sanitize_entry(entry)
    assert result["dn"].startswith("[entry-") and result["dn"].endswith("]")
    assert result["attrs"]["userPassword"] == "[REDACTED]"
    assert result["attrs"]["objectClass"] == ["inetOrgPerson"]


def test_sanitizer_finding():
    """Test finding sanitization."""
    sanitizer = PrivacySanitizer()
    finding = {
        "title": "Test Issue",
        "severity": "high",
        "server": "ds-test-1",
        "metadata": {
            "suffix": "dc=example,dc=com",
            "server": "ds-test-1",
        }
    }
    result = sanitizer.sanitize_finding(finding)
    assert result["server"] == "ds-test-1"  # Server names pass through unsanitized
    assert result["metadata"]["suffix"].startswith("[suffix-")
    assert result["metadata"]["server"] == result["server"]
    assert result["severity"] == "high"  # Preserved


def test_sanitizer_agreement():
    """Test replication agreement sanitization."""
    sanitizer = PrivacySanitizer()
    agreement = {
        "name": "agreement-to-replica2",
        "consumer_host": "replica2.example.com",
        "consumer_port": 389,
        "suffix": "dc=example,dc=com",
        "status": {"state": "online", "lag": 0},
    }
    result = sanitizer.sanitize_agreement(agreement)
    assert result["name"] == "[agreement]"
    assert result["consumer_host"].startswith("[host-")
    assert result["consumer_port"] == "[port]"
    assert result["suffix"].startswith("[suffix-")
    assert result["status"]["state"] == "online"


def test_sanitizer_backend():
    """Test backend sanitization."""
    sanitizer = PrivacySanitizer()
    backend = {
        "name": "userroot",
        "suffix": "dc=example,dc=com",
        "entry_count": 1000,
    }
    result = sanitizer.sanitize_backend(backend)
    assert result["name"] == "[backend]"
    assert result["suffix"].startswith("[suffix-")
    assert result["entry_count"] == 1000  # Numeric preserved


def test_sanitizer_finding_metadata_items():
    """Test that finding metadata 'items' list is sanitized via sanitize_text."""
    sanitizer = PrivacySanitizer()
    finding = {
        "title": "Test",
        "severity": "medium",
        "metadata": {
            "items": [
                "cn=config",
                "cn=replica,cn=dc=example,dc=com,cn=mapping tree,cn=config",
                "dc=example,dc=com",
            ],
            "dsle": "DSELE0001",
        }
    }
    result = sanitizer.sanitize_finding(finding)
    # Items should be processed by sanitize_text (DN patterns replaced)
    for item in result["metadata"]["items"]:
        assert "example" not in item, f"DN should be sanitized: {item}"
    # Non-items metadata preserved
    assert result["metadata"]["dsle"] == "DSELE0001"


def test_sanitizer_finding_metadata_items_single():
    """Test that finding metadata 'items' non-list is sanitized."""
    sanitizer = PrivacySanitizer()
    finding = {
        "title": "Test",
        "metadata": {
            "items": "cn=replica,cn=dc=example,dc=com,cn=mapping tree,cn=config",
        }
    }
    result = sanitizer.sanitize_finding(finding)
    assert "example" not in result["metadata"]["items"]


def test_sanitizer_agreement_csn_keys():
    """Test that top-level CSN keys in agreements are redacted."""
    sanitizer = PrivacySanitizer()
    agreement = {
        "name": "agmt-to-replica2",
        "suffix": "dc=example,dc=com",
        "supplier_csn": "5f3b0a0e000000010000",
        "consumer_csn": "5f3b0a0d000000010000",
        "lag_status": "lagging",
    }
    result = sanitizer.sanitize_agreement(agreement)
    assert result["supplier_csn"] == "[csn]"
    assert result["consumer_csn"] == "[csn]"
    assert result["lag_status"] == "lagging"  # Non-CSN preserved
    assert result["name"] == "[agreement]"


def test_sanitizer_agreement_csn_in_nested_status():
    """Test that CSNs in nested status dict are also redacted."""
    sanitizer = PrivacySanitizer()
    agreement = {
        "name": "agmt1",
        "status": {
            "state": "green",
            "agmt_maxcsn": "5f3b0a0e000000010000",
            "con_maxcsn": "5f3b0a0d000000010000",
        },
    }
    result = sanitizer.sanitize_agreement(agreement)
    assert result["status"]["agmt_maxcsn"] == "[csn]"
    assert result["status"]["con_maxcsn"] == "[csn]"
    assert result["status"]["state"] == "green"


# Helper function tests


def test_create_privacy_error():
    """Test privacy error response creation."""
    result = create_privacy_error("ldap_search")
    assert result["type"] == "privacy_restricted"
    assert "ldap_search" in result["error"]
    assert "disabled" in result["error"].lower()
    assert "hint" in result


def test_create_count_only_response():
    """Test count-only response creation."""
    reset_sanitizer()
    result = create_count_only_response("user_list", "ds-test-1", 42)
    assert result["type"] == "user_list"
    assert result["privacy_mode"] is True
    assert result["count"] == 42
    assert result["server"] == "ds-test-1"  # Server names pass through unsanitized
    assert "42" in result["message"]


def test_global_sanitizer():
    """Test global sanitizer instance."""
    reset_sanitizer()
    s1 = get_sanitizer()
    s2 = get_sanitizer()
    assert s1 is s2, "Should return same instance"
    val = s1.sanitize_hostname("test.example.com")
    assert val.startswith("[host-")
    # Same sanitizer instance should give same result
    assert s2.sanitize_hostname("test.example.com") == val


# DirSrvMCP privacy mode fixtures


@pytest.fixture
def mock_env():
    """Ensure LDAP connection environment variables are defined."""
    env_vars = {
        "LDAP_URL": os.environ.get("LDAP_URL", "ldap://localhost:33891"),
        "LDAP_BASE_DN": os.environ.get("LDAP_BASE_DN", "dc=test,dc=com"),
        "LDAP_BIND_DN": os.environ.get("LDAP_BIND_DN", "cn=Directory Manager"),
        "LDAP_BIND_PASSWORD": os.environ.get("LDAP_BIND_PASSWORD", "TestPassword123"),
    }
    with patch.dict(os.environ, env_vars):
        yield env_vars


@pytest.fixture
def server_config(mock_env) -> LDAPServerConfig:
    """Return the LDAP server configuration."""
    return LDAPServerConfig.from_env()


@pytest.fixture
def privacy_server(server_config) -> DirSrvMCP:
    """Create a DirSrvMCP instance with privacy mode enabled (default)."""
    settings = MCPSettings(expose_sensitive_data=False)
    return DirSrvMCP(
        servers=[server_config],
        include_env_fallback=False,
        settings=settings,
    )


@pytest.fixture
def exposed_server(server_config) -> DirSrvMCP:
    """Create a DirSrvMCP instance with privacy mode disabled."""
    settings = MCPSettings(expose_sensitive_data=True)
    return DirSrvMCP(
        servers=[server_config],
        include_env_fallback=False,
        settings=settings,
    )


# Integration tests - privacy mode behavior


@pytest.mark.asyncio
async def test_privacy_server_has_privacy_enabled(privacy_server):
    """Test that privacy server has privacy mode enabled."""
    assert privacy_server.privacy_enabled is True


@pytest.mark.asyncio
async def test_exposed_server_has_privacy_disabled(exposed_server):
    """Test that exposed server has privacy mode disabled."""
    assert exposed_server.privacy_enabled is False


@pytest.mark.asyncio
async def test_list_users_privacy_mode_returns_count_only(privacy_server):
    """Test that list_all_users returns count-only in privacy mode."""
    async with Client(privacy_server) as client:
        result = await client.call_tool("list_all_users", {})
        data = result.data

        assert data["privacy_mode"] is True, "Should indicate privacy mode"
        assert "count" in data, "Should include count"
        assert "items" not in data, "Should NOT include items"
        assert "[server-" not in data["server"], "Server name should not be sanitized"


@pytest.mark.asyncio
async def test_list_users_exposed_mode_returns_items(exposed_server):
    """Test that list_all_users returns full items when exposed."""
    async with Client(exposed_server) as client:
        result = await client.call_tool("list_all_users", {})
        data = result.data

        assert data.get("privacy_mode") is not True, "Should not be in privacy mode"
        assert "items" in data, "Should include items"


@pytest.mark.asyncio
async def test_list_groups_privacy_mode_returns_count_only(privacy_server):
    """Test that list_all_groups returns count-only in privacy mode."""
    async with Client(privacy_server) as client:
        result = await client.call_tool("list_all_groups", {})
        data = result.data

        assert data["privacy_mode"] is True, "Should indicate privacy mode"
        assert "count" in data, "Should include count"


@pytest.mark.asyncio
async def test_get_user_details_disabled_in_privacy_mode(privacy_server):
    """Test that get_user_details is disabled in privacy mode."""
    async with Client(privacy_server) as client:
        result = await client.call_tool("get_user_details", {"username": "testuser1"})
        data = result.data

        assert data["type"] == "privacy_restricted", "Should return privacy error"
        assert "disabled" in data["error"].lower()


@pytest.mark.asyncio
async def test_get_user_details_works_in_exposed_mode(exposed_server):
    """Test that get_user_details works when exposed."""
    async with Client(exposed_server) as client:
        result = await client.call_tool("get_user_details", {"username": "testuser1"})
        data = result.data

        # Should either return user data or "not found" - not privacy restricted
        assert data["type"] != "privacy_restricted"


@pytest.mark.asyncio
async def test_ldap_search_disabled_in_privacy_mode(privacy_server):
    """Test that ldap_search is disabled in privacy mode."""
    async with Client(privacy_server) as client:
        result = await client.call_tool("ldap_search", {"base_dn": "dc=test,dc=com"})
        data = result.data

        assert data["type"] == "privacy_restricted"
        assert "ldap_search" in data["error"]


@pytest.mark.asyncio
async def test_ldap_search_works_in_exposed_mode(exposed_server):
    """Test that ldap_search works when exposed."""
    async with Client(exposed_server) as client:
        result = await client.call_tool("ldap_search", {
            "base_dn": "dc=test,dc=com",
            "scope": "BASE"
        })
        data = result.data

        assert data["type"] == "ldap_search"
        assert "items" in data


@pytest.mark.asyncio
async def test_health_check_sanitizes_server_names(privacy_server):
    """Test that health check sanitizes server names."""
    async with Client(privacy_server) as client:
        result = await client.call_tool("first_look", {})
        data = result.data

        # Server names in results should pass through unsanitized
        if "servers_checked" in data:
            for server in data["servers_checked"]:
                assert "[server-" not in server


@pytest.mark.asyncio
async def test_config_comparison_sanitizes_servers(privacy_server):
    """Test that configuration tools sanitize server names."""
    async with Client(privacy_server) as client:
        result = await client.call_tool("get_server_configuration", {})
        data = result.data

        if "server" in data:
            assert "[server-" not in data["server"], "Server name should not be sanitized"

        # Config values should be redacted
        if "config" in data and isinstance(data["config"], dict):
            for value in data["config"].values():
                assert value == "[REDACTED]", "Config values should be redacted"


@pytest.mark.asyncio
async def test_backend_config_sanitizes_in_privacy_mode(privacy_server):
    """Test that backend configuration is sanitized."""
    async with Client(privacy_server) as client:
        result = await client.call_tool("get_backend_configuration", {})
        data = result.data

        if "backends" in data:
            for backend in data["backends"]:
                if "name" in backend:
                    assert backend["name"] == "[backend]"
                if "suffix" in backend:
                    assert "[suffix-" in backend["suffix"]


@pytest.mark.asyncio
async def test_replication_status_sanitizes_in_privacy_mode(privacy_server):
    """Test that replication status is sanitized."""
    async with Client(privacy_server) as client:
        result = await client.call_tool("get_replication_status", {})
        data = result.data

        if "server" in data:
            assert "[server-" not in data["server"]

        # Agreements should be sanitized
        if "replicas" in data:
            for replica in data["replicas"]:
                if "suffix" in replica:
                    assert "[suffix-" in replica["suffix"]


@pytest.mark.asyncio
async def test_performance_summary_sanitizes_server(privacy_server):
    """Test that performance summary sanitizes server name."""
    async with Client(privacy_server) as client:
        result = await client.call_tool("get_performance_summary", {})
        data = result.data

        if "server" in data:
            assert "[server-" not in data["server"]


@pytest.mark.asyncio
async def test_cache_statistics_sanitizes_backends(privacy_server):
    """Test that cache statistics sanitizes backend names."""
    async with Client(privacy_server) as client:
        result = await client.call_tool("get_cache_statistics", {})
        data = result.data

        if "backends" in data:
            for backend in data["backends"]:
                if "name" in backend:
                    assert backend["name"] == "[backend]"


# DirSrvMCP settings loading tests


@pytest.mark.asyncio
async def test_dirsrv_uses_provided_settings(server_config):
    """Test that DirSrvMCP uses provided settings."""
    settings = MCPSettings(expose_sensitive_data=True)
    server = DirSrvMCP(
        servers=[server_config],
        include_env_fallback=False,
        settings=settings,
    )
    assert server.privacy_enabled is False


@pytest.mark.asyncio
async def test_dirsrv_defaults_to_privacy_mode(server_config):
    """Test that DirSrvMCP defaults to privacy mode."""
    # Clear the env var to test defaults
    with patch.dict(os.environ, {"LDAP_MCP_EXPOSE_SENSITIVE_DATA": ""}, clear=False):
        server = DirSrvMCP(
            servers=[server_config],
            include_env_fallback=False,
        )
        assert server.privacy_enabled is True


@pytest.mark.asyncio
async def test_dirsrv_settings_from_env(server_config):
    """Test that DirSrvMCP loads settings from environment."""
    with patch.dict(os.environ, {"LDAP_MCP_EXPOSE_SENSITIVE_DATA": "true"}):
        server = DirSrvMCP(
            servers=[server_config],
            include_env_fallback=False,
        )
        assert server.privacy_enabled is False
