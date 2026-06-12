"""Tests for configuration analysis tools.

These tests verify the configuration analysis tools work correctly against
389 Directory Server instances.
"""

from __future__ import annotations

import pytest
from fastmcp import Client

from ldap_assistant_mcp.dirsrv_mcp.server import DirSrvMCP

pytestmark = pytest.mark.asyncio


# get_server_configuration tests


async def test_get_server_configuration_returns_valid_structure(
    dirsrv_server: DirSrvMCP,
):
    """Test that get_server_configuration returns expected structure."""
    async with Client(dirsrv_server) as client:
        result = await client.call_tool("get_server_configuration", {})
        data = result.data

    assert data["type"] == "server_configuration"
    assert "server" in data
    assert "config" in data
    assert "attribute_count" in data
    assert isinstance(data["config"], dict)


async def test_get_server_configuration_with_pattern_filter(dirsrv_server: DirSrvMCP):
    """Test get_server_configuration with pattern filter."""
    async with Client(dirsrv_server) as client:
        result = await client.call_tool(
            "get_server_configuration", {"pattern": "security"}
        )
        data = result.data

    assert data["type"] == "server_configuration"
    assert data["pattern"] == "security"
    # All returned attributes should contain "security"
    for attr in data["config"].keys():
        assert "security" in attr.lower()


async def test_get_server_configuration_returns_attributes(dirsrv_server: DirSrvMCP):
    """Test that configuration returns actual attributes."""
    async with Client(dirsrv_server) as client:
        result = await client.call_tool("get_server_configuration", {})
        data = result.data

    # Should have attributes
    assert data["attribute_count"] > 0
    assert len(data["config"]) > 0


async def test_get_server_configuration_pattern_port(dirsrv_server: DirSrvMCP):
    """Test filtering by port pattern."""
    async with Client(dirsrv_server) as client:
        result = await client.call_tool(
            "get_server_configuration", {"pattern": "port"}
        )
        data = result.data

    assert data["type"] == "server_configuration"
    # Should find port-related settings
    assert data["attribute_count"] > 0


# list_plugins tests


async def test_list_plugins_returns_valid_structure(dirsrv_server: DirSrvMCP):
    """Test that list_plugins returns expected structure."""
    async with Client(dirsrv_server) as client:
        result = await client.call_tool("list_plugins", {})
        data = result.data

    assert data["type"] == "plugin_list"
    assert "server" in data
    assert "plugins" in data
    assert "count" in data
    assert isinstance(data["plugins"], list)


async def test_list_plugins_enabled_only_default(dirsrv_server: DirSrvMCP):
    """Test that list_plugins defaults to enabled_only=True."""
    async with Client(dirsrv_server) as client:
        result = await client.call_tool("list_plugins", {})
        data = result.data

    assert data["enabled_only"] is True
    for plugin in data.get("plugins", []):
        assert plugin.get("enabled", "").lower() == "on"


async def test_list_plugins_all_plugins(dirsrv_server: DirSrvMCP):
    """Test list_plugins with enabled_only=False."""
    async with Client(dirsrv_server) as client:
        result = await client.call_tool("list_plugins", {"enabled_only": False})
        data = result.data

    assert data["enabled_only"] is False


async def test_list_plugins_has_plugin_details(dirsrv_server: DirSrvMCP):
    """Test that plugins have proper details."""
    async with Client(dirsrv_server) as client:
        result = await client.call_tool("list_plugins", {})
        data = result.data

    if data.get("plugins"):
        plugin = data["plugins"][0]
        assert "name" in plugin
        assert "enabled" in plugin
        assert "type" in plugin


# get_backend_configuration tests


async def test_get_backend_configuration_returns_valid_structure(
    dirsrv_server: DirSrvMCP,
):
    """Test that get_backend_configuration returns expected structure."""
    async with Client(dirsrv_server) as client:
        result = await client.call_tool("get_backend_configuration", {})
        data = result.data

    assert data["type"] == "backend_configuration"
    assert "server" in data
    assert "backends" in data
    assert isinstance(data["backends"], list)


async def test_get_backend_configuration_with_filter(dirsrv_server: DirSrvMCP):
    """Test get_backend_configuration with backend filter."""
    async with Client(dirsrv_server) as client:
        result = await client.call_tool(
            "get_backend_configuration", {"backend": "userroot"}
        )
        data = result.data

    assert data["type"] == "backend_configuration"
    if "backends" in data and data["backends"]:
        assert len(data["backends"]) == 1
        assert data["backends"][0]["name"].lower() == "userroot"


async def test_get_backend_configuration_has_backend_details(dirsrv_server: DirSrvMCP):
    """Test that backends have proper details."""
    async with Client(dirsrv_server) as client:
        result = await client.call_tool("get_backend_configuration", {})
        data = result.data

    if data.get("backends"):
        backend = data["backends"][0]
        assert "name" in backend
        assert "suffix" in backend
        assert "replication" in backend


async def test_get_backend_configuration_includes_config(dirsrv_server: DirSrvMCP):
    """Test that backend includes dynamic config."""
    async with Client(dirsrv_server) as client:
        result = await client.call_tool("get_backend_configuration", {})
        data = result.data

    if data.get("backends"):
        backend = data["backends"][0]
        assert "config" in backend
        assert isinstance(backend["config"], dict)


# compare_server_configurations tests


async def test_compare_server_configurations_same_server(dirsrv_server: DirSrvMCP):
    """Test comparing a server with itself returns no differences."""
    server_names = dirsrv_server.connection_manager.get_server_names()
    if not server_names:
        pytest.skip("No servers configured")

    server_name = server_names[0]

    async with Client(dirsrv_server) as client:
        result = await client.call_tool(
            "compare_server_configurations",
            {"server1": server_name, "server2": server_name},
        )
        data = result.data

    assert data["type"] == "config_comparison"
    assert data["differences"] == []
    assert data["matching_count"] > 0


async def test_compare_server_configurations_invalid_server(dirsrv_server: DirSrvMCP):
    """Test comparing with invalid server returns error."""
    async with Client(dirsrv_server) as client:
        result = await client.call_tool(
            "compare_server_configurations",
            {"server1": "nonexistent_server", "server2": "another_fake"},
        )
        data = result.data

    assert "error" in data


async def test_compare_server_configurations_with_pattern(dirsrv_server: DirSrvMCP):
    """Test compare with pattern filter."""
    server_names = dirsrv_server.connection_manager.get_server_names()
    if not server_names:
        pytest.skip("No servers configured")

    server_name = server_names[0]

    async with Client(dirsrv_server) as client:
        result = await client.call_tool(
            "compare_server_configurations",
            {"server1": server_name, "server2": server_name, "pattern": "cache"},
        )
        data = result.data

    assert data["type"] == "config_comparison"
    assert data["pattern"] == "cache"
