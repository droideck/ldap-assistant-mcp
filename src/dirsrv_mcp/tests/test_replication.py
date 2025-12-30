"""Tests for replication diagnostic tools.

These tests verify the replication tools work correctly against
389 Directory Server instances. The test servers may or may not
have replication configured depending on the test environment.
"""

from __future__ import annotations

import pytest
from fastmcp import Client

from src.dirsrv_mcp.server import DirSrvMCP

pytestmark = pytest.mark.asyncio


async def test_get_replication_status_returns_valid_structure(dirsrv_server: DirSrvMCP):
    """Test that get_replication_status returns expected structure."""
    async with Client(dirsrv_server) as client:
        result = await client.call_tool("get_replication_status", {})
        data = result.data

    assert "type" in data
    assert data["type"] == "replication_status"
    assert "server" in data
    assert "replicas" in data
    assert isinstance(data["replicas"], list)

    # Should either have replicas or a message about no replication
    if data.get("summary"):
        assert isinstance(data["summary"], str)


async def test_get_replication_status_with_server_name(dirsrv_server: DirSrvMCP):
    """Test get_replication_status with explicit server_name parameter."""
    server_name = dirsrv_server.default_server
    async with Client(dirsrv_server) as client:
        result = await client.call_tool(
            "get_replication_status",
            {"server_name": server_name}
        )
        data = result.data

    assert data["type"] == "replication_status"
    assert data["server"] == server_name


async def test_get_replication_topology_returns_valid_structure(dirsrv_server: DirSrvMCP):
    """Test that get_replication_topology returns expected structure."""
    async with Client(dirsrv_server) as client:
        result = await client.call_tool("get_replication_topology", {})
        data = result.data

    assert "type" in data
    assert data["type"] == "replication_topology"
    assert "servers" in data
    assert isinstance(data["servers"], list)
    assert "agreements" in data
    assert isinstance(data["agreements"], list)
    assert "suffixes" in data
    assert isinstance(data["suffixes"], dict)


async def test_check_replication_lag_returns_valid_structure(dirsrv_server: DirSrvMCP):
    """Test that check_replication_lag returns expected structure."""
    async with Client(dirsrv_server) as client:
        result = await client.call_tool("check_replication_lag", {})
        data = result.data

    assert "type" in data
    assert data["type"] == "replication_lag"
    assert "server" in data
    assert "lag_data" in data
    assert isinstance(data["lag_data"], list)


async def test_check_replication_lag_with_suffix_filter(dirsrv_server: DirSrvMCP):
    """Test check_replication_lag with suffix filter."""
    async with Client(dirsrv_server) as client:
        result = await client.call_tool(
            "check_replication_lag",
            {"suffix": "dc=test,dc=com"}
        )
        data = result.data

    assert data["type"] == "replication_lag"
    # If replication is configured, suffix filter should be recorded
    # If no replication, this field may not be present
    if "suffix_filter" in data:
        assert data["suffix_filter"] == "dc=test,dc=com"


async def test_list_replication_conflicts_returns_valid_structure(dirsrv_server: DirSrvMCP):
    """Test that list_replication_conflicts returns expected structure."""
    async with Client(dirsrv_server) as client:
        result = await client.call_tool("list_replication_conflicts", {})
        data = result.data

    assert "type" in data
    assert data["type"] == "replication_conflicts"
    assert "server" in data
    assert "conflicts" in data
    assert isinstance(data["conflicts"], list)
    assert "glue_entries" in data
    assert isinstance(data["glue_entries"], list)


async def test_list_replication_conflicts_with_base_dn(dirsrv_server: DirSrvMCP):
    """Test list_replication_conflicts with specific base_dn."""
    async with Client(dirsrv_server) as client:
        result = await client.call_tool(
            "list_replication_conflicts",
            {"base_dn": "dc=test,dc=com"}
        )
        data = result.data

    assert data["type"] == "replication_conflicts"
    # Should have checked our specific suffix
    if "suffixes_checked" in data:
        assert "dc=test,dc=com" in data["suffixes_checked"]


async def test_get_agreement_status_returns_valid_structure(dirsrv_server: DirSrvMCP):
    """Test that get_agreement_status returns expected structure."""
    async with Client(dirsrv_server) as client:
        result = await client.call_tool("get_agreement_status", {})
        data = result.data

    assert "type" in data
    assert data["type"] == "agreement_status"
    assert "server" in data
    assert "agreements" in data
    assert isinstance(data["agreements"], list)


async def test_get_agreement_status_with_filters(dirsrv_server: DirSrvMCP):
    """Test get_agreement_status with name and suffix filters."""
    async with Client(dirsrv_server) as client:
        result = await client.call_tool(
            "get_agreement_status",
            {
                "suffix": "dc=test,dc=com",
            }
        )
        data = result.data

    assert data["type"] == "agreement_status"
    # If replication is configured, filter should be recorded
    # If no replication, the filter field may not be present
    if "filter" in data:
        assert data["filter"].get("suffix") == "dc=test,dc=com"


async def test_replication_tools_handle_no_replication_gracefully(dirsrv_server: DirSrvMCP):
    """Test that replication tools handle servers without replication configured."""
    async with Client(dirsrv_server) as client:
        # All these should return valid responses even without replication
        tools = [
            ("get_replication_status", {}),
            ("get_replication_topology", {}),
            ("check_replication_lag", {}),
            ("list_replication_conflicts", {}),
            ("get_agreement_status", {}),
        ]

        for tool_name, args in tools:
            result = await client.call_tool(tool_name, args)
            assert result is not None, f"{tool_name} returned None"
            data = result.data

            # Should not have error (or if error, should be informative)
            if "error" in data:
                # Error should be a string, not an exception
                assert isinstance(data["error"], str)
            else:
                # Should have valid type
                assert "type" in data


async def test_multiserver_replication_topology(dirsrv_multiserver: DirSrvMCP):
    """Test topology mapping across multiple servers."""
    async with Client(dirsrv_multiserver) as client:
        result = await client.call_tool("get_replication_topology", {})
        data = result.data

    assert data["type"] == "replication_topology"
    # Should have queried multiple servers
    assert "servers_checked" in data
    assert len(data["servers_checked"]) > 0


async def test_replication_status_findings_structure(dirsrv_server: DirSrvMCP):
    """Test that findings in replication status have correct structure."""
    async with Client(dirsrv_server) as client:
        result = await client.call_tool("get_replication_status", {})
        data = result.data

    if "findings" in data and data["findings"]:
        for finding in data["findings"]:
            # Each finding should have required fields
            assert "title" in finding
            assert "severity" in finding
            assert finding["severity"] in ["critical", "high", "medium", "low", "info"]
            # Should have remediation info
            if "remediation" in finding:
                assert isinstance(finding["remediation"], str)
