"""Tests for index analysis tools.

These tests verify the index analysis tools work correctly against
389 Directory Server instances.
"""

from __future__ import annotations

import pytest
from fastmcp import Client

from ldap_assistant_mcp.dirsrv_mcp.server import DirSrvMCP

# Every test in this module drives live LDAP tools against a running DS
# instance — deselect without containers via `pytest -m "not live"`.
pytestmark = [pytest.mark.asyncio, pytest.mark.live]


# list_indexes tests


async def test_list_indexes_returns_valid_structure(dirsrv_server: DirSrvMCP):
    """Test that list_indexes returns expected structure."""
    async with Client(dirsrv_server) as client:
        result = await client.call_tool("list_indexes", {})
        data = result.data

    assert "type" in data
    assert data["type"] == "index_list"
    assert "server" in data
    assert "backends" in data
    assert isinstance(data["backends"], list)


async def test_list_indexes_includes_summary(dirsrv_server: DirSrvMCP):
    """Test that list_indexes includes summary statistics."""
    async with Client(dirsrv_server) as client:
        result = await client.call_tool("list_indexes", {})
        data = result.data

    assert "summary" in data
    summary = data["summary"]
    assert "total_indexes" in summary
    assert "user_indexes" in summary
    assert "system_indexes" in summary
    assert "backends_checked" in summary


async def test_list_indexes_with_backend_filter(dirsrv_server: DirSrvMCP):
    """Test list_indexes with specific backend filter."""
    async with Client(dirsrv_server) as client:
        result = await client.call_tool("list_indexes", {"backend": "userroot"})
        data = result.data

    assert data["type"] == "index_list"
    # Should only have the filtered backend (or empty if not found)
    for backend in data["backends"]:
        assert backend["name"].lower() == "userroot"


async def test_list_indexes_has_index_details(dirsrv_server: DirSrvMCP):
    """Test that indexes have proper detail structure."""
    async with Client(dirsrv_server) as client:
        result = await client.call_tool("list_indexes", {})
        data = result.data

    if data["backends"] and data["backends"][0].get("indexes"):
        idx = data["backends"][0]["indexes"][0]
        assert "attribute" in idx
        assert "types" in idx
        assert "is_system" in idx
        assert "types_description" in idx


async def test_list_indexes_includes_backend_info(dirsrv_server: DirSrvMCP):
    """Test that backend information is included."""
    async with Client(dirsrv_server) as client:
        result = await client.call_tool("list_indexes", {})
        data = result.data

    if data["backends"]:
        backend = data["backends"][0]
        assert "name" in backend
        assert "suffix" in backend
        assert "indexes" in backend
        assert "vlv_indexes" in backend


# analyze_index_configuration tests


async def test_analyze_index_configuration_returns_valid_structure(
    dirsrv_server: DirSrvMCP,
):
    """Test that analyze_index_configuration returns expected structure."""
    async with Client(dirsrv_server) as client:
        result = await client.call_tool("analyze_index_configuration", {})
        data = result.data

    assert "type" in data
    assert data["type"] == "index_analysis"
    assert "server" in data
    assert "backends" in data
    assert "findings" in data
    assert isinstance(data["findings"], list)


async def test_analyze_index_configuration_includes_status(dirsrv_server: DirSrvMCP):
    """Test that analysis includes status and summary."""
    async with Client(dirsrv_server) as client:
        result = await client.call_tool("analyze_index_configuration", {})
        data = result.data

    assert "status" in data
    assert data["status"] in ["healthy", "fair", "warning", "unknown"]
    assert "summary" in data


async def test_analyze_index_configuration_includes_recommendations(
    dirsrv_server: DirSrvMCP,
):
    """Test that analysis includes recommendations."""
    async with Client(dirsrv_server) as client:
        result = await client.call_tool("analyze_index_configuration", {})
        data = result.data

    assert "recommendations" in data
    assert isinstance(data["recommendations"], list)


async def test_analyze_index_configuration_with_backend_filter(
    dirsrv_server: DirSrvMCP,
):
    """Test analyze_index_configuration with specific backend."""
    async with Client(dirsrv_server) as client:
        result = await client.call_tool(
            "analyze_index_configuration", {"backend": "userroot"}
        )
        data = result.data

    assert data["type"] == "index_analysis"
    for backend in data["backends"]:
        assert backend["name"].lower() == "userroot"


async def test_analyze_index_configuration_backend_has_analysis(
    dirsrv_server: DirSrvMCP,
):
    """Test that backend analysis includes expected fields."""
    async with Client(dirsrv_server) as client:
        result = await client.call_tool("analyze_index_configuration", {})
        data = result.data

    if data["backends"]:
        backend = data["backends"][0]
        assert "name" in backend
        assert "suffix" in backend
        assert "current_index_count" in backend
        assert "missing_recommended" in backend
        assert "incomplete_indexes" in backend


async def test_analyze_index_configuration_missing_has_dsconf_command(
    dirsrv_server: DirSrvMCP,
):
    """Test that missing indexes include dsconf commands."""
    async with Client(dirsrv_server) as client:
        result = await client.call_tool("analyze_index_configuration", {})
        data = result.data

    for backend in data["backends"]:
        for missing in backend.get("missing_recommended", []):
            assert "dsconf_command" in missing
            assert "dsconf" in missing["dsconf_command"]
            assert "attribute" in missing
            assert "recommended_types" in missing


# find_unindexed_searches tests


async def test_find_unindexed_searches_returns_valid_structure(
    dirsrv_server: DirSrvMCP,
):
    """Test that find_unindexed_searches returns expected structure."""
    async with Client(dirsrv_server) as client:
        result = await client.call_tool("find_unindexed_searches", {})
        data = result.data

    assert "type" in data
    assert data["type"] == "unindexed_searches"
    # Either has results or error (for remote servers)
    assert "server" in data or "error" in data


async def test_find_unindexed_searches_handles_remote_server(dirsrv_server: DirSrvMCP):
    """Test that find_unindexed_searches handles remote servers gracefully."""
    async with Client(dirsrv_server) as client:
        result = await client.call_tool("find_unindexed_searches", {})
        data = result.data

    assert data["type"] == "unindexed_searches"
    # For remote servers, should return error about local requirement
    # For local servers, should return actual results
    if "error" in data:
        assert "local" in data["error"].lower() or "local" in data.get(
            "details", ""
        ).lower()
    else:
        # Local server - should have proper structure
        assert "summary" in data
        assert "status" in data
        assert "patterns" in data


async def test_find_unindexed_searches_accepts_time_range(dirsrv_server: DirSrvMCP):
    """Test that find_unindexed_searches accepts time_range parameter."""
    async with Client(dirsrv_server) as client:
        result = await client.call_tool(
            "find_unindexed_searches", {"time_range": "24h"}
        )
        data = result.data

    assert data["type"] == "unindexed_searches"
    # If successful (local server), time_range should be reflected
    if "time_range" in data:
        assert data["time_range"] == "24h"


async def test_find_unindexed_searches_accepts_limit(dirsrv_server: DirSrvMCP):
    """Test that find_unindexed_searches accepts limit parameter."""
    async with Client(dirsrv_server) as client:
        result = await client.call_tool("find_unindexed_searches", {"limit": 10})
        data = result.data

    assert data["type"] == "unindexed_searches"
    # If patterns are returned, should be limited
    if "patterns" in data:
        assert len(data["patterns"]) <= 10


async def test_find_unindexed_searches_findings_structure(dirsrv_server: DirSrvMCP):
    """Test that findings have proper structure when present."""
    async with Client(dirsrv_server) as client:
        result = await client.call_tool("find_unindexed_searches", {})
        data = result.data

    if "findings" in data:
        assert isinstance(data["findings"], list)
        for finding in data["findings"]:
            assert "title" in finding
            assert "severity" in finding
            assert "impact" in finding
            assert "remediation" in finding
