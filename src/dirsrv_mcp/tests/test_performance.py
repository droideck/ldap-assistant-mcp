"""Tests for performance diagnostic tools.

These tests verify the performance tools work correctly against
389 Directory Server instances.
"""

from __future__ import annotations

import pytest
from fastmcp import Client

from src.dirsrv_mcp.server import DirSrvMCP

pytestmark = pytest.mark.asyncio


async def test_get_cache_statistics_returns_valid_structure(dirsrv_server: DirSrvMCP):
    """Test that get_cache_statistics returns expected structure."""
    async with Client(dirsrv_server) as client:
        result = await client.call_tool("get_cache_statistics", {})
        data = result.data

    assert "type" in data
    assert data["type"] == "cache_statistics"
    assert "server" in data
    assert "backends" in data
    assert isinstance(data["backends"], list)


async def test_get_cache_statistics_with_backend_filter(dirsrv_server: DirSrvMCP):
    """Test get_cache_statistics with specific backend."""
    async with Client(dirsrv_server) as client:
        result = await client.call_tool(
            "get_cache_statistics",
            {"backend": "userroot"}
        )
        data = result.data

    assert data["type"] == "cache_statistics"
    # Should have filtered to specific backend (or empty if not found)
    assert isinstance(data["backends"], list)


async def test_get_cache_statistics_includes_cache_metrics(dirsrv_server: DirSrvMCP):
    """Test that cache statistics includes expected metrics."""
    async with Client(dirsrv_server) as client:
        result = await client.call_tool("get_cache_statistics", {})
        data = result.data

    # Should have global db cache or an error
    assert "global_db_cache" in data

    # If we have backends, check their structure
    if data["backends"]:
        for backend in data["backends"]:
            if "error" not in backend:
                assert "name" in backend
                if "entry_cache" in backend:
                    entry_cache = backend["entry_cache"]
                    assert "hits" in entry_cache
                    assert "tries" in entry_cache
                    assert "hit_ratio" in entry_cache


async def test_get_connection_statistics_returns_valid_structure(dirsrv_server: DirSrvMCP):
    """Test that get_connection_statistics returns expected structure."""
    async with Client(dirsrv_server) as client:
        result = await client.call_tool("get_connection_statistics", {})
        data = result.data

    assert "type" in data
    assert data["type"] == "connection_statistics"
    assert "server" in data
    assert "current_connections" in data
    assert "max_file_descriptors" in data
    assert "fd_utilization_pct" in data


async def test_get_connection_statistics_includes_states(dirsrv_server: DirSrvMCP):
    """Test that connection statistics includes state breakdown."""
    async with Client(dirsrv_server) as client:
        result = await client.call_tool("get_connection_statistics", {})
        data = result.data

    # Should have connection states
    if "connection_states" in data:
        states = data["connection_states"]
        assert "established" in states
        assert "close_wait" in states
        assert "time_wait" in states


async def test_get_operation_statistics_returns_valid_structure(dirsrv_server: DirSrvMCP):
    """Test that get_operation_statistics returns expected structure."""
    async with Client(dirsrv_server) as client:
        result = await client.call_tool("get_operation_statistics", {})
        data = result.data

    assert "type" in data
    assert data["type"] == "operation_statistics"
    assert "server" in data
    assert "operations_initiated" in data
    assert "operations_completed" in data
    assert "operations_pending" in data


async def test_get_operation_statistics_includes_breakdown(dirsrv_server: DirSrvMCP):
    """Test that operation statistics includes type breakdown."""
    async with Client(dirsrv_server) as client:
        result = await client.call_tool("get_operation_statistics", {})
        data = result.data

    # Should have operation breakdown (from SNMP stats)
    if "operation_breakdown" in data and "error" not in data["operation_breakdown"]:
        breakdown = data["operation_breakdown"]
        if "binds" in breakdown:
            assert "anonymous" in breakdown["binds"]
            assert "simple" in breakdown["binds"]
        if "searches" in breakdown:
            assert "total" in breakdown["searches"]


async def test_get_thread_statistics_returns_valid_structure(dirsrv_server: DirSrvMCP):
    """Test that get_thread_statistics returns expected structure."""
    async with Client(dirsrv_server) as client:
        result = await client.call_tool("get_thread_statistics", {})
        data = result.data

    assert "type" in data
    assert data["type"] == "thread_statistics"
    assert "server" in data
    assert "configured_threads" in data
    assert "connections_at_max_threads" in data


async def test_get_resource_utilization_returns_valid_structure(dirsrv_server: DirSrvMCP):
    """Test that get_resource_utilization returns expected structure."""
    async with Client(dirsrv_server) as client:
        result = await client.call_tool("get_resource_utilization", {})
        data = result.data

    assert "type" in data
    assert data["type"] == "resource_utilization"
    assert "server" in data


async def test_get_resource_utilization_includes_memory(dirsrv_server: DirSrvMCP):
    """Test that resource utilization includes memory metrics."""
    async with Client(dirsrv_server) as client:
        result = await client.call_tool("get_resource_utilization", {})
        data = result.data

    # Should have memory section
    if "memory" in data:
        memory = data["memory"]
        assert "rss" in memory
        assert "rss_human" in memory
        # Percent fields may be 0 if running remotely
        assert "rss_percent" in memory


async def test_get_resource_utilization_includes_cpu(dirsrv_server: DirSrvMCP):
    """Test that resource utilization includes CPU metrics."""
    async with Client(dirsrv_server) as client:
        result = await client.call_tool("get_resource_utilization", {})
        data = result.data

    # Should have CPU section
    if "cpu" in data:
        cpu = data["cpu"]
        assert "usage_percent" in cpu


async def test_get_performance_summary_returns_valid_structure(dirsrv_server: DirSrvMCP):
    """Test that get_performance_summary returns expected structure."""
    async with Client(dirsrv_server) as client:
        result = await client.call_tool("get_performance_summary", {})
        data = result.data

    assert "type" in data
    assert data["type"] == "performance_summary"
    assert "server" in data
    assert "overall_health" in data
    assert data["overall_health"] in ["healthy", "fair", "degraded", "critical"]
    assert "summary" in data
    assert "findings" in data
    assert isinstance(data["findings"], list)


async def test_get_performance_summary_includes_metrics(dirsrv_server: DirSrvMCP):
    """Test that performance summary includes key metrics."""
    async with Client(dirsrv_server) as client:
        result = await client.call_tool("get_performance_summary", {})
        data = result.data

    # Should have metrics section
    assert "metrics" in data
    metrics = data["metrics"]

    # Check for expected metric categories
    if "connections" in metrics:
        assert "current" in metrics["connections"]
    if "operations" in metrics:
        assert "completed" in metrics["operations"]
    if "resources" in metrics:
        assert "memory_pct" in metrics["resources"]


async def test_performance_tools_handle_errors_gracefully(dirsrv_server: DirSrvMCP):
    """Test that performance tools handle errors without crashing."""
    async with Client(dirsrv_server) as client:
        tools = [
            ("get_cache_statistics", {}),
            ("get_connection_statistics", {}),
            ("get_operation_statistics", {}),
            ("get_thread_statistics", {}),
            ("get_resource_utilization", {}),
            ("get_performance_summary", {}),
        ]

        for tool_name, args in tools:
            result = await client.call_tool(tool_name, args)
            assert result is not None, f"{tool_name} returned None"
            data = result.data

            # Should have valid type
            assert "type" in data, f"{tool_name} missing 'type' field"

            # If error occurred, it should be a string
            if "error" in data:
                assert isinstance(data["error"], str)


async def test_performance_findings_have_correct_structure(dirsrv_server: DirSrvMCP):
    """Test that findings in performance tools have correct structure."""
    async with Client(dirsrv_server) as client:
        result = await client.call_tool("get_performance_summary", {})
        data = result.data

    if "findings" in data and data["findings"]:
        for finding in data["findings"]:
            assert "title" in finding
            assert "severity" in finding
            assert finding["severity"] in ["critical", "high", "medium", "low", "info"]
            assert "impact" in finding
            assert "remediation" in finding


async def test_cache_statistics_with_server_name(dirsrv_server: DirSrvMCP):
    """Test get_cache_statistics with explicit server_name."""
    server_name = dirsrv_server.default_server
    async with Client(dirsrv_server) as client:
        result = await client.call_tool(
            "get_cache_statistics",
            {"server_name": server_name}
        )
        data = result.data

    assert data["type"] == "cache_statistics"
    assert data["server"] == server_name


async def test_multiserver_performance_summary(dirsrv_multiserver: DirSrvMCP):
    """Test performance summary works with multiple servers configured."""
    server_names = dirsrv_multiserver.connection_manager.get_server_names()

    async with Client(dirsrv_multiserver) as client:
        for server_name in server_names[:2]:  # Test first 2 servers
            result = await client.call_tool(
                "get_performance_summary",
                {"server_name": server_name}
            )
            data = result.data

            assert data["type"] == "performance_summary"
            assert data["server"] == server_name
