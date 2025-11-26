"""Tests for monitoring tools.

Following FastMCP testing patterns:
- Each test verifies exactly one behavior
- Tests are self-contained and can run in any order
- Use in-memory transport via Client(server) pattern
"""

from __future__ import annotations

import pytest
from fastmcp import Client

pytestmark = pytest.mark.asyncio


async def test_run_monitor_returns_monitor_data(dirsrv_server):
    """Test that run_monitor returns server monitor data."""
    async with Client(dirsrv_server) as client:
        result = await client.call_tool("run_monitor", {})
        data = result.data

        assert data["type"] == "monitor", "Response type should be 'monitor'"
        assert "item" in data, "Response should contain 'item'"
        assert "attrs" in data["item"], "Monitor item should contain 'attrs'"


async def test_run_monitor_includes_version_info(dirsrv_server):
    """Test that run_monitor includes 389 Directory Server version."""
    async with Client(dirsrv_server) as client:
        result = await client.call_tool("run_monitor", {})
        data = result.data

        attrs = data["item"]["attrs"]
        assert "version" in attrs, "Monitor should include version attribute"
        version = attrs["version"][0] if isinstance(attrs["version"], list) else attrs["version"]
        assert version.startswith("389-Directory"), (
            f"Version should start with '389-Directory', got: {version}"
        )


async def test_run_monitor_includes_thread_info(dirsrv_server):
    """Test that run_monitor includes thread information."""
    async with Client(dirsrv_server) as client:
        result = await client.call_tool("run_monitor", {})
        data = result.data

        attrs = data["item"]["attrs"]
        assert "threads" in attrs, "Monitor should include threads attribute"


async def test_run_monitor_includes_backend_count(dirsrv_server):
    """Test that run_monitor includes backend count."""
    async with Client(dirsrv_server) as client:
        result = await client.call_tool("run_monitor", {})
        data = result.data

        attrs = data["item"]["attrs"]
        assert "nbackends" in attrs, "Monitor should include nbackends attribute"


async def test_run_monitor_includes_connection_count(dirsrv_server):
    """Test that run_monitor includes connection statistics."""
    async with Client(dirsrv_server) as client:
        result = await client.call_tool("run_monitor", {})
        data = result.data

        attrs = data["item"]["attrs"]
        assert "totalconnections" in attrs, "Monitor should include totalconnections attribute"


async def test_run_monitor_with_backend_returns_backend_info(dirsrv_server):
    """Test that run_monitor with backend parameter returns backend-specific data."""
    async with Client(dirsrv_server) as client:
        result = await client.call_tool("run_monitor", {"backend": "userroot"})
        data = result.data

        assert data["type"] == "monitor", "Response type should be 'monitor'"
        assert data["backend"] == "userroot", "Backend name should be preserved"

        attrs = data["item"]["attrs"]
        assert "database" in attrs, "Backend monitor should include database attribute"

        database = attrs["database"][0] if isinstance(attrs["database"], list) else attrs["database"]
        assert database == "ldbm database", f"Database should be 'ldbm database', got: {database}"


async def test_run_monitor_with_backend_includes_cache_info(dirsrv_server):
    """Test that backend monitor includes cache statistics."""
    async with Client(dirsrv_server) as client:
        result = await client.call_tool("run_monitor", {"backend": "userroot"})
        data = result.data

        attrs = data["item"]["attrs"]
        assert "entrycachehits" in attrs, "Backend monitor should include entrycachehits"


async def test_run_monitor_with_suffix_returns_backend_info(dirsrv_server):
    """Test that run_monitor with suffix parameter returns backend-specific data."""
    async with Client(dirsrv_server) as client:
        result = await client.call_tool("run_monitor", {"suffix": "dc=test,dc=com"})
        data = result.data

        assert data["type"] == "monitor", "Response type should be 'monitor'"

        attrs = data["item"]["attrs"]
        assert "database" in attrs, "Backend monitor should include database attribute"

