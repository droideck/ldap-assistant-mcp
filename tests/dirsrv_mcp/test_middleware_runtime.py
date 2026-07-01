"""Runtime behavior tests for the middleware stack (IMPROVEMENT-PLAN 1.5.3).

The arithmetic (per-tool overrides, caps) is covered in test_middleware.py;
these tests exercise the middleware at runtime through a real client:

- TimeoutMiddleware actually cancels a slow async tool.
- ResponseSizeMiddleware replaces oversized structured content with a small
  valid payload and truncates oversized text content.
- LoggingMiddleware emits start/end records for tool calls.
"""

from __future__ import annotations

import asyncio
import logging
import os
from typing import Any, Dict
from unittest.mock import patch

import pytest
from fastmcp import Client
from fastmcp.exceptions import ToolError

from ldap_assistant_mcp.core import LDAPServerConfig, MCPSettings
from ldap_assistant_mcp.dirsrv_mcp.server import DirSrvMCP


def _make_server(**settings_kwargs) -> DirSrvMCP:
    config = LDAPServerConfig(
        name="mw-test",
        hostname="localhost",
        port=33891,
        base_dn="dc=example,dc=com",
    )
    env = {k: v for k, v in os.environ.items() if k != "LDAP_SERVERS_CONFIG"}
    with patch.dict(os.environ, env, clear=True):
        return DirSrvMCP(
            servers=[config],
            include_env_fallback=False,
            settings=MCPSettings(expose_sensitive_data=True, **settings_kwargs),
        )


@pytest.mark.asyncio
async def test_timeout_middleware_cancels_slow_async_tool():
    server = _make_server(tool_timeout=0.2, max_tool_timeout=0.5)

    @server.tool
    async def sleepy_tool() -> Dict[str, Any]:
        """Sleep far beyond the configured timeout."""
        await asyncio.sleep(5)
        return {"done": True}

    async with Client(server) as client:
        with pytest.raises(ToolError, match="timed out"):
            await client.call_tool("sleepy_tool", {})


@pytest.mark.asyncio
async def test_timeout_middleware_leaves_fast_tools_alone():
    server = _make_server(tool_timeout=5.0)

    @server.tool
    async def quick_tool() -> Dict[str, Any]:
        """Return instantly."""
        return {"done": True}

    async with Client(server) as client:
        result = await client.call_tool("quick_tool", {})
        assert result.data["done"] is True


@pytest.mark.asyncio
async def test_response_size_middleware_replaces_oversized_structured_content():
    server = _make_server()

    @server.tool
    async def huge_tool() -> Dict[str, Any]:
        """Return a payload far over the 100k character limit."""
        return {"blob": "x" * 300_000}

    async with Client(server) as client:
        result = await client.call_tool("huge_tool", {})
        data = result.data

    # The structured channel must hold the small replacement payload,
    # not 300k of data and not invalid JSON.
    assert data["truncated"] is True
    assert data["error"] == "response too large"
    assert "hint" in data
    assert "blob" not in data


@pytest.mark.asyncio
async def test_response_size_middleware_truncates_oversized_text_content():
    server = _make_server()

    @server.tool
    async def huge_text_tool() -> Dict[str, Any]:
        """Return a payload whose serialized text exceeds the limit."""
        return {"blob": "y" * 300_000}

    async with Client(server) as client:
        result = await client.call_tool_mcp("huge_text_tool", {})
        text = result.content[0].text

    assert len(text) < 300_000
    assert "[TRUNCATED" in text


@pytest.mark.asyncio
async def test_small_responses_pass_through_unmodified():
    server = _make_server()

    @server.tool
    async def small_tool() -> Dict[str, Any]:
        """Return a small payload."""
        return {"value": 42}

    async with Client(server) as client:
        result = await client.call_tool("small_tool", {})
        assert result.data == {"value": 42}


@pytest.mark.asyncio
async def test_logging_middleware_emits_start_and_end_records(caplog):
    server = _make_server()
    logger_name = "ldap_assistant_mcp.dirsrv_mcp.middleware"

    with caplog.at_level(logging.INFO, logger=logger_name):
        async with Client(server) as client:
            await client.call_tool("server_health", {})

    messages = [r.getMessage() for r in caplog.records if r.name == logger_name]
    assert any("tool_call_start tool=server_health" in m for m in messages)
    assert any("tool_call_end tool=server_health status=ok" in m for m in messages)


@pytest.mark.asyncio
async def test_logging_middleware_logs_errors_with_type_only(caplog):
    server = _make_server()
    logger_name = "ldap_assistant_mcp.dirsrv_mcp.middleware"

    @server.tool
    async def failing_tool() -> Dict[str, Any]:
        """Raise an error carrying sensitive-looking detail."""
        raise RuntimeError("secret-hostname.example.com exploded")

    with caplog.at_level(logging.INFO, logger=logger_name):
        async with Client(server) as client:
            with pytest.raises(ToolError):
                await client.call_tool("failing_tool", {})

    error_msgs = [
        r.getMessage() for r in caplog.records
        if r.name == logger_name and "tool_call_error" in r.getMessage()
    ]
    assert error_msgs, "expected a tool_call_error record"
    # Only the exception TYPE is logged — never the message text.
    # (FastMCP wraps tool exceptions in ToolError before middleware sees
    # them, so the recorded type is ToolError, not RuntimeError.)
    assert all("secret-hostname" not in m for m in error_msgs)
    assert any("error_type=" in m for m in error_msgs)
