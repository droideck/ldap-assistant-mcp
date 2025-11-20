"""Shared helpers for invoking FastMCP tools in tests."""

from __future__ import annotations

from typing import Any, Dict

from fastmcp import Client


async def call_tool(server, tool_name: str, **arguments: Any) -> Any:
    """Invoke a tool through the official FastMCP client interface."""

    async with Client(server) as client:
        return await client.call_tool(tool_name, arguments)

