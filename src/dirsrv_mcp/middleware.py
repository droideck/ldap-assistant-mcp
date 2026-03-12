"""Cross-cutting middleware for the 389 DS MCP server.

Three middlewares that wrap every tool call:

- LoggingMiddleware: logs tool invocations (name + status only, no args).
- TimeoutMiddleware: enforces per-call time limits with per-tool overrides.
- ResponseSizeMiddleware: truncates oversized responses with a notice.
"""

from __future__ import annotations

import asyncio
import logging
from typing import Any, Dict, Optional

from fastmcp.exceptions import ToolError
from fastmcp.server.middleware import Middleware

logger = logging.getLogger(__name__)


class LoggingMiddleware(Middleware):
    """Log tool call start / end without leaking arguments or results."""

    async def on_call_tool(self, context, call_next):
        tool_name = context.message.name
        logger.info("tool_call_start tool=%s", tool_name)
        try:
            result = await call_next(context)
            logger.info("tool_call_end tool=%s status=ok", tool_name)
            return result
        except Exception as exc:
            logger.error(
                "tool_call_error tool=%s error_type=%s",
                tool_name,
                type(exc).__name__,
            )
            raise


class TimeoutMiddleware(Middleware):
    """Enforce a per-tool-call timeout.

    Supports per-tool overrides via the ``tool_timeouts`` dict, which
    maps tool names to their custom timeout in seconds.  Any override
    is still capped at ``max_timeout``.

    On timeout the wrapped task is cancelled.  A brief grace period
    (``cleanup_grace``) is given for the task to handle
    ``CancelledError`` and release resources (e.g. close LDAP
    connections, remove temp files) before the error is raised to the
    caller.
    """

    def __init__(
        self,
        default_timeout: float = 30.0,
        max_timeout: float = 120.0,
        tool_timeouts: Optional[Dict[str, float]] = None,
        cleanup_grace: float = 5.0,
    ):
        self.default_timeout = default_timeout
        self.max_timeout = max_timeout
        self.tool_timeouts: Dict[str, float] = tool_timeouts or {}
        self.cleanup_grace = cleanup_grace

    async def on_call_tool(self, context, call_next):
        tool_name = context.message.name
        requested = self.tool_timeouts.get(tool_name, self.default_timeout)
        timeout = min(requested, self.max_timeout)

        task = asyncio.ensure_future(call_next(context))
        try:
            return await asyncio.wait_for(
                asyncio.shield(task), timeout=timeout,
            )
        except asyncio.TimeoutError:
            logger.error("tool_timeout tool=%s timeout=%.1f", tool_name, timeout)
            task.cancel()
            try:
                await asyncio.wait_for(task, timeout=self.cleanup_grace)
            except (asyncio.TimeoutError, asyncio.CancelledError):
                pass
            raise ToolError(f"Operation timed out after {timeout}s")


class ResponseSizeMiddleware(Middleware):
    """Guard against oversized tool responses that could overload LLM context."""

    def __init__(self, max_chars: int = 100_000):
        self.max_chars = max_chars

    async def on_call_tool(self, context, call_next):
        result = await call_next(context)
        return self._guard(result)

    def _guard(self, result: Any) -> Any:
        """Truncate text content blocks that exceed the character limit.

        Rebuilds content items instead of mutating in-place, since MCP SDK
        content objects may be frozen Pydantic models.
        """
        if not hasattr(result, "content") or not isinstance(result.content, list):
            return result

        new_content = []
        changed = False
        for item in result.content:
            if hasattr(item, "text") and isinstance(item.text, str) and len(item.text) > self.max_chars:
                truncated_text = (
                    item.text[: self.max_chars]
                    + f"\n\n[TRUNCATED — response exceeded {self.max_chars} characters]"
                )
                try:
                    new_content.append(item.model_copy(update={"text": truncated_text}))
                except (AttributeError, TypeError):
                    item.text = truncated_text
                    new_content.append(item)
                changed = True
            else:
                new_content.append(item)

        if changed:
            try:
                result = result.model_copy(update={"content": new_content})
            except (AttributeError, TypeError):
                result.content = new_content
        return result
