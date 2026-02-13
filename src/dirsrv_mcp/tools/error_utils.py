"""Error formatting utilities for tool error responses.

Provides two helpers:

- ``format_error_message(exc)`` — always includes exception type:
  ``"IndexError: list index out of range"`` instead of bare ``"list index out of range"``.

- ``format_tool_error(exc, mcp, type_str, server=None, **extra)`` — builds
  a complete error dict suitable for returning from a tool.  Adds a
  ``"traceback"`` key when debug mode is enabled.
"""

from __future__ import annotations

import traceback
from typing import TYPE_CHECKING, Any, Dict, Optional

if TYPE_CHECKING:
    from src.dirsrv_mcp.server import DirSrvMCP


def format_error_message(exc: BaseException) -> str:
    """Format an exception with its type name.

    Returns ``"TypeError: unsupported operand"`` instead of
    ``"unsupported operand"``.
    """
    return f"{type(exc).__name__}: {exc}"


def format_tool_error(
    exc: BaseException,
    mcp: "DirSrvMCP",
    type_str: str,
    server: Optional[str] = None,
    **extra: Any,
) -> Dict[str, Any]:
    """Build a standard error dict for tool responses.

    Always includes the exception type in the ``"error"`` value.  When
    debug mode is enabled on *mcp*, a ``"traceback"`` key is added with
    the full stack trace.

    Extra keyword arguments are merged into the returned dict (e.g.
    ``server1=..., server2=...``).
    """
    result: Dict[str, Any] = {"type": type_str}
    if server is not None:
        result["server"] = server
    result.update(extra)
    result["error"] = format_error_message(exc)

    if getattr(mcp, "debug_enabled", False):
        result["traceback"] = traceback.format_exception(type(exc), exc, exc.__traceback__)

    return result
