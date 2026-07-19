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
    from ldap_assistant_mcp.dirsrv_mcp.server import DirSrvMCP


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
    privacy mode is active, the error message is scrubbed for embedded
    paths, DNs, hostnames, and server names.  When debug mode is enabled
    on *mcp*, a ``"traceback"`` key is added with the full stack trace
    (scrubbed line-by-line when privacy mode is also active).  Exceptions
    carrying a ``try_instead`` attribute (mode errors such as
    ``LiveServerRequired``) contribute a ``"try_instead"`` key listing
    alternative tools that work in the server's mode.

    Extra keyword arguments are merged into the returned dict (e.g.
    ``server1=..., server2=...``).
    """
    result: Dict[str, Any] = {"type": type_str}
    privacy = getattr(mcp, "privacy_enabled", False)
    if server is not None:
        result["server"] = server
    result.update(extra)

    error_msg = format_error_message(exc)
    if privacy:
        error_msg = mcp.sanitizer.sanitize_text(error_msg)
    result["error"] = error_msg

    # Stable machine-readable classification so clients can branch
    # on failures without parsing prose.
    from ldap_assistant_mcp.lib.envelope import classify_exception

    error_code, category, retryable = classify_exception(exc)
    result["error_code"] = error_code
    result["category"] = category
    result["retryable"] = retryable

    # Mode errors (e.g. LiveServerRequired) carry alternative tool names so
    # LLM clients can continue on the same server.  Tool names are part of
    # the public schema, so they bypass the privacy scrub.
    try_instead = getattr(exc, "try_instead", None)
    if try_instead:
        result["try_instead"] = list(try_instead)

    if getattr(mcp, "debug_enabled", False):
        tb_lines = traceback.format_exception(type(exc), exc, exc.__traceback__)
        if privacy:
            # A verbatim traceback would leak the paths/DNs/hostnames that
            # were just scrubbed from the error text above.
            tb_lines = [mcp.sanitizer.sanitize_text(line) for line in tb_lines]
        result["traceback"] = tb_lines

    return result
