"""Opaque cursor pagination for list-shaped tool results.

LDAP has no server-side "skip", and per-call connection lifecycles mean
RFC 2696 paged-results cookies cannot survive between tool calls — so
cursors encode a plain offset over a deterministic iteration. The fetch
itself is still bounded by the caller's iteration (entries are consumed
lazily up to ``offset + limit + 1``), and results are never silently cut:
``has_more`` / ``next_cursor`` always say whether another page exists.
"""

from __future__ import annotations

import base64
from typing import Any, Iterable, Iterator, List, Optional, Tuple

from fastmcp.exceptions import ToolError


def decode_cursor(cursor: Optional[str]) -> int:
    """Decode an opaque cursor into an offset. Raises ToolError on garbage."""
    if not cursor:
        return 0
    try:
        decoded = base64.b64decode(cursor.encode("ascii"), validate=True).decode("utf-8")
        if decoded.startswith("o:"):
            offset = int(decoded[2:])
            if offset >= 0:
                return offset
    except (ValueError, UnicodeDecodeError):
        pass
    raise ToolError(
        "Invalid cursor. Pass the 'next_cursor' value from the previous "
        "page unmodified, or omit it to start from the beginning."
    )


def encode_cursor(offset: int) -> str:
    """Encode an offset as an opaque cursor."""
    return base64.b64encode(f"o:{offset}".encode("utf-8")).decode("ascii")


def paginate(
    entries: Iterable[Any], offset: int, limit: int
) -> Tuple[List[Any], bool, Optional[str]]:
    """Take one page from *entries*.

    Returns ``(page_items, has_more, next_cursor)``. Consumes at most
    ``offset + limit + 1`` items from the iterable (lazy iterables are
    not fully drained).
    """
    iterator: Iterator[Any] = iter(entries)
    for _ in range(offset):
        try:
            next(iterator)
        except StopIteration:
            return [], False, None

    page: List[Any] = []
    for item in iterator:
        if len(page) >= limit:
            return page, True, encode_cursor(offset + limit)
        page.append(item)
    return page, False, None
