"""Parsing helpers for 389 Directory Server dsDisk monitor values.

lib389's ``MonitorDiskSpace.get_disks()`` returns the raw ``dsDisk``
attribute values from ``cn=disk space,cn=monitor``. Each value is a
space-separated list of quoted key/value pairs, e.g.::

    partition="/" size="52521566208" used="9837719552" available="42683846656" use%="18"

Note the real attribute keys are ``available`` and ``use%`` (not ``avail``
or ``percent``).
"""

from __future__ import annotations

import re
from typing import Any, Dict

from ldap_assistant_mcp.lib.value_utils import safe_int

# Matches key="value" pairs (quoted values may contain spaces) and
# tolerates unquoted values as a fallback.
_DSDISK_PAIR_RE = re.compile(r'(\S+?)=(?:"([^"]*)"|(\S+))')


def parse_dsdisk_entry(value: str) -> Dict[str, Any]:
    """Parse a single dsDisk attribute value into a dictionary.

    Args:
        value: Raw dsDisk string from lib389 ``MonitorDiskSpace.get_disks()``.

    Returns:
        Dict with keys ``partition``, ``size``, ``used``, ``available``
        (raw string values, ``"unknown"`` when missing) and ``use_percent``
        (int, 0 when missing or unparseable).
    """
    raw: Dict[str, str] = {}
    for match in _DSDISK_PAIR_RE.finditer(value or ""):
        key = match.group(1).lower()
        val = match.group(2) if match.group(2) is not None else match.group(3)
        raw[key] = val

    return {
        "partition": raw.get("partition", "unknown"),
        "size": raw.get("size", "unknown"),
        "used": raw.get("used", "unknown"),
        "available": raw.get("available", "unknown"),
        "use_percent": safe_int(raw.get("use%")),
    }
