"""DateTime conversion utilities for LDAP Assistant MCP."""

from datetime import datetime
from typing import Any, Dict, List


def convert_datetimes_to_strings(data: Any) -> Any:
    """
    Recursively convert datetime objects in dicts/lists to ISO strings.

    LDAP attributes often contain datetime objects that need to be serialized
    to JSON. This function walks through nested structures and converts all
    datetime objects to ISO 8601 format strings.

    Args:
        data: Any data structure (dict, list, datetime, or primitive)

    Returns:
        The same structure with all datetime objects converted to strings

    Examples:
        >>> from datetime import datetime
        >>> data = {'created': datetime(2024, 1, 1, 12, 0), 'count': 5}
        >>> convert_datetimes_to_strings(data)
        {'created': '2024-01-01T12:00:00', 'count': 5}
    """
    if isinstance(data, dict):
        return {k: convert_datetimes_to_strings(v) for k, v in data.items()}
    elif isinstance(data, list):
        return [convert_datetimes_to_strings(i) for i in data]
    elif isinstance(data, datetime):
        return data.isoformat()
    return data
