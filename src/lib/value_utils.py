"""Safe value conversion and formatting utilities."""

from typing import Any


def safe_int(value: Any, default: int = 0) -> int:
    """Convert value to int with fallback.

    Handles None, lists (extracts first element), and invalid strings.
    Returns default on any conversion failure.
    """
    if value is None:
        return default
    if isinstance(value, list):
        value = value[0] if value else default
    try:
        return int(value)
    except (ValueError, TypeError):
        return default


def safe_float(value: Any, default: float = 0.0) -> float:
    """Convert value to float with fallback.

    Handles None, lists (extracts first element), and invalid strings.
    Returns default on any conversion failure.
    """
    if value is None:
        return default
    if isinstance(value, list):
        value = value[0] if value else default
    try:
        return float(value)
    except (ValueError, TypeError):
        return default


def format_bytes(bytes_val: int) -> str:
    """Format bytes as human-readable string (KB, MB, GB, TB)."""
    if bytes_val < 0:
        return "0 B"
    for unit in ["B", "KB", "MB", "GB", "TB"]:
        if bytes_val < 1024:
            return f"{bytes_val:.1f} {unit}" if unit != "B" else f"{bytes_val} B"
        bytes_val /= 1024
    return f"{bytes_val:.1f} PB"
