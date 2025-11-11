"""Result formatting utilities for LDAP Assistant MCP."""

import json
from enum import Enum
from typing import Any, Dict, List, Optional
from mcp.types import CallToolResult, TextContent


class Severity(Enum):
    """Severity levels for findings."""
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


def format_finding(
    title: str,
    severity: Severity,
    impact: str,
    details: str,
    remediation: str,
    server: Optional[str] = None,
    metadata: Optional[Dict[str, Any]] = None
) -> Dict[str, Any]:
    """
    Format a finding with severity, impact, and remediation guidance.

    This creates a standardized finding format that ensures consistency across
    all health checks and diagnostics. Each finding includes actionable
    information to help support engineers and administrators quickly resolve issues.

    Args:
        title: Short, descriptive title of the finding
        severity: Severity level (CRITICAL, HIGH, MEDIUM, LOW, INFO)
        impact: Description of what impact this has on the service/users
        details: Detailed explanation of what was found
        remediation: Concrete steps to resolve the issue
        server: Optional server identifier (for multi-server setups)
        metadata: Optional additional context/data about the finding

    Returns:
        Standardized finding dictionary

    Examples:
        >>> finding = format_finding(
        ...     title="Replication Agreement Down",
        ...     severity=Severity.CRITICAL,
        ...     impact="Data is not replicating to backup server",
        ...     details="Agreement to prod-ds2 has been down for 3 hours",
        ...     remediation="1. Check network connectivity 2. Verify credentials 3. Check logs"
        ... )
    """
    finding = {
        "title": title,
        "severity": severity.value,
        "impact": impact,
        "details": details,
        "remediation": remediation
    }

    if server:
        finding["server"] = server

    if metadata:
        finding["metadata"] = metadata

    return finding


def format_tool_result(
    result_type: str,
    data: Any,
    is_error: bool = False,
    error_message: Optional[str] = None
) -> CallToolResult:
    """
    Format a tool result in standard MCP format.

    Args:
        result_type: Type identifier for the result (e.g., "user_list", "health_check")
        data: The result data (will be JSON serialized)
        is_error: Whether this is an error result
        error_message: Error message if is_error=True

    Returns:
        CallToolResult ready to return from an MCP tool

    Examples:
        >>> result = format_tool_result("user_list", {"users": [...]})
        >>> error_result = format_tool_result(
        ...     "connection_error",
        ...     {},
        ...     is_error=True,
        ...     error_message="Failed to connect to LDAP server"
        ... )
    """
    if is_error:
        content_text = error_message or "Unknown error"
    else:
        response = {"type": result_type}
        if isinstance(data, dict):
            response.update(data)
        else:
            response["data"] = data
        content_text = json.dumps(response, indent=2)

    return CallToolResult(
        isError=is_error,
        content=[TextContent(type="text", text=content_text)]
    )
