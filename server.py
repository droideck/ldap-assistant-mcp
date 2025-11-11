"""
LDAP Assistant MCP Server.

Multi-directory health and diagnostics assistant for LDAP environments.
Provides natural-language access to 389 Directory Server operations,
health checks, and multi-server monitoring.
"""

import os
import json
import logging
from typing import Optional
from mcp.server.fastmcp import FastMCP
from mcp.server.fastmcp.prompts import base
from mcp.types import CallToolResult, TextContent
from lib389.config import Config

# Import our modular components
from src.config.loader import load_config, initialize_connection_manager
from src.providers.dirsrv_mcp.tools import (
    list_all_users as _list_all_users,
    search_users_by_name as _search_users_by_name,
    get_user_details as _get_user_details,
    list_active_users as _list_active_users,
    list_locked_users as _list_locked_users,
    search_users_by_attribute as _search_users_by_attribute,
    list_all_groups as _list_all_groups,
    run_monitor as _run_monitor,
    ldap_search as _ldap_search,
)
from src.providers.dirsrv_mcp.health import first_look as _first_look
from src.providers.dirsrv_mcp.connection import get_connection
from src.lib.result_formatter import format_tool_result

# Set up logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# Create an MCP server
mcp = FastMCP("LDAP Assistant")

# Initialize configuration and connection manager
try:
    config = load_config()
    initialize_connection_manager(config)
    logger.info(f"Initialized with {len(config.servers)} server(s)")
except Exception as e:
    logger.warning(f"Failed to initialize multi-server config: {e}")
    logger.info("Will use single-server mode with environment variables")


@mcp.prompt(title="Tool Navigator")
def tool_navigator(goal: str) -> list[base.Message]:
    """Guide users through available tools and their usage."""
    return [
        base.UserMessage("Directory task:"),
        base.UserMessage(goal),
        base.AssistantMessage(
            (
                "Use the available MCP tools to accomplish the task. Prefer specialized tools first, "
                "falling back to ldap_search for advanced queries.\n\n"
                "**Health & Diagnostics:**\n"
                "- first_look: Quick health overview across all servers (RECOMMENDED for troubleshooting)\n\n"
                "**User Management:**\n"
                "- list_active_users / list_locked_users / list_all_users: enumerate users\n"
                "- search_users_by_name or search_users_by_attribute: find users\n"
                "- get_user_details: retrieve a specific user's details\n\n"
                "**Group Management:**\n"
                "- list_all_groups: view groups\n\n"
                "**Monitoring:**\n"
                "- run_monitor: check server/backend monitor\n\n"
                "**Advanced:**\n"
                "- ldap_search(base_dn, scope, filter, attributes, attrs_only, limit): custom queries\n\n"
                "**Resources:** config://config-all and config://config-attribute/{attribute} for cn=config.\n\n"
                "State which tool you'll call next and why; keep outputs concise."
            )
        ),
    ]


# ============================================================================
# HEALTH CHECK TOOLS
# ============================================================================

@mcp.tool()
def first_look() -> CallToolResult:
    """
    Quick health overview across all configured LDAP servers.

    This is the PRIMARY diagnostic tool for support engineers. It provides
    rapid assessment of the entire LDAP topology, identifying critical issues
    that require immediate attention. Use this FIRST when troubleshooting.

    The tool checks:
    - Server connectivity for all configured servers
    - Basic operational status
    - Critical resource indicators (connections, threads)
    - Identifies servers that are unreachable or degraded

    Returns:
        JSON containing:
            - summary: High-level health status
            - critical_count, high_count, etc.: Counts by severity
            - findings: Detailed findings with severity/impact/remediation
            - servers_checked: Successfully checked servers
            - servers_failed: Servers that couldn't be checked

    Examples:
        >>> # Check health of all servers
        >>> result = first_look()
        >>> # Returns summary like "CRITICAL: 2 critical issues found across 5 servers"
    """
    try:
        result = _first_look()
        return format_tool_result("first_look", result)
    except Exception as e:
        error_message = f"Error during first_look health check: {str(e)}"
        logger.error(error_message)
        return format_tool_result(
            "first_look_error",
            {},
            is_error=True,
            error_message=error_message
        )


# ============================================================================
# USER MANAGEMENT TOOLS
# ============================================================================

@mcp.tool()
def list_all_users(limit: int = 50) -> CallToolResult:
    """
    List all users in the directory.

    Args:
        limit: Maximum number of users to return (default: 50)

    Returns:
        JSON containing all user entries with computed status
    """
    try:
        result = _list_all_users(limit=limit)
        return CallToolResult(
            content=[TextContent(type="text", text=json.dumps(result, indent=2))]
        )
    except Exception as e:
        error_message = f"Error listing users: {str(e)}"
        logger.error(error_message)
        return CallToolResult(
            isError=True,
            content=[TextContent(type="text", text=error_message)]
        )


@mcp.tool()
def search_users_by_name(name: str, limit: int = 50) -> CallToolResult:
    """
    Search for users by name (uid, cn, givenName, sn, or displayName).

    Args:
        name: Name to search for (supports wildcards with *)
        limit: Maximum number of users to return (default: 50)

    Returns:
        JSON containing matching user entries
    """
    try:
        result = _search_users_by_name(name=name, limit=limit)
        return CallToolResult(
            content=[TextContent(type="text", text=json.dumps(result, indent=2))]
        )
    except Exception as e:
        error_message = f"Error searching users by name '{name}': {str(e)}"
        logger.error(error_message)
        return CallToolResult(
            isError=True,
            content=[TextContent(type="text", text=error_message)]
        )


@mcp.tool()
def get_user_details(username: str) -> CallToolResult:
    """
    Get detailed information about a specific user.

    Args:
        username: Username (uid) to get details for

    Returns:
        JSON containing detailed user information
    """
    try:
        result = _get_user_details(username=username)
        return CallToolResult(
            content=[TextContent(type="text", text=json.dumps(result, indent=2))]
        )
    except Exception as e:
        error_message = f"Error getting user details for '{username}': {str(e)}"
        logger.error(error_message)
        return CallToolResult(
            isError=True,
            content=[TextContent(type="text", text=error_message)]
        )


@mcp.tool()
def list_active_users(limit: int = 50) -> CallToolResult:
    """
    List all active (unlocked) users in the directory.

    Args:
        limit: Maximum number of users to return (default: 50)

    Returns:
        JSON containing active user entries
    """
    try:
        result = _list_active_users(limit=limit)
        return CallToolResult(
            content=[TextContent(type="text", text=json.dumps(result, indent=2))]
        )
    except Exception as e:
        error_message = f"Error listing active users: {str(e)}"
        logger.error(error_message)
        return CallToolResult(
            isError=True,
            content=[TextContent(type="text", text=error_message)]
        )


@mcp.tool()
def list_locked_users(limit: int = 50) -> CallToolResult:
    """
    List all locked users in the directory.

    Args:
        limit: Maximum number of users to return (default: 50)

    Returns:
        JSON containing locked user entries
    """
    try:
        result = _list_locked_users(limit=limit)
        return CallToolResult(
            content=[TextContent(type="text", text=json.dumps(result, indent=2))]
        )
    except Exception as e:
        error_message = f"Error listing locked users: {str(e)}"
        logger.error(error_message)
        return CallToolResult(
            isError=True,
            content=[TextContent(type="text", text=error_message)]
        )


@mcp.tool()
def search_users_by_attribute(attribute: str, value: str, limit: int = 50) -> CallToolResult:
    """
    Search for users by a specific attribute value.

    Args:
        attribute: LDAP attribute name to search (e.g., 'employeeType', 'department', 'title')
        value: Value to search for (supports wildcards with *)
        limit: Maximum number of users to return (default: 50)

    Returns:
        JSON containing matching user entries
    """
    try:
        result = _search_users_by_attribute(attribute=attribute, value=value, limit=limit)
        return CallToolResult(
            content=[TextContent(type="text", text=json.dumps(result, indent=2))]
        )
    except Exception as e:
        error_message = f"Error searching users by attribute {attribute}={value}: {str(e)}"
        logger.error(error_message)
        return CallToolResult(
            isError=True,
            content=[TextContent(type="text", text=error_message)]
        )


# ============================================================================
# GROUP MANAGEMENT TOOLS
# ============================================================================

@mcp.tool()
def list_all_groups(limit: int = 50) -> CallToolResult:
    """
    List all groups in the directory.

    Args:
        limit: Maximum number of groups to return (default: 50)

    Returns:
        JSON containing all group entries
    """
    try:
        result = _list_all_groups(limit=limit)
        return CallToolResult(
            content=[TextContent(type="text", text=json.dumps(result, indent=2))]
        )
    except Exception as e:
        error_message = f"Error listing groups: {str(e)}"
        logger.error(error_message)
        return CallToolResult(
            isError=True,
            content=[TextContent(type="text", text=error_message)]
        )


# ============================================================================
# MONITORING TOOLS
# ============================================================================

@mcp.tool()
def run_monitor(backend: str = "", suffix: str = "") -> CallToolResult:
    """
    Get the Directory Server's monitor information.

    Get the backend monitor information if backend/suffix is provided.

    Args:
        backend: The database backend name, like 'userroot'
        suffix: The database suffix name, like 'dc=example,dc=com'

    Returns:
        JSON object containing the server's monitor information
    """
    try:
        result = _run_monitor(backend=backend, suffix=suffix)
        return CallToolResult(
            content=[TextContent(type="text", text=json.dumps(result, indent=2))]
        )
    except Exception as e:
        error_message = f"Error accessing the monitor: {str(e)}"
        logger.error(error_message)
        return CallToolResult(
            isError=True,
            content=[TextContent(type="text", text=error_message)]
        )


# ============================================================================
# ADVANCED SEARCH TOOLS
# ============================================================================

@mcp.tool()
def ldap_search(
    base_dn: str,
    scope: str = 'SUBTREE',
    filter: str = '(objectClass=*)',
    attributes: Optional[str] = None,
    attrs_only: bool = False,
    limit: int = 100
) -> CallToolResult:
    """
    Perform a general LDAP search with full control over search parameters.

    This tool provides direct access to LDAP search functionality for cases where
    the specialized search tools (user/group specific) are not sufficient. It allows
    searching for any type of LDAP entry with complete control over the search scope,
    filter, and attributes returned.

    Args:
        base_dn: The base DN to start the search from (e.g., 'dc=example,dc=com' or 'cn=config')
        scope: Search scope - must be one of: 'BASE', 'ONELEVEL', or 'SUBTREE'
               - BASE: Search only the base DN entry itself
               - ONELEVEL: Search only immediate children of the base DN
               - SUBTREE: Search the entire subtree starting from base DN
        filter: LDAP search filter (e.g., '(objectClass=*)', '(&(uid=*)(mail=*))', '(cn=admin*)')
                Default: '(objectClass=*)' to return all entries
        attributes: Comma-separated list of attributes to return (e.g., 'cn,mail,uid')
                    Default: None (returns all attributes)
                    Special values: '*' for all user attributes, '+' for all operational attributes
        attrs_only: If True, return only attribute names without values (default: False)
        limit: Maximum number of entries to return (default: 100, max: 1000)

    Returns:
        JSON containing the search results with full entry details
    """
    try:
        result = _ldap_search(
            base_dn=base_dn,
            scope=scope,
            filter=filter,
            attributes=attributes,
            attrs_only=attrs_only,
            limit=limit
        )
        return CallToolResult(
            content=[TextContent(type="text", text=json.dumps(result, indent=2))]
        )
    except ValueError as e:
        # Handle validation errors (like invalid scope)
        error_message = str(e)
        logger.error(error_message)
        return CallToolResult(
            isError=True,
            content=[TextContent(type="text", text=error_message)]
        )
    except Exception as e:
        error_message = f"Unexpected error during LDAP search: {str(e)}"
        logger.error(error_message)
        return CallToolResult(
            isError=True,
            content=[TextContent(type="text", text=error_message)]
        )


# ============================================================================
# RESOURCES
# ============================================================================

@mcp.resource("config://config-all")
def get_cn_config_all_attributes() -> str:
    """Return all attributes for cn=config as JSON."""
    ds = None
    try:
        ds = get_connection()
        config_entry = Config(ds)
        return config_entry.get_all_attrs_json()
    except Exception as e:
        error_payload = {
            "type": "cn_config_attribute_error",
            "attribute": "*",
            "error": str(e),
        }
        return json.dumps(error_payload, indent=2)
    finally:
        try:
            if ds is not None:
                ds.unbind_s()
        except Exception:
            pass


@mcp.resource("config://config-attribute/{attribute}")
def get_cn_config_attribute(attribute: str) -> str:
    """Get a specific attribute from cn=config as JSON."""
    ds = None
    try:
        ds = get_connection()
        config_entry = Config(ds)

        attr_name = attribute.strip()

        # Prefer list-valued API, fall back to single value if available
        try:
            values_list = config_entry.get_attr_vals_utf8(attr_name)
        except Exception:
            values_list = []

        try:
            single_value = config_entry.get_attr_val_utf8(attr_name)
        except Exception:
            single_value = None

        response = {
            "type": "cn_config_attribute",
            "attribute": attr_name,
            "values": values_list if isinstance(values_list, list) else ([] if values_list is None else [str(values_list)]),
            "value": single_value,
        }
        return json.dumps(response, indent=2)

    except Exception as e:
        error_payload = {
            "type": "cn_config_attribute_error",
            "attribute": attribute,
            "error": str(e),
        }
        return json.dumps(error_payload, indent=2)
    finally:
        try:
            if ds is not None:
                ds.unbind_s()
        except Exception:
            pass


if __name__ == "__main__":
    mcp.run()
