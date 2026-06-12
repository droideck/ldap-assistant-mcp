"""Tests for multi-server functionality.

These tests verify that the MCP server can:
- Connect to multiple LDAP servers
- Execute tools against specific servers
- Aggregate health checks across all servers
"""

from __future__ import annotations

import pytest
from fastmcp import Client

pytestmark = pytest.mark.asyncio


# Multi-server configuration tests


async def test_multiserver_has_all_servers_configured(dirsrv_multiserver, test_server_names):
    """Test that all expected servers are registered in the connection manager."""
    registered_names = dirsrv_multiserver.connection_manager.get_server_names()

    for expected_name in test_server_names:
        assert expected_name in registered_names, (
            f"Expected server '{expected_name}' not found in registered servers. "
            f"Found: {registered_names}"
        )


async def test_multiserver_server_count(dirsrv_multiserver, test_server_names):
    """Test that the correct number of servers are registered."""
    registered_names = dirsrv_multiserver.connection_manager.get_server_names()
    assert len(registered_names) == len(test_server_names), (
        f"Expected {len(test_server_names)} servers, got {len(registered_names)}"
    )


# first_look() multi-server health check tests


async def test_first_look_checks_all_servers(dirsrv_multiserver, test_server_names):
    """Test that first_look() checks all configured servers."""
    async with Client(dirsrv_multiserver) as client:
        result = await client.call_tool("first_look", {})
        data = result.data

        assert data["type"] == "first_look", "Response type should be 'first_look'"
        assert data["total_servers"] == len(test_server_names), (
            f"Expected {len(test_server_names)} total servers, got {data['total_servers']}"
        )


async def test_first_look_reports_all_servers_checked(dirsrv_multiserver, test_server_names):
    """Test that first_look() reports all servers as checked."""
    async with Client(dirsrv_multiserver) as client:
        result = await client.call_tool("first_look", {})
        data = result.data

        servers_checked = data.get("servers_checked", [])
        for expected_name in test_server_names:
            assert expected_name in servers_checked, (
                f"Server '{expected_name}' should be in servers_checked. "
                f"Checked: {servers_checked}"
            )


async def test_first_look_returns_findings_for_each_server(dirsrv_multiserver, test_server_names):
    """Test that first_look() returns findings from each server."""
    async with Client(dirsrv_multiserver) as client:
        result = await client.call_tool("first_look", {})
        data = result.data

        findings = data.get("findings", [])
        servers_with_findings = set()
        for finding in findings:
            server = finding.get("server")
            if server:
                servers_with_findings.add(server)

        for expected_name in test_server_names:
            assert expected_name in servers_with_findings, (
                f"Expected findings from server '{expected_name}'. "
                f"Servers with findings: {servers_with_findings}"
            )


async def test_first_look_no_servers_failed(dirsrv_multiserver):
    """Test that first_look() reports no failed servers when all are healthy."""
    async with Client(dirsrv_multiserver) as client:
        result = await client.call_tool("first_look", {})
        data = result.data

        servers_failed = data.get("servers_failed", [])
        assert len(servers_failed) == 0, (
            f"Expected no failed servers, but found: {servers_failed}"
        )


# Tool execution with specific server_name


async def test_list_users_on_specific_server(dirsrv_multiserver, test_server_names):
    """Test that list_all_users can target a specific server."""
    async with Client(dirsrv_multiserver) as client:
        for server_name in test_server_names:
            result = await client.call_tool(
                "list_all_users",
                {"limit": 50, "server_name": server_name},
            )
            data = result.data

            assert data["type"] == "user_list", "Response type should be 'user_list'"
            assert data["server"] == server_name, (
                f"Expected server '{server_name}', got '{data['server']}'"
            )
            assert data["total_returned"] > 0, (
                f"Expected users on server {server_name}"
            )


async def test_each_server_has_unique_user(dirsrv_multiserver, test_server_names):
    """Test that each server has its unique user (server1user, server2user, etc.)."""
    async with Client(dirsrv_multiserver) as client:
        for i, server_name in enumerate(test_server_names, start=1):
            expected_user = f"server{i}user"

            result = await client.call_tool(
                "search_users_by_name",
                {"name": expected_user, "limit": 10, "server_name": server_name},
            )
            data = result.data

            found_users = _extract_user_ids(data["items"])
            assert expected_user in found_users, (
                f"Expected user '{expected_user}' on server '{server_name}'. "
                f"Found: {found_users}"
            )


async def test_get_user_details_on_specific_server(dirsrv_multiserver, test_server_names):
    """Test that get_user_details works with specific server_name."""
    async with Client(dirsrv_multiserver) as client:
        server_name = test_server_names[0]

        result = await client.call_tool(
            "get_user_details",
            {"username": "testuser1", "server_name": server_name},
        )
        data = result.data

        assert data["type"] == "user_details", "Response type should be 'user_details'"
        assert data["server"] == server_name, (
            f"Expected server '{server_name}', got '{data['server']}'"
        )
        assert data["username"] == "testuser1", "Username should be preserved"


async def test_list_groups_on_specific_server(dirsrv_multiserver, test_server_names):
    """Test that list_all_groups can target a specific server."""
    async with Client(dirsrv_multiserver) as client:
        for server_name in test_server_names:
            result = await client.call_tool(
                "list_all_groups",
                {"limit": 50, "server_name": server_name},
            )
            data = result.data

            assert data["type"] == "group_list", "Response type should be 'group_list'"
            assert data["server"] == server_name, (
                f"Expected server '{server_name}', got '{data['server']}'"
            )


async def test_ldap_search_on_specific_server(dirsrv_multiserver, test_server_names):
    """Test that ldap_search can target a specific server."""
    async with Client(dirsrv_multiserver) as client:
        for server_name in test_server_names:
            result = await client.call_tool(
                "ldap_search",
                {
                    "base_dn": "dc=test,dc=com",
                    "scope": "SUBTREE",
                    "filter": "(objectClass=*)",
                    "limit": 10,
                    "server_name": server_name,
                },
            )
            data = result.data

            assert data["type"] == "ldap_search", "Response type should be 'ldap_search'"
            assert data["server"] == server_name, (
                f"Expected server '{server_name}', got '{data['server']}'"
            )
            assert data["total_returned"] > 0, (
                f"Expected results from server {server_name}"
            )


# Default server behavior


async def test_tool_uses_default_server_when_not_specified(dirsrv_multiserver):
    """Test that tools use the default server when server_name is not provided."""
    async with Client(dirsrv_multiserver) as client:
        result = await client.call_tool("list_all_users", {"limit": 10})
        data = result.data

        assert "server" in data, "Response should include server name"
        assert data["server"] is not None, "Server should not be None"


# Helper functions


def _extract_user_ids(items: list) -> list[str]:
    """Extract user IDs from a list of user items."""
    found_users = []
    for item in items:
        attrs = item.get("attrs", {})
        uid_values = attrs.get("uid", [])
        if isinstance(uid_values, list) and uid_values:
            found_users.append(uid_values[0])
        elif uid_values:
            found_users.append(uid_values)
    return found_users
