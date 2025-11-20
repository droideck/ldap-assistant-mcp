# LDAP Assistent MCP Tests

This directory contains pytest-based unit tests for LDAP Assistent's MCP server tools. These tests run against a real 389 Directory Server instance in a container to verify the stable parts of LDAP Assistent MCP functionality while exercising the public FastMCP interface.

## Test Structure

- `conftest.py` - Shared pytest fixtures and configuration
- `test_list_all_users.py` - Tests for the list_all_users tool
- `test_list_all_groups.py` - Tests for the list_all_groups tool
- `test_search_users_by_name.py` - Tests for the search_users_by_name tool
- `test_get_user_details.py` - Tests for the get_user_details tool
- `test_list_active_users.py` - Tests for the list_active_users tool
- `test_list_locked_users.py` - Tests for the list_locked_users tool
- `test_search_users_by_attribute.py` - Tests for the search_users_by_attribute tool

## Test Approach

All tests instantiate `DirSrvMCP` and call tools through the official FastMCP `Client`, mirroring how downstream clients interact with the server. Each test:

- Builds a temporary MCP server instance using `LDAPServerConfig.from_env()`
- Opens an in-memory FastMCP client (`async with Client(server) as client`)
- Invokes a single tool with `await client.call_tool("tool_name", {...})`
- Asserts on the structured data returned via `result.data`

This pattern keeps the tests fast, deterministic, and faithful to production usage. Individual tests remain focused on a single behavior (tool success, validation failure, etc.) while still exercising the network/protocol layer.

## Running Tests

Tests are automatically run in CI via the pytest workflow, which:
1. Sets up a 389 DS container with test data
2. Runs all tests against the real DS instance
3. Verifies tool functionality without LLM dependencies

To run locally:
```bash
# Ensure you have a DS instance running with appropriate test data
export LDAP_URL="ldap://localhost:3389"
export LDAP_BASE_DN="dc=test,dc=com"
export LDAP_BIND_DN="cn=Directory Manager"
export LDAP_BIND_PASSWORD="TestPassword123"

uv run pytest tests/ -v
```
