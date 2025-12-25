# 389 Directory Server MCP Tests

This directory contains pytest-based tests for the 389 Directory Server MCP tools. These tests follow FastMCP testing best practices and run against real 389 Directory Server instances.

## Test Structure

```
tests/
├── conftest.py          # Shared pytest fixtures (server config, expected data)
├── test_users.py        # User management tool tests
├── test_groups.py       # Group management tool tests
├── test_monitoring.py   # Monitoring tool tests
├── test_search.py       # LDAP search tool tests
└── test_multiserver.py  # Multi-server testing
```

## Testing Patterns

Following [FastMCP testing guidelines](https://docs.fastmcp.ai/development/tests):

### In-Memory Testing
Tests use in-memory transport where servers and clients communicate directly:

```python
async def test_list_all_users_returns_user_list(dirsrv_server):
    """Test that list_all_users returns a properly structured user list."""
    async with Client(dirsrv_server) as client:
        result = await client.call_tool("list_all_users", {"limit": 50})
        data = result.data
        assert data["type"] == "user_list"
```

### Single Behavior Per Test
Each test verifies exactly one behavior, making failures easy to diagnose:

```python
async def test_list_active_users_excludes_locked_user(dirsrv_server):
    """Test that list_active_users does not include locked users."""
    # ...
```

### Self-Contained Setup
Every test creates its own setup via fixtures. Tests can run in any order.

### Clear Intent
Test names and assertions make the verified behavior obvious.

## Running Tests

### Quick Start (Recommended)

Use the test script to set up containers and run tests:

```bash
# Set up 3 test containers and run pytest
./scripts/ds-test.sh

# Or set up containers only (for manual test runs)
./scripts/ds-test.sh --no-pytest
```

### Manual Testing

If you already have DS instances running:

```bash
export LDAP_URL="ldap://localhost:33891"
export LDAP_BASE_DN="dc=test,dc=com"
export LDAP_BIND_DN="cn=Directory Manager"
export LDAP_BIND_PASSWORD="TestPassword123"

# Run all dirsrv_mcp tests
uv run pytest src/dirsrv_mcp/tests/ -v

# Run specific test file
uv run pytest src/dirsrv_mcp/tests/test_users.py -v

# Run with coverage
uv run pytest src/dirsrv_mcp/tests/ --cov=src.dirsrv_mcp
```

### Multi-Server Testing

For multi-server tests, set `LDAP_SERVERS_CONFIG`:

```bash
export LDAP_SERVERS_CONFIG="./tests-servers.json"
uv run pytest src/dirsrv_mcp/tests/test_multiserver.py -v
```

## Test Data Requirements

The tests expect the following data in the directory:

**Users** (in `ou=people,dc=test,dc=com`):
- `testuser1` - Active user with mail attribute
- `testuser2` - Active user with departmentNumber
- `lockeduser` - Locked user account (nsAccountLock=true)
- `contractor` - Active user with `employeeType=Contractor`

**Groups** (in `ou=groups,dc=test,dc=com`):
- `testgroup1`
- `testgroup2`

See `scripts/ds-test.sh` for test data setup.
