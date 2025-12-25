# Testing Guide

This guide covers how to run and write tests for LDAP Assistant MCP.

## Quick Start

Run all tests with a single command:

```bash
./scripts/ds-test.sh
```

This script handles everything: container setup, test data seeding, and pytest execution.

## Test Environment

The test suite creates **3 DS containers** for multi-server testing:

| Container | LDAP URL | LDAPS URL |
|-----------|----------|-----------|
| ds-test-1 | ldap://localhost:33891 | ldaps://localhost:36361 |
| ds-test-2 | ldap://localhost:33892 | ldaps://localhost:36362 |
| ds-test-3 | ldap://localhost:33893 | ldaps://localhost:36363 |

All containers use:
- **Base DN:** `dc=test,dc=com`
- **Bind DN:** `cn=Directory Manager`
- **Password:** `TestPassword123`

## Script Options

```bash
# Full test run (default)
./scripts/ds-test.sh

# Set up containers only (for manual pytest runs)
./scripts/ds-test.sh --no-pytest

# Skip cleanup (reuse existing containers)
./scripts/ds-test.sh --no-clean

# Custom image
./scripts/ds-test.sh --image quay.io/389ds/dirsrv:latest
```

## Running Tests Manually

If you prefer manual control:

### 1. Set Up Containers

```bash
./scripts/ds-test.sh --no-pytest
```

### 2. Set Environment Variables

```bash
export LDAP_SERVERS_CONFIG="./tests-servers.json"
export LDAP_URL="ldap://localhost:33891"
export LDAP_BASE_DN="dc=test,dc=com"
export LDAP_BIND_DN="cn=Directory Manager"
export LDAP_BIND_PASSWORD="TestPassword123"
```

### 3. Run pytest

```bash
# Run all tests
uv run pytest -v -s

# Run specific test file
uv run pytest src/dirsrv_mcp/tests/test_users.py -v -s

# Run tests matching a pattern
uv run pytest -k "test_user" -v -s
```

## Test Structure

```
src/dirsrv_mcp/tests/
├── conftest.py          # Shared fixtures
├── test_users.py        # User management tool tests
├── test_groups.py       # Group management tool tests
├── test_monitoring.py   # Monitoring tool tests
├── test_search.py       # LDAP search tool tests
└── test_multiserver.py  # Multi-server testing
```

## Writing Tests

### Using Fixtures

Tests use pytest fixtures for common setup:

```python
import pytest
from fastmcp import Client

async def test_list_users(dirsrv_server):
    """Test listing users."""
    async with Client(dirsrv_server) as client:
        result = await client.call_tool("list_all_users", {"limit": 50})
        assert result.data["type"] == "user_list"
```

### Multi-Server Testing

For tests that require multiple servers:

```python
async def test_multiserver(dirsrv_multiserver, test_server_names):
    """Test multi-server operations."""
    async with Client(dirsrv_multiserver) as client:
        result = await client.call_tool("first_look", {})
        # Verify all servers are checked
```

## Debugging Tests

### Verbose Output

```bash
uv run pytest -v -s --tb=long
```

### Run Single Test

```bash
uv run pytest src/dirsrv_mcp/tests/test_users.py::test_list_all_users -v -s
```

### Stop on First Failure

```bash
uv run pytest -x -v -s
```

## Continuous Integration

Tests run automatically on pull requests. The CI:
- Creates 3 DS containers using `ds-test.sh --no-pytest`
- Runs the full test suite including multi-server tests
- Reports failures with container logs for debugging
