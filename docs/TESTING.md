# Testing Guide

This guide covers how to run and write tests for LDAP Assistant MCP.

## Quick Start

Run all tests with a single command:

```bash
./scripts/ds-test.sh
```

This script handles everything: container setup, test execution, and cleanup.

## Test Environment

The test suite uses a **separate container** to avoid conflicts with the dev environment:

| Setting | Value |
|---------|-------|
| Container | `ds-test` |
| Password | `TestPassword123` |
| Base DN | `dc=test,dc=com` |
| Port | Dynamically mapped |

## Running Tests Manually

If you prefer manual control over the test environment:

### 1. Set Environment Variables

```bash
export LDAP_URL="ldap://localhost:3389"
export LDAP_BASE_DN="dc=test,dc=com"
export LDAP_BIND_DN="cn=Directory Manager"
export LDAP_BIND_PASSWORD="TestPassword123"
```

### 2. Run pytest

```bash
# Run all tests
uv run pytest tests/ -v -s

# Run specific test file
uv run pytest tests/test_specific.py -v -s

# Run tests matching a pattern
uv run pytest tests/ -k "test_user" -v -s
```

## Test Structure

```
tests/
├── conftest.py          # Shared fixtures
├── test_connection.py   # Connection management tests
├── test_health.py       # Health check tool tests
├── test_users.py        # User management tool tests
├── test_groups.py       # Group management tool tests
└── ...
```

## Writing Tests

### Using Fixtures

Tests use pytest fixtures for common setup:

```python
import pytest

def test_list_users(ldap_connection):
    """Test listing users."""
    users = ldap_connection.list_all_users()
    assert isinstance(users, list)
```

### Testing Tools

When testing MCP tools, use the tool functions directly:

```python
from dirsrv_mcp.tools import list_all_users

def test_list_all_users(connection_manager):
    """Test the list_all_users tool."""
    result = list_all_users(limit=10)
    assert "users" in result
```

## Debugging Tests

### Verbose Output

```bash
uv run pytest tests/ -v -s --tb=long
```

### Run Single Test

```bash
uv run pytest tests/test_users.py::test_list_all_users -v -s
```

### Stop on First Failure

```bash
uv run pytest tests/ -x -v -s
```

## Continuous Integration

Tests are run automatically on pull requests. The CI environment:
- Spins up a fresh DS container
- Runs the full test suite
- Reports failures with detailed output
