# Testing Guide

This guide covers how to run and write tests for LDAP Assistant MCP.

## Quick Start (no containers needed)

Most of the suite runs without any LDAP server. Tests that need a running
389 DS instance carry the `live` pytest marker — deselect them:

```bash
pip install -e .[dev]
pytest -m "not live"
```

This is the same subset CI's fast job runs, and it should always pass on a
fresh checkout. A bare `pytest` without the containers below will fail the
`live` tests with connection errors — that's expected, not a bug.

## Full Suite (with containers)

Run everything, including `live` tests, with a single command:

```bash
./scripts/ds-test.sh
```

This script handles everything: container setup, test data seeding, and pytest execution.

Docker is the default container runtime. To run the same scripts with Podman,
select it for the whole shell session (and start `podman machine` first on
macOS or Windows):

```bash
export DS_CLI=podman
podman machine start  # macOS/Windows only
./scripts/ds-test.sh
```

The scripts fail before setup or cleanup when the selected CLI is missing or
its engine is unavailable.

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

pytest and pytest-asyncio are dev dependencies and are not installed by `uv run` alone, so install them first:

```bash
uv pip install pytest pytest-asyncio
```

```bash
# Run all tests
uv run pytest -v -s

# Run specific test file
uv run pytest tests/dirsrv_mcp/test_users.py -v -s

# Run tests matching a pattern
uv run pytest -k "test_user" -v -s
```

## Test Structure

```
tests/dirsrv_mcp/
├── conftest.py              # Shared fixtures
├── test_users.py            # User management tool tests
├── test_groups.py           # Group management tool tests
├── test_monitoring.py       # Monitoring tool tests
├── test_search.py           # LDAP search tool tests
├── test_multiserver.py      # Multi-server testing
├── test_local_connection.py # Local/LDAPI connection tests
├── test_ssl_config.py       # SSL/TLS configuration tests
├── test_anonymous.py        # Anonymous bind tests
├── test_privacy.py          # Privacy mode tests
├── test_config.py           # Configuration tool tests
├── test_health.py           # Health check tool tests
├── test_indexes.py          # Index tool tests
├── test_performance.py      # Performance tool tests
├── test_replication.py      # Replication tool tests
├── test_offline_mode.py     # Offline instance mode tests
├── test_archive_mode.py     # Archive mode infrastructure tests
├── test_archive_tools.py    # Archive/offline tool tests + DSE comparison
├── test_logs.py             # Log parsing tool tests
├── test_debug_mode.py       # Debug mode behavior tests
├── test_middleware.py       # Middleware timeout/size/logging tests
└── test_privacy_gaps.py     # Privacy gap regression tests
```

## Tool-selection eval

The `tests/eval/` directory contains a tool-selection evaluation framework. It runs a 31-case dataset (`tests/eval/eval_dataset.json`) that checks whether tool descriptions route prompts to the right tool, plus guards for annotation and tag completeness.

```bash
# Run via pytest
pytest tests/eval/run_eval.py -v

# Or standalone
python tests/eval/run_eval.py
```

When tools are added or renamed, `eval_dataset.json` should gain corresponding cases.

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
uv run pytest tests/dirsrv_mcp/test_users.py::test_list_all_users -v -s
```

### Stop on First Failure

```bash
uv run pytest -x -v -s
```

## Continuous Integration

Tests run automatically on pull requests. The CI runs four jobs:

1. **Pytest Tests** - Standard remote connection tests against 3 DS containers
2. **Local Connection Tests** - Tests run inside a DS container for local/LDAPI access
3. **Multi-Server Local Tests** - Mixed local + remote server configuration tests
4. **Offline Mode Tests** - Tests run in a container where DS is never started (verifying offline analysis works without any LDAP connection)

Each job reports failures with container logs for debugging.
