"""Pytest configuration and fixtures for DirSrv MCP tests.

Following FastMCP testing patterns:
- Fixtures create reusable server configurations
- Clients are NOT opened in fixtures (per FastMCP guidelines)
- Tests use in-memory transport via Client(server) pattern
"""

from __future__ import annotations

import os
from unittest.mock import patch

import pytest

from src.dirsrv_mcp.server import DirSrvMCP
from src.ldap_assistant_mcp.server import LDAPServerConfig


@pytest.fixture
def mock_env():
    """Ensure the LDAP connection environment variables are always defined.

    These can be overridden by setting real environment variables before running tests.
    """
    env_vars = {
        "LDAP_URL": os.environ.get("LDAP_URL", "ldap://localhost:3389"),
        "LDAP_BASE_DN": os.environ.get("LDAP_BASE_DN", "dc=test,dc=com"),
        "LDAP_BIND_DN": os.environ.get("LDAP_BIND_DN", "cn=Directory Manager"),
        "LDAP_BIND_PASSWORD": os.environ.get("LDAP_BIND_PASSWORD", "TestPassword123"),
    }

    with patch.dict(os.environ, env_vars):
        yield env_vars


@pytest.fixture
def server_config(mock_env) -> LDAPServerConfig:
    """Return the LDAP server configuration used by DirSrvMCP."""
    return LDAPServerConfig.from_env()


@pytest.fixture
def dirsrv_server(server_config) -> DirSrvMCP:
    """Create a DirSrvMCP instance backed by the configured 389 DS instance.

    Note: Per FastMCP testing guidelines, we do NOT open clients in fixtures
    as this can create hard-to-diagnose issues with event loops.
    """
    return DirSrvMCP(
        servers=[server_config],
        include_env_fallback=False,
    )


@pytest.fixture
def expected_test_users() -> list[str]:
    """Expected test users for verification."""
    return [
        "testuser1",
        "testuser2",
        "lockeduser",
        "contractor",
    ]


@pytest.fixture
def expected_test_groups() -> list[str]:
    """Expected test groups for verification."""
    return [
        "testgroup1",
        "testgroup2",
    ]

