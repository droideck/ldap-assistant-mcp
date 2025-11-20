import os
from unittest.mock import patch

import pytest

from src.dirsrv_mcp.server import DirSrvMCP
from src.ldap_assistant_mcp.server import LDAPServerConfig

@pytest.fixture
def mock_env():
    """Ensure the LDAP connection environment variables are always defined."""
    env_vars = {
        "LDAP_URL": os.environ.get("LDAP_URL", "ldap://localhost:3389"),
        "LDAP_BASE_DN": os.environ.get("LDAP_BASE_DN", "dc=test,dc=com"),
        "LDAP_BIND_DN": os.environ.get("LDAP_BIND_DN", "cn=Directory Manager"),
        "LDAP_BIND_PASSWORD": os.environ.get("LDAP_BIND_PASSWORD", "TestPassword123"),
    }

    with patch.dict(os.environ, env_vars):
        yield env_vars


@pytest.fixture
def dirsrv_server_config(mock_env):
    """Return the LDAP server configuration used by DirSrvMCP."""

    return LDAPServerConfig.from_env()


@pytest.fixture
def dirsrv_server(dirsrv_server_config):
    """Instantiate a DirSrvMCP backed by the configured 389 DS instance."""

    return DirSrvMCP(
        servers=[dirsrv_server_config],
        include_env_fallback=False,
    )

@pytest.fixture
def expected_test_users():
    """Expected test users for verification."""
    return [
        'testuser1',
        'testuser2',
        'lockeduser',
        'contractor'
    ]

@pytest.fixture
def expected_test_groups():
    """Expected test groups for verification."""
    return [
        'testgroup1',
        'testgroup2'
    ]
