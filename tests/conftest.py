import pytest
import sys
import os
from unittest.mock import patch

# Add the parent directory to the path so we can import modules
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

# Import the underlying tool implementations (not the FastMCP-wrapped versions)
from src.providers.dirsrv_mcp.tools import (
    list_all_users,
    list_all_groups,
    search_users_by_name,
    get_user_details,
    list_active_users,
    list_locked_users,
    search_users_by_attribute,
    ldap_search,
    run_monitor,
)

@pytest.fixture
def mock_env():
    """Mock environment variables for testing."""
    # Use environment variables if available, otherwise use defaults
    env_vars = {
        'LDAP_URL': os.environ.get('LDAP_URL', 'ldap://localhost:3389'),
        'LDAP_BASE_DN': os.environ.get('LDAP_BASE_DN', 'dc=test,dc=com'),
        'LDAP_BIND_DN': os.environ.get('LDAP_BIND_DN', 'cn=Directory Manager'),
        'LDAP_BIND_PASSWORD': os.environ.get('LDAP_BIND_PASSWORD', 'TestPassword123')
    }

    with patch.dict(os.environ, env_vars):
        yield

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
