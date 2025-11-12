import json
import pytest
from src.providers.dirsrv_mcp.tools import run_monitor


def check_out(response_data, arg: str = ""):
    """Check the JSON repsnse for the expected values"""

    print("DEBUG response: " + str(response_data))
    assert response_data["type"] == "monitor"
    assert "item" in response_data
    assert "attrs" in response_data["item"]
    attrs = response_data["item"]['attrs']

    if arg == "":
        assert "version" in attrs
        assert attrs["version"][0].startswith("389-Directory")
        assert "threads" in attrs
        assert "nbackends" in attrs
        assert "totalconnections" in attrs
    elif arg == 'backend':
        assert "database" in attrs
        assert attrs["database"][0] == "ldbm database"
        assert "entrycachehits" in attrs
    else:
        print("Unknown arg: " + str(arg))
        assert False


def test_monitor(mock_env):
    """Test that run_monitor returns monitor data from the directory."""

    #
    # Call the tool (no backend/suffix) - now returns dict directly
    #
    response_data = run_monitor()

    # Verify response structure
    check_out(response_data)
    print("✓ Found expected monitor data")

    #
    # Call the tool (backend) - now returns dict directly
    #
    response_data = run_monitor(backend="userroot")

    # Verify response structure
    check_out(response_data, "backend")
    print("✓ Found expected monitor data for backend")

    #
    # Call the tool (suffix) - now returns dict directly
    #
    response_data = run_monitor(suffix="dc=test,dc=com")

    # Verify response structure
    check_out(response_data, "backend")
    print("✓ Found expected monitor data for suffix")
