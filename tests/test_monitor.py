import pytest

from tests.helpers import call_tool

pytestmark = pytest.mark.asyncio


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


async def test_monitor(dirsrv_server):
    """Test that run_monitor returns monitor data from the directory."""

    response = await call_tool(dirsrv_server, "run_monitor")
    response_data = response.data

    # Verify response structure
    check_out(response_data)
    print("✓ Found expected monitor data")

    response = await call_tool(dirsrv_server, "run_monitor", backend="userroot")
    response_data = response.data

    # Verify response structure
    check_out(response_data, "backend")
    print("✓ Found expected monitor data for backend")

    response = await call_tool(dirsrv_server, "run_monitor", suffix="dc=test,dc=com")
    response_data = response.data

    # Verify response structure
    check_out(response_data, "backend")
    print("✓ Found expected monitor data for suffix")
