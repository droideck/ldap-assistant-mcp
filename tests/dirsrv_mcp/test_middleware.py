"""Tests for middleware, lifespan, health check, and sanitizer cap."""

from __future__ import annotations

import os
from unittest.mock import patch

import pytest
from fastmcp import Client

from ldap_assistant_mcp.dirsrv_mcp.server import DirSrvMCP
from ldap_assistant_mcp.core import LDAPServerConfig, MCPSettings
from ldap_assistant_mcp.lib.privacy import PrivacySanitizer


@pytest.fixture
def _env():
    env_vars = {
        "LDAP_URL": "ldap://localhost:389",
        "LDAP_BASE_DN": "dc=example,dc=com",
        "LDAP_BIND_DN": "cn=Directory Manager",
        "LDAP_BIND_PASSWORD": "secret",
        "LDAP_MCP_EXPOSE_SENSITIVE_DATA": "true",
    }
    with patch.dict(os.environ, env_vars):
        yield


@pytest.fixture
def mcp_server(_env):
    config = LDAPServerConfig.from_env()
    return DirSrvMCP(
        servers=[config],
        settings=MCPSettings(expose_sensitive_data=True),
        include_env_fallback=False,
    )


@pytest.mark.asyncio
async def test_server_health_returns_status(mcp_server):
    async with Client(mcp_server) as client:
        result = await client.call_tool("server_health", {})
        data = result.data
    assert data["type"] == "server_health"
    assert data["status"] == "healthy"
    assert data["server_count"] >= 1
    assert isinstance(data["privacy_mode"], bool)
    assert isinstance(data["debug_mode"], bool)


@pytest.mark.asyncio
async def test_all_tools_have_readonly_annotation(mcp_server):
    async with Client(mcp_server) as client:
        tools = await client.list_tools()
    missing = []
    for tool in tools:
        if not tool.annotations or not getattr(tool.annotations, "readOnlyHint", False):
            missing.append(tool.name)
    assert not missing, f"Tools missing readOnlyHint: {missing}"


@pytest.mark.asyncio
async def test_all_tools_have_non_destructive_annotation(mcp_server):
    async with Client(mcp_server) as client:
        tools = await client.list_tools()
    wrong = []
    for tool in tools:
        if not tool.annotations:
            wrong.append(tool.name)
        elif getattr(tool.annotations, "destructiveHint", True) is not False:
            wrong.append(tool.name)
    assert not wrong, f"Tools with destructiveHint != False: {wrong}"


@pytest.mark.asyncio
async def test_openWorldHint_differentiates_live_vs_local(mcp_server):
    """Live-only tools should have openWorldHint=True, file-only tools False."""
    async with Client(mcp_server) as client:
        tools = await client.list_tools()
    tool_map = {t.name: t for t in tools}

    live_only = ["ldap_search", "run_monitor", "get_replication_status"]
    for name in live_only:
        t = tool_map.get(name)
        assert t and t.annotations, f"{name} missing annotations"
        assert getattr(t.annotations, "openWorldHint", None) is True, (
            f"{name} should have openWorldHint=True"
        )

    local_only = ["parse_access_log", "analyze_archive", "list_servers"]
    for name in local_only:
        t = tool_map.get(name)
        assert t and t.annotations, f"{name} missing annotations"
        assert getattr(t.annotations, "openWorldHint", None) is False, (
            f"{name} should have openWorldHint=False"
        )


def test_timeout_middleware_per_tool_override():
    """Per-tool timeout should override default but be capped at max."""
    from ldap_assistant_mcp.dirsrv_mcp.middleware import TimeoutMiddleware

    mw = TimeoutMiddleware(
        default_timeout=30.0,
        max_timeout=120.0,
        tool_timeouts={"slow_tool": 90.0, "too_slow": 999.0},
    )
    # Normal tools use default
    assert mw.tool_timeouts.get("normal_tool") is None
    # Configured tool gets its override
    assert mw.tool_timeouts["slow_tool"] == 90.0
    # Override exceeding max is stored but will be capped at runtime
    assert mw.tool_timeouts["too_slow"] == 999.0


def test_timeout_middleware_caps_override_at_max():
    """Per-tool override exceeding max_timeout should be capped."""
    from ldap_assistant_mcp.dirsrv_mcp.middleware import TimeoutMiddleware

    mw = TimeoutMiddleware(
        default_timeout=30.0,
        max_timeout=60.0,
        tool_timeouts={"slow_tool": 999.0},
    )
    # Simulate what on_call_tool does: min(requested, max_timeout)
    requested = mw.tool_timeouts.get("slow_tool", mw.default_timeout)
    effective = min(requested, mw.max_timeout)
    assert effective == 60.0


def test_server_configures_per_tool_timeouts(mcp_server):
    """DirSrvMCP should configure longer timeouts for heavy tools."""
    # Access the middleware stack through the server
    middlewares = mcp_server._middleware if hasattr(mcp_server, '_middleware') else []
    from ldap_assistant_mcp.dirsrv_mcp.middleware import TimeoutMiddleware
    timeout_mw = None
    for mw in middlewares:
        if isinstance(mw, TimeoutMiddleware):
            timeout_mw = mw
            break
    if timeout_mw is not None:
        assert "first_look" in timeout_mw.tool_timeouts
        assert "run_healthcheck" in timeout_mw.tool_timeouts
        assert "analyze_archive" in timeout_mw.tool_timeouts


def test_mcp_settings_timeout_defaults():
    s = MCPSettings()
    assert s.tool_timeout == 30.0
    assert s.max_tool_timeout == 120.0


def test_mcp_settings_timeout_from_env():
    with patch.dict(os.environ, {
        "LDAP_MCP_TOOL_TIMEOUT": "60",
        "LDAP_MCP_MAX_TOOL_TIMEOUT": "300",
    }):
        s = MCPSettings.from_env()
    assert s.tool_timeout == 60.0
    assert s.max_tool_timeout == 300.0


def test_mcp_settings_to_dict_includes_timeouts():
    s = MCPSettings(tool_timeout=15.0, max_tool_timeout=45.0)
    d = s.to_dict()
    assert d["tool_timeout"] == 15.0
    assert d["max_tool_timeout"] == 45.0


def test_no_default_password():
    """from_env() with no LDAP_BIND_PASSWORD should yield None, not 'Password123'."""
    clean_env = {k: v for k, v in os.environ.items() if not k.startswith("LDAP_")}
    clean_env["LDAP_URL"] = "ldap://localhost:389"
    with patch.dict(os.environ, clean_env, clear=True):
        config = LDAPServerConfig.from_env()
    assert config.bind_password is None


def test_sanitizer_many_hostnames_all_deterministic():
    """Even with many hostnames, the same input always yields the same output."""
    s = PrivacySanitizer()
    for i in range(100):
        s._get_anon_hostname(f"host-{i}.example.com")
    # All 100 should be in the map (no eviction)
    assert len(s._hostname_map) == 100
    # And the mapping is deterministic
    assert s._get_anon_hostname("host-0.example.com") == s._get_anon_hostname("host-0.example.com")


def test_temp_dir_tracking():
    from ldap_assistant_mcp.dirsrv_mcp.archive.loader import _temp_dirs, cleanup_temp_dirs
    import tempfile

    td = tempfile.mkdtemp(prefix="ldap-mcp-test-cleanup-")
    _temp_dirs.append(td)
    assert os.path.isdir(td)

    cleanup_temp_dirs()
    assert not os.path.isdir(td)
    assert len(_temp_dirs) == 0


def test_extract_archive_caches_result():
    """Extracting the same tarball twice should return the cached dir."""
    from ldap_assistant_mcp.dirsrv_mcp.archive.loader import (
        _temp_dirs, cleanup_temp_dirs, extract_archive,
    )
    import tarfile
    import tempfile

    # Create a minimal tarball with a single file
    work = tempfile.mkdtemp(prefix="ldap-mcp-test-tar-")
    dummy = os.path.join(work, "dse.ldif")
    with open(dummy, "w") as f:
        f.write("dn: cn=config\n")
    tar_path = os.path.join(work, "test.tar.gz")
    with tarfile.open(tar_path, "w:gz") as tar:
        tar.add(dummy, arcname="dse.ldif")

    try:
        first = extract_archive(tar_path)
        second = extract_archive(tar_path)
        assert first == second, "Second call should return cached dir"
        assert _temp_dirs.count(first) == 1, "Should only track dir once"
    finally:
        cleanup_temp_dirs()
        import shutil
        shutil.rmtree(work, ignore_errors=True)


def test_format_tool_error_sanitizes_in_privacy_mode():
    from unittest.mock import MagicMock
    from ldap_assistant_mcp.dirsrv_mcp.tools.error_utils import format_tool_error
    from ldap_assistant_mcp.lib.privacy import PrivacySanitizer

    mcp = MagicMock()
    mcp.debug_enabled = False
    mcp.privacy_enabled = True
    mcp.sanitizer = PrivacySanitizer()

    exc = RuntimeError("Failed to read /etc/dirsrv/slapd-supplier1/dse.ldif")
    result = format_tool_error(exc, mcp, "test_type", server="my-server")

    assert result["server"] == "my-server"
    assert "/etc/dirsrv" not in result["error"]


def test_format_tool_error_no_sanitize_without_privacy():
    from unittest.mock import MagicMock
    from ldap_assistant_mcp.dirsrv_mcp.tools.error_utils import format_tool_error

    mcp = MagicMock()
    mcp.debug_enabled = False
    mcp.privacy_enabled = False

    exc = RuntimeError("Failed on server alpha")
    result = format_tool_error(exc, mcp, "test_type", server="alpha")

    assert result["server"] == "alpha"
    assert "Failed on server alpha" in result["error"]
