"""Phase 3 workflow tests: mode errors that teach.

Mode/permission errors should not dead-end an LLM client — they name
alternative tools that DO work in the target server's mode:

- LiveServerRequired carries a ``try_instead`` list (per-tool mapping in
  connection.py) and renders it into the error message.
- format_tool_error() surfaces the ``try_instead`` attribute as a result key.
- Archive-only tools rejecting live servers, and log tools rejecting remote
  servers, include ``try_instead`` in their returned error dicts.
- Every suggested tool name must be a real registered tool (rot guard).

No live LDAP server is required.
"""

from __future__ import annotations

import os
from unittest.mock import patch

import pytest
from fastmcp import Client

from ldap_assistant_mcp.core import LDAPServerConfig, MCPSettings
from ldap_assistant_mcp.dirsrv_mcp.connection import (
    DEFAULT_OFFLINE_ALTERNATIVES,
    OFFLINE_ALTERNATIVES,
    LiveServerRequired,
)
from ldap_assistant_mcp.dirsrv_mcp.server import DirSrvMCP
from ldap_assistant_mcp.dirsrv_mcp.tools.error_utils import format_tool_error


@pytest.fixture
def clean_env():
    """Prevent external config from leaking into these tests."""
    env = {
        "LDAP_SERVERS_CONFIG": "",
        "LDAP_MCP_EXPOSE_SENSITIVE_DATA": "true",
    }
    with patch.dict(os.environ, env):
        yield


def _archive_config(name: str = "sos-archive") -> LDAPServerConfig:
    return LDAPServerConfig(
        name=name,
        hostname="archive",
        port=0,
        is_archive=True,
        archive_path="/nonexistent/sosreport",
    )


def _offline_config(name: str = "offline-test") -> LDAPServerConfig:
    return LDAPServerConfig(
        name=name,
        hostname="localhost",
        port=3389,
        base_dn="dc=test,dc=com",
        is_local=True,
        serverid="localhost",
        is_offline=True,
    )


def _remote_config(name: str = "remote-live") -> LDAPServerConfig:
    return LDAPServerConfig(
        name=name,
        hostname="ldap.example.com",
        port=389,
        base_dn="dc=test,dc=com",
        bind_dn="cn=Directory Manager",
        bind_password="TestPassword123",
    )


# ---------------------------------------------------------------------------
# Unit: LiveServerRequired carries and renders try_instead
# ---------------------------------------------------------------------------


class TestLiveServerRequiredTryInstead:
    def test_mapped_feature_uses_mapping(self):
        exc = LiveServerRequired("get_replication_status", "sos-archive", mode="archive")
        assert exc.try_instead == OFFLINE_ALTERNATIVES["get_replication_status"]
        assert "get_backend_configuration" in exc.try_instead

    def test_message_names_alternatives(self):
        exc = LiveServerRequired("get_replication_status", "sos-archive", mode="archive")
        message = str(exc)
        assert "Try these tools instead" in message
        for tool in exc.try_instead:
            assert tool in message

    def test_unmapped_feature_gets_default(self):
        exc = LiveServerRequired("config://config-all resource", "offline-test")
        assert exc.try_instead == DEFAULT_OFFLINE_ALTERNATIVES
        assert "first_look" in str(exc)

    def test_explicit_try_instead_overrides_mapping(self):
        exc = LiveServerRequired(
            "get_replication_status", "s", try_instead=["analyze_error_log"]
        )
        assert exc.try_instead == ["analyze_error_log"]
        assert "get_backend_configuration" not in str(exc)

    def test_empty_try_instead_omits_suffix(self):
        exc = LiveServerRequired("run_monitor", "s", try_instead=[])
        assert exc.try_instead == []
        assert "Try these tools instead" not in str(exc)

    def test_existing_message_shape_preserved(self):
        exc = LiveServerRequired("run_monitor", "offline-test", mode="offline")
        message = str(exc)
        assert "'run_monitor' requires a running server" in message
        assert "is_offline=True" in message


# ---------------------------------------------------------------------------
# Unit: format_tool_error surfaces try_instead
# ---------------------------------------------------------------------------


class TestFormatToolErrorTryInstead:
    def _mcp_stub(self):
        class Stub:
            privacy_enabled = False
            debug_enabled = False

        return Stub()

    def test_mode_error_contributes_key(self):
        exc = LiveServerRequired("get_performance_summary", "offline-test")
        result = format_tool_error(exc, self._mcp_stub(), "performance_summary")
        assert result["try_instead"] == OFFLINE_ALTERNATIVES["get_performance_summary"]

    def test_plain_exception_has_no_key(self):
        result = format_tool_error(ValueError("boom"), self._mcp_stub(), "x")
        assert "try_instead" not in result


# ---------------------------------------------------------------------------
# Rot guard: every suggested (and mapped) name is a real registered tool
# ---------------------------------------------------------------------------


class TestSuggestionsReferenceRealTools:
    async def test_all_suggestions_are_registered_tools(self, clean_env):
        server = DirSrvMCP(servers=[_remote_config()], include_env_fallback=False)
        async with Client(server) as client:
            registered = {t.name for t in await client.list_tools()}

        suggested = set(DEFAULT_OFFLINE_ALTERNATIVES)
        for alternatives in OFFLINE_ALTERNATIVES.values():
            suggested.update(alternatives)
        missing = suggested - registered
        assert not missing, f"try_instead suggests nonexistent tools: {missing}"

        # Mapping keys are the feature strings tools pass to require_live —
        # they must stay in sync with the actual tool names.
        stale_keys = set(OFFLINE_ALTERNATIVES) - registered
        assert not stale_keys, f"OFFLINE_ALTERNATIVES has stale keys: {stale_keys}"


# ---------------------------------------------------------------------------
# Client-level: guards teach the workflow end to end
# ---------------------------------------------------------------------------


class TestGuardsThroughClient:
    async def test_live_tool_on_archive_names_alternatives(self, clean_env):
        server = DirSrvMCP(servers=[_archive_config()], include_env_fallback=False)
        async with Client(server) as client:
            with pytest.raises(Exception) as exc_info:
                await client.call_tool(
                    "get_replication_status", {"server_name": "sos-archive"}
                )
        message = str(exc_info.value)
        assert "Try these tools instead" in message
        assert "compare_dse_configs" in message

    async def test_live_tool_on_offline_names_alternatives(self, clean_env):
        server = DirSrvMCP(servers=[_offline_config()], include_env_fallback=False)
        async with Client(server) as client:
            with pytest.raises(Exception) as exc_info:
                await client.call_tool("list_all_users", {"server_name": "offline-test"})
        message = str(exc_info.value)
        assert "analyze_access_log" in message

    async def test_archive_tool_on_live_returns_try_instead(self, clean_env):
        server = DirSrvMCP(servers=[_remote_config()], include_env_fallback=False)
        async with Client(server) as client:
            result = await client.call_tool(
                "analyze_archive", {"server_name": "remote-live"}
            )
        data = result.data
        assert "error" in data
        assert data["try_instead"] == [
            "first_look",
            "run_healthcheck",
            "get_server_configuration",
        ]

    async def test_compare_dse_on_live_returns_try_instead(self, clean_env):
        server = DirSrvMCP(
            servers=[_remote_config(), _archive_config()], include_env_fallback=False
        )
        async with Client(server) as client:
            result = await client.call_tool(
                "compare_dse_configs",
                {"server1": "remote-live", "server2": "sos-archive"},
            )
        assert result.data["try_instead"] == ["compare_server_configurations"]

    async def test_log_tool_on_remote_returns_try_instead(self, clean_env):
        server = DirSrvMCP(servers=[_remote_config()], include_env_fallback=False)
        async with Client(server) as client:
            result = await client.call_tool(
                "analyze_access_log", {"server_name": "remote-live"}
            )
        data = result.data
        assert "error" in data
        assert "get_connection_statistics" in data["try_instead"]

    async def test_try_instead_survives_privacy_mode(self):
        """Tool names are public schema — the privacy scrub must not eat them."""
        env = {"LDAP_SERVERS_CONFIG": ""}
        with patch.dict(os.environ, env):
            server = DirSrvMCP(
                servers=[_remote_config()],
                settings=MCPSettings(),  # privacy mode on (default)
                include_env_fallback=False,
            )
        async with Client(server) as client:
            result = await client.call_tool(
                "analyze_archive", {"server_name": "remote-live"}
            )
        data = result.data
        assert data["try_instead"] == [
            "first_look",
            "run_healthcheck",
            "get_server_configuration",
        ]
