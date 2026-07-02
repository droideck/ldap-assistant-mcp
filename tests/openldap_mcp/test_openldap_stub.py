"""Smoke tests for the experimental OpenLDAP provider (IMPROVEMENT-PLAN 1.5.6).

The OpenLDAP provider is a two-tool stub that bypasses the privacy
sanitizer and middleware used by the 389 DS provider.  These tests pin
down what exists today: the server constructs, registers exactly its two
tools, warns loudly that it is experimental, and describe_connection
works without contacting any server.
"""

from __future__ import annotations

import logging
import os
from unittest.mock import patch

import pytest
from fastmcp import Client

from ldap_assistant_mcp.core import LDAPServerConfig
from ldap_assistant_mcp.openldap_mcp.server import OpenLDAPMCP


def _make_config() -> LDAPServerConfig:
    return LDAPServerConfig(
        name="openldap-test",
        hostname="ldap.example.com",
        port=389,
        base_dn="dc=example,dc=com",
        bind_dn="cn=admin,dc=example,dc=com",
        bind_password="secret",
        provider_type="openldap",
    )


def _make_server() -> OpenLDAPMCP:
    env = {k: v for k, v in os.environ.items() if k != "LDAP_SERVERS_CONFIG"}
    with patch.dict(os.environ, env, clear=True):
        return OpenLDAPMCP(servers=[_make_config()])


def test_constructs_and_warns_experimental(caplog):
    with caplog.at_level(logging.WARNING, logger="ldap_assistant_mcp.OpenLDAPMCP"):
        _make_server()
    warnings = [
        r.getMessage() for r in caplog.records
        if r.name == "ldap_assistant_mcp.OpenLDAPMCP"
    ]
    assert any("EXPERIMENTAL" in m for m in warnings), (
        "OpenLDAP provider must warn that it is experimental at startup"
    )


@pytest.mark.asyncio
async def test_registers_exactly_two_tools():
    server = _make_server()
    async with Client(server) as client:
        tools = await client.list_tools()
    assert sorted(t.name for t in tools) == ["describe_connection", "whoami"]


@pytest.mark.asyncio
async def test_describe_connection_reads_config_without_network():
    server = _make_server()
    async with Client(server) as client:
        result = await client.call_tool("describe_connection", {})
        data = result.data

    assert data["name"] == "openldap-test"
    assert data["hostname"] == "ldap.example.com"
    assert data["port"] == 389
    assert data["base_dn"] == "dc=example,dc=com"
    assert data["auth_method"] == "simple"


@pytest.mark.asyncio
async def test_provider_selectable_via_registry():
    from ldap_assistant_mcp.main import SERVER_REGISTRY

    definition = SERVER_REGISTRY["openldap"]
    assert definition.cls is OpenLDAPMCP
    assert definition.supports_config_path is False


# ---------------------------------------------------------------------------
# Phase 2.3: the OpenLDAP provider requires an explicit opt-in
# ---------------------------------------------------------------------------


def test_resolve_provider_openldap_requires_opt_in(monkeypatch):
    """LDAP_PROVIDER=openldap without the flag must error with guidance."""
    from ldap_assistant_mcp.main import _resolve_provider

    monkeypatch.delenv("LDAP_MCP_EXPERIMENTAL_OPENLDAP", raising=False)
    with pytest.raises(ValueError) as exc_info:
        _resolve_provider("openldap")
    message = str(exc_info.value)
    assert "LDAP_MCP_EXPERIMENTAL_OPENLDAP" in message
    assert "dirsrv" in message


def test_resolve_provider_openldap_with_opt_in(monkeypatch):
    from ldap_assistant_mcp.main import _resolve_provider

    monkeypatch.setenv("LDAP_MCP_EXPERIMENTAL_OPENLDAP", "true")
    requested, definition = _resolve_provider("openldap")
    assert requested == "openldap"
    assert definition.cls is OpenLDAPMCP


def test_resolve_provider_env_var_also_gated(monkeypatch):
    """The gate applies when the provider comes from LDAP_PROVIDER too."""
    from ldap_assistant_mcp.main import _resolve_provider

    monkeypatch.setenv("LDAP_PROVIDER", "openldap")
    monkeypatch.delenv("LDAP_MCP_EXPERIMENTAL_OPENLDAP", raising=False)
    with pytest.raises(ValueError, match="LDAP_MCP_EXPERIMENTAL_OPENLDAP"):
        _resolve_provider(None)


def test_resolve_provider_dirsrv_unaffected(monkeypatch):
    from ldap_assistant_mcp.main import DirSrvMCP, _resolve_provider

    monkeypatch.delenv("LDAP_MCP_EXPERIMENTAL_OPENLDAP", raising=False)
    monkeypatch.delenv("LDAP_PROVIDER", raising=False)
    requested, definition = _resolve_provider(None)
    assert requested == "dirsrv"
    assert definition.cls is DirSrvMCP
