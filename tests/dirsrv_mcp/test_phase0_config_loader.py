"""Phase 0 regression tests: config-load failures and resource error handling.

Covers IMPROVEMENT-PLAN.md items 0.4 and two rows of 0.6:

- Explicitly requested config files (config_path argument or
  LDAP_SERVERS_CONFIG env var) that fail to load must raise a clear error
  including the file path and the underlying cause, instead of silently
  booting with only the env-fallback phantom server.
- Env-only operation (no explicit config) must keep working unchanged.
- MCP resources must not leak raw exception text (LDAP URIs, bind DNs,
  hostnames) past the privacy sanitizer, and must reject offline/archive
  servers with a clear live-mode error.

Tests use tmp_path JSON files and mocks only — no live LDAP server needed.
"""

from __future__ import annotations

import json
from unittest.mock import MagicMock, patch

import pytest
from fastmcp import Client

from ldap_assistant_mcp.dirsrv_mcp.server import DirSrvMCP
from ldap_assistant_mcp.core import LDAPServerConfig, MCPSettings


VALID_SERVER = {
    "name": "test-server",
    "ldap_url": "ldap://ldap.example.com:389",
    "base_dn": "dc=example,dc=com",
    "bind_dn": "cn=Directory Manager",
    "bind_password": "Secret.123",
}


@pytest.fixture(autouse=True)
def clean_config_env(monkeypatch):
    """Isolate tests from any LDAP_SERVERS_CONFIG set in the outer environment."""
    monkeypatch.delenv("LDAP_SERVERS_CONFIG", raising=False)


def _write_config(tmp_path, data, name="servers.json"):
    """Write *data* as JSON (or raw text if a string) and return the path."""
    path = tmp_path / name
    if isinstance(data, str):
        path.write_text(data)
    else:
        path.write_text(json.dumps(data))
    return str(path)


# ---------------------------------------------------------------------------
# Item 0.4 — explicit config failures must raise, not warn
# ---------------------------------------------------------------------------


def test_malformed_json_raises_with_path_and_cause(tmp_path):
    config_path = _write_config(tmp_path, "{ this is not json")

    with pytest.raises(RuntimeError) as excinfo:
        DirSrvMCP(config_path=config_path)

    msg = str(excinfo.value)
    assert config_path in msg
    assert "JSONDecodeError" in msg
    assert isinstance(excinfo.value.__cause__, json.JSONDecodeError)


def test_nonexistent_path_raises_with_path(tmp_path):
    config_path = str(tmp_path / "does-not-exist.json")

    with pytest.raises(RuntimeError) as excinfo:
        DirSrvMCP(config_path=config_path)

    msg = str(excinfo.value)
    assert config_path in msg
    assert "FileNotFoundError" in msg
    assert isinstance(excinfo.value.__cause__, FileNotFoundError)


def test_missing_required_keys_raises(tmp_path):
    # Server entry with neither hostname nor ldap_url
    config_path = _write_config(tmp_path, {"servers": [{"name": "broken"}]})

    with pytest.raises(RuntimeError) as excinfo:
        DirSrvMCP(config_path=config_path)

    msg = str(excinfo.value)
    assert config_path in msg
    assert "hostname or ldap_url" in msg


def test_bad_port_type_raises(tmp_path):
    server = dict(VALID_SERVER)
    del server["ldap_url"]
    server["hostname"] = "ldap.example.com"
    server["port"] = "not-a-number"
    config_path = _write_config(tmp_path, {"servers": [server]})

    with pytest.raises(RuntimeError) as excinfo:
        DirSrvMCP(config_path=config_path)

    msg = str(excinfo.value)
    assert config_path in msg
    assert "port" in msg
    assert "not-a-number" in msg


def test_bad_settings_tool_timeout_raises(tmp_path):
    config_path = _write_config(
        tmp_path,
        {"servers": [dict(VALID_SERVER)], "settings": {"tool_timeout": "abc"}},
    )

    with pytest.raises(RuntimeError) as excinfo:
        DirSrvMCP(config_path=config_path)

    msg = str(excinfo.value)
    assert config_path in msg
    assert "tool_timeout" in msg
    assert "abc" in msg


def test_bad_settings_max_tool_timeout_raises(tmp_path):
    config_path = _write_config(
        tmp_path,
        {"servers": [dict(VALID_SERVER)], "settings": {"max_tool_timeout": [1, 2]}},
    )

    with pytest.raises(RuntimeError) as excinfo:
        DirSrvMCP(config_path=config_path)

    assert "max_tool_timeout" in str(excinfo.value)


def test_env_var_config_failure_raises(tmp_path, monkeypatch):
    """A bad LDAP_SERVERS_CONFIG path is an explicit request and must raise."""
    missing = str(tmp_path / "missing-servers.json")
    monkeypatch.setenv("LDAP_SERVERS_CONFIG", missing)

    with pytest.raises(RuntimeError) as excinfo:
        DirSrvMCP()

    msg = str(excinfo.value)
    assert missing in msg
    assert "FileNotFoundError" in msg


def test_explicit_config_failure_raises_even_with_extra_servers(tmp_path):
    """Extra servers must not mask a failing explicitly-requested config."""
    config_path = _write_config(tmp_path, "{ bad json")
    extra = LDAPServerConfig(
        name="extra",
        hostname="localhost",
        port=3389,
        base_dn="dc=example,dc=com",
    )

    with pytest.raises(RuntimeError):
        DirSrvMCP(config_path=config_path, servers=[extra])


def test_env_fallback_only_still_works(monkeypatch):
    """No config_path and no LDAP_SERVERS_CONFIG: env fallback keeps working."""
    monkeypatch.setenv("LDAP_URL", "ldap://localhost:33891")
    monkeypatch.setenv("LDAP_BASE_DN", "dc=test,dc=com")
    monkeypatch.setenv("LDAP_BIND_DN", "cn=Directory Manager")

    server = DirSrvMCP()

    assert "default" in server.server_configs
    assert server.default_server == "default"
    assert server.server_configs["default"].hostname == "localhost"
    assert server.server_configs["default"].port == 33891


def test_valid_config_file_loads(tmp_path):
    config_path = _write_config(tmp_path, {"servers": [dict(VALID_SERVER)]})

    server = DirSrvMCP(config_path=config_path)

    assert "test-server" in server.server_configs
    assert server.server_configs["test-server"].hostname == "ldap.example.com"


# ---------------------------------------------------------------------------
# Item 0.6 — resource error sanitization and live-mode guard
# ---------------------------------------------------------------------------


def _offline_server_config() -> LDAPServerConfig:
    return LDAPServerConfig(
        name="offline-1",
        hostname="localhost",
        port=3389,
        base_dn="dc=example,dc=com",
        is_local=True,
        is_offline=True,
        serverid="testinst",
    )


def _archive_server_config(tmp_path) -> LDAPServerConfig:
    return LDAPServerConfig(
        name="archive-1",
        hostname="archive",
        port=0,
        base_dn="dc=example,dc=com",
        is_archive=True,
        archive_path=str(tmp_path),
    )


def _live_server_config() -> LDAPServerConfig:
    return LDAPServerConfig(
        name="live-1",
        hostname="ldap.example.com",
        port=3389,
        base_dn="dc=example,dc=com",
        bind_dn="cn=Directory Manager",
        bind_password="Secret.123",
    )


async def test_resource_config_all_rejects_offline_server():
    server = DirSrvMCP(servers=[_offline_server_config()], include_env_fallback=False)

    async with Client(server) as client:
        with pytest.raises(Exception) as excinfo:
            await client.read_resource("config://config-all")

    msg = str(excinfo.value)
    assert "requires a running server" in msg
    assert "offline-1" in msg


async def test_resource_config_attribute_rejects_archive_server(tmp_path):
    server = DirSrvMCP(servers=[_archive_server_config(tmp_path)], include_env_fallback=False)

    async with Client(server) as client:
        with pytest.raises(Exception) as excinfo:
            await client.read_resource("config://config-attribute/nsslapd-port")

    msg = str(excinfo.value)
    assert "requires a running server" in msg
    assert "archive-1" in msg


SENSITIVE_ERROR = (
    "Can't contact LDAP server ldap://secret-host.example.com:389 "
    "bound as cn=admin,dc=corp,dc=example"
)


async def test_resource_config_all_error_sanitized_in_privacy_mode():
    server = DirSrvMCP(
        servers=[_live_server_config()],
        include_env_fallback=False,
        settings=MCPSettings(expose_sensitive_data=False),
    )

    with patch.object(server.connection_manager, "connect", return_value=MagicMock()):
        with patch(
            "ldap_assistant_mcp.dirsrv_mcp.server.Config",
            side_effect=Exception(SENSITIVE_ERROR),
        ):
            async with Client(server) as client:
                with pytest.raises(Exception) as excinfo:
                    await client.read_resource("config://config-all")

    msg = str(excinfo.value)
    assert "Failed to retrieve cn=config attributes" in msg
    assert "secret-host" not in msg
    assert "dc=corp" not in msg
    assert "[ldap-url]" in msg


async def test_resource_config_attribute_error_sanitized_in_privacy_mode():
    server = DirSrvMCP(
        servers=[_live_server_config()],
        include_env_fallback=False,
        settings=MCPSettings(expose_sensitive_data=False),
    )

    with patch.object(server.connection_manager, "connect", return_value=MagicMock()):
        with patch(
            "ldap_assistant_mcp.dirsrv_mcp.server.Config",
            side_effect=Exception(SENSITIVE_ERROR),
        ):
            async with Client(server) as client:
                with pytest.raises(Exception) as excinfo:
                    await client.read_resource("config://config-attribute/nsslapd-port")

    msg = str(excinfo.value)
    assert "Failed to retrieve cn=config attribute" in msg
    assert "secret-host" not in msg
    assert "dc=corp" not in msg


async def test_resource_error_detail_visible_when_privacy_off():
    """With expose_sensitive_data=true the raw detail is kept (matches tools)."""
    server = DirSrvMCP(
        servers=[_live_server_config()],
        include_env_fallback=False,
        settings=MCPSettings(expose_sensitive_data=True),
    )

    with patch.object(server.connection_manager, "connect", return_value=MagicMock()):
        with patch(
            "ldap_assistant_mcp.dirsrv_mcp.server.Config",
            side_effect=Exception(SENSITIVE_ERROR),
        ):
            async with Client(server) as client:
                with pytest.raises(Exception) as excinfo:
                    await client.read_resource("config://config-all")

    msg = str(excinfo.value)
    assert "secret-host.example.com" in msg
