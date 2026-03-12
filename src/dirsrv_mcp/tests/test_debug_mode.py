"""Tests for debug mode and error formatting utilities.

Tests verify that:
1. MCPSettings debug field defaults and from_env() behavior
2. Config loader parses debug from JSON with env fallback
3. format_error_message includes exception type name
4. format_tool_error produces correct dict (with/without debug)
5. Debug mode sets logger level to DEBUG
6. ConnectionManager.debug propagates from DirSrvMCP
"""

from __future__ import annotations

import logging
import os
from unittest.mock import MagicMock, patch

import pytest

from src.config.loader import ServerListConfig, _settings_from_dict
from src.dirsrv_mcp.connection import ConnectionManager
from src.dirsrv_mcp.server import DirSrvMCP
from src.dirsrv_mcp.tools.error_utils import format_error_message, format_tool_error
from src.ldap_assistant_mcp.server import LDAPServerConfig, MCPSettings


def test_mcp_settings_debug_default():
    """Debug should default to False."""
    settings = MCPSettings()
    assert settings.debug is False


def test_mcp_settings_to_dict_includes_debug():
    """to_dict() should include the debug key."""
    settings = MCPSettings(debug=True)
    d = settings.to_dict()
    assert "debug" in d
    assert d["debug"] is True


def test_mcp_settings_to_dict_debug_false():
    """to_dict() should include debug=False by default."""
    settings = MCPSettings()
    d = settings.to_dict()
    assert d["debug"] is False


def test_from_env_debug_default():
    """from_env() should return debug=False when env var is not set."""
    with patch.dict(os.environ, {}, clear=True):
        settings = MCPSettings.from_env()
        assert settings.debug is False


def test_from_env_debug_true():
    """from_env() should read LDAP_MCP_DEBUG=true."""
    with patch.dict(os.environ, {"LDAP_MCP_DEBUG": "true"}):
        settings = MCPSettings.from_env()
        assert settings.debug is True


def test_from_env_debug_truthy_values():
    """from_env() should accept various truthy values for LDAP_MCP_DEBUG."""
    for value in ["1", "true", "True", "TRUE", "yes", "YES", "on", "ON"]:
        with patch.dict(os.environ, {"LDAP_MCP_DEBUG": value}):
            settings = MCPSettings.from_env()
            assert settings.debug is True, f"Should accept '{value}' as True"


def test_from_env_debug_falsy_values():
    """from_env() should treat non-truthy values as False."""
    for value in ["0", "false", "no", "off", "", "maybe"]:
        with patch.dict(os.environ, {"LDAP_MCP_DEBUG": value}):
            settings = MCPSettings.from_env()
            assert settings.debug is False, f"Should treat '{value}' as False"


def test_settings_from_dict_debug_true():
    """Config loader should parse debug=true from JSON data."""
    with patch.dict(os.environ, {}, clear=True):
        settings = _settings_from_dict({"debug": True})
        assert settings.debug is True


def test_settings_from_dict_debug_false():
    """Config loader should parse debug=false from JSON data."""
    with patch.dict(os.environ, {"LDAP_MCP_DEBUG": "true"}, clear=True):
        settings = _settings_from_dict({"debug": False})
        assert settings.debug is False


def test_settings_from_dict_debug_string():
    """Config loader should handle string 'true' for debug."""
    with patch.dict(os.environ, {}, clear=True):
        settings = _settings_from_dict({"debug": "true"})
        assert settings.debug is True


def test_settings_from_dict_debug_env_fallback():
    """Config loader should fallback to env var when debug is not in JSON."""
    with patch.dict(os.environ, {"LDAP_MCP_DEBUG": "true"}, clear=True):
        settings = _settings_from_dict({})
        assert settings.debug is True


def test_settings_from_dict_no_debug_no_env():
    """Config loader should default to False when no JSON key and no env."""
    with patch.dict(os.environ, {}, clear=True):
        settings = _settings_from_dict({})
        assert settings.debug is False


def test_server_list_config_from_dict_with_debug():
    """ServerListConfig.from_dict should propagate debug setting."""
    data = {
        "servers": [
            {
                "name": "test",
                "hostname": "localhost",
                "port": 389,
            }
        ],
        "settings": {
            "expose_sensitive_data": True,
            "debug": True,
        },
    }
    with patch.dict(os.environ, {}, clear=True):
        config = ServerListConfig.from_dict(data)
        assert config.settings.debug is True


def test_format_error_message_includes_type():
    """Should prepend exception type name."""
    exc = ValueError("bad value")
    msg = format_error_message(exc)
    assert msg == "ValueError: bad value"


def test_format_error_message_index_error():
    """Should work with IndexError (the motivating example)."""
    exc = IndexError("list index out of range")
    msg = format_error_message(exc)
    assert msg == "IndexError: list index out of range"


def test_format_error_message_runtime_error():
    """Should work with RuntimeError."""
    exc = RuntimeError("something broke")
    msg = format_error_message(exc)
    assert msg == "RuntimeError: something broke"


def test_format_error_message_key_error():
    """Should work with KeyError."""
    exc = KeyError("missing")
    msg = format_error_message(exc)
    assert msg.startswith("KeyError:")


def test_format_error_message_custom_exception():
    """Should work with custom exception classes."""

    class MyCustomError(Exception):
        pass

    exc = MyCustomError("custom problem")
    msg = format_error_message(exc)
    assert msg == "MyCustomError: custom problem"


def test_format_error_message_preserves_original():
    """Original error message should be included after the type."""
    exc = TypeError("unsupported operand")
    msg = format_error_message(exc)
    assert "unsupported operand" in msg
    assert msg.startswith("TypeError:")


def _make_mcp_mock(debug_enabled=False, privacy_enabled=False):
    """Create a mock MCP object with debug_enabled and privacy_enabled properties."""
    mcp = MagicMock()
    mcp.debug_enabled = debug_enabled
    mcp.privacy_enabled = privacy_enabled
    return mcp


def test_format_tool_error_basic():
    """Should build a standard error dict."""
    mcp = _make_mcp_mock(debug_enabled=False)
    exc = ValueError("bad input")
    result = format_tool_error(exc, mcp, "test_type")
    assert result["type"] == "test_type"
    assert result["error"] == "ValueError: bad input"
    assert "traceback" not in result


def test_format_tool_error_with_server():
    """Should include server key when provided."""
    mcp = _make_mcp_mock(debug_enabled=False)
    exc = RuntimeError("fail")
    result = format_tool_error(exc, mcp, "test_type", server="my-server")
    assert result["server"] == "my-server"
    assert result["error"] == "RuntimeError: fail"
    assert "traceback" not in result


def test_format_tool_error_without_server():
    """Should omit server key when not provided."""
    mcp = _make_mcp_mock(debug_enabled=False)
    exc = RuntimeError("fail")
    result = format_tool_error(exc, mcp, "test_type")
    assert "server" not in result


def test_format_tool_error_extra_kwargs():
    """Should pass through extra keyword arguments."""
    mcp = _make_mcp_mock(debug_enabled=False)
    exc = RuntimeError("fail")
    result = format_tool_error(
        exc, mcp, "dse_comparison", server1="s1", server2="s2"
    )
    assert result["server1"] == "s1"
    assert result["server2"] == "s2"
    assert result["type"] == "dse_comparison"


def test_format_tool_error_debug_includes_traceback():
    """Should include traceback when debug is enabled."""
    mcp = _make_mcp_mock(debug_enabled=True)
    try:
        raise ValueError("test error for traceback")
    except ValueError as exc:
        result = format_tool_error(exc, mcp, "test_type")
    assert "traceback" in result
    assert isinstance(result["traceback"], list)
    assert len(result["traceback"]) > 0
    tb_text = "".join(result["traceback"])
    assert "test error for traceback" in tb_text
    assert "ValueError" in tb_text


def test_format_tool_error_debug_still_has_error_key():
    """Debug mode should still have the error string."""
    mcp = _make_mcp_mock(debug_enabled=True)
    try:
        raise IndexError("out of range")
    except IndexError as exc:
        result = format_tool_error(exc, mcp, "test_type")
    assert result["error"] == "IndexError: out of range"
    assert "traceback" in result


def test_format_tool_error_no_traceback_when_no_debug():
    """Should NOT include traceback when debug is disabled."""
    mcp = _make_mcp_mock(debug_enabled=False)
    try:
        raise ValueError("no traceback please")
    except ValueError as exc:
        result = format_tool_error(exc, mcp, "test_type")
    assert "traceback" not in result


def _make_test_server():
    """Create a minimal server config for testing."""
    return LDAPServerConfig(
        name="test-debug",
        hostname="localhost",
        port=389,
    )


def test_dirsrv_mcp_debug_enabled_false():
    """debug_enabled should be False by default."""
    env = {
        "LDAP_MCP_EXPOSE_SENSITIVE_DATA": "true",
        "LDAP_SERVERS_CONFIG": "",
    }
    with patch.dict(os.environ, env):
        mcp = DirSrvMCP(
            servers=[_make_test_server()],
            settings=MCPSettings(debug=False),
            include_env_fallback=False,
        )
        assert mcp.debug_enabled is False


def test_dirsrv_mcp_debug_enabled_true():
    """debug_enabled should reflect settings."""
    env = {
        "LDAP_MCP_EXPOSE_SENSITIVE_DATA": "true",
        "LDAP_SERVERS_CONFIG": "",
    }
    with patch.dict(os.environ, env):
        mcp = DirSrvMCP(
            servers=[_make_test_server()],
            settings=MCPSettings(debug=True),
            include_env_fallback=False,
        )
        assert mcp.debug_enabled is True


def test_debug_mode_sets_log_level():
    """When debug=True, DirSrvMCP logger should be set to DEBUG."""
    env = {
        "LDAP_MCP_EXPOSE_SENSITIVE_DATA": "true",
        "LDAP_SERVERS_CONFIG": "",
    }
    with patch.dict(os.environ, env):
        mcp = DirSrvMCP(
            servers=[_make_test_server()],
            settings=MCPSettings(debug=True),
            include_env_fallback=False,
        )
        assert mcp.logger.level == logging.DEBUG


def test_no_debug_does_not_force_debug_level():
    """When debug=False, DirSrvMCP should NOT set the logger to DEBUG."""
    logging.getLogger("DirSrvMCP").setLevel(logging.WARNING)

    env = {
        "LDAP_MCP_EXPOSE_SENSITIVE_DATA": "true",
        "LDAP_SERVERS_CONFIG": "",
    }
    with patch.dict(os.environ, env):
        mcp = DirSrvMCP(
            servers=[_make_test_server()],
            settings=MCPSettings(debug=False),
            include_env_fallback=False,
        )
        assert mcp.logger.level != logging.DEBUG


def test_connection_manager_debug_default():
    """ConnectionManager.debug should default to False."""
    mgr = ConnectionManager()
    assert mgr.debug is False


def test_connection_manager_debug_set():
    """ConnectionManager.debug can be set to True."""
    mgr = ConnectionManager()
    mgr.debug = True
    assert mgr.debug is True


def test_dirsrv_mcp_propagates_debug_to_connection_manager():
    """DirSrvMCP should set connection_manager.debug when debug is enabled."""
    env = {
        "LDAP_MCP_EXPOSE_SENSITIVE_DATA": "true",
        "LDAP_SERVERS_CONFIG": "",
    }
    with patch.dict(os.environ, env):
        mcp = DirSrvMCP(
            servers=[_make_test_server()],
            settings=MCPSettings(debug=True),
            include_env_fallback=False,
        )
        assert mcp.connection_manager.debug is True


def test_dirsrv_mcp_no_debug_connection_manager_stays_false():
    """ConnectionManager.debug should stay False when debug is disabled."""
    env = {
        "LDAP_MCP_EXPOSE_SENSITIVE_DATA": "true",
        "LDAP_SERVERS_CONFIG": "",
    }
    with patch.dict(os.environ, env):
        mcp = DirSrvMCP(
            servers=[_make_test_server()],
            settings=MCPSettings(debug=False),
            include_env_fallback=False,
        )
        assert mcp.connection_manager.debug is False


def test_format_error_message_returns_string():
    """format_error_message should always return a str."""
    exc = ValueError("test")
    result = format_error_message(exc)
    assert isinstance(result, str)


def test_format_tool_error_error_is_string():
    """The 'error' value in format_tool_error result should be a string."""
    mcp = _make_mcp_mock(debug_enabled=True)
    try:
        raise RuntimeError("test")
    except RuntimeError as exc:
        result = format_tool_error(exc, mcp, "test_type")
    assert isinstance(result["error"], str)


def test_format_error_message_preserves_searchability():
    """Original message should be searchable (e.g. 'offline' in error.lower())."""
    exc = RuntimeError("Offline mode not supported for this operation")
    msg = format_error_message(exc)
    assert "offline" in msg.lower()
    assert "RuntimeError" in msg
