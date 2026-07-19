"""Phase 0 connection-path robustness tests.

Covers:
- UnknownServer / ConnectionFailed ToolError subclasses (mask_error_details safe)
- require_live_server raising UnknownServer instead of silently returning
- LDAP network/operation timeouts set in connect() (LDAP_CONNECT_TIMEOUT knob)
- connect() to an unreachable host failing fast with ConnectionFailed
- Remote LDAPS certificate verification (tls_verify) plumbing
- ResponseSizeMiddleware guarding structured_content

No live LDAP server is required: connections are mocked or pointed at a
closed local port.
"""

from __future__ import annotations

import time
from unittest.mock import MagicMock, patch

import ldap
import pytest
from fastmcp.exceptions import ToolError

from ldap_assistant_mcp.config.loader import ServerListConfig, _server_config_from_dict
from ldap_assistant_mcp.core import LDAPServerConfig
from ldap_assistant_mcp.dirsrv_mcp.connection import (
    DEFAULT_CONNECT_TIMEOUT,
    ConnectionFailed,
    ConnectionManager,
    LiveServerRequired,
    ServerConfig,
    UnknownServer,
    _get_connect_timeout,
    is_local_server,
    require_live_server,
)
from ldap_assistant_mcp.dirsrv_mcp.middleware import ResponseSizeMiddleware


def _live_config(name: str = "live", **overrides) -> ServerConfig:
    defaults = dict(
        name=name,
        ldap_url="ldap://localhost:389",
        base_dn="dc=test,dc=com",
        bind_dn="cn=Directory Manager",
        bind_password="secret",
    )
    defaults.update(overrides)
    return ServerConfig(**defaults)


# ---------------------------------------------------------------------------
# UnknownServer
# ---------------------------------------------------------------------------


class TestUnknownServer:
    def test_get_config_unknown_raises_unknown_server(self):
        cm = ConnectionManager()
        with pytest.raises(UnknownServer) as exc_info:
            cm.get_config("ghost")
        assert "ghost" in str(exc_info.value)
        assert "not configured" in str(exc_info.value)

    def test_unknown_server_is_tool_error_and_key_error(self):
        """ToolError so mask_error_details passes it through; KeyError for backcompat."""
        exc = UnknownServer("ghost")
        assert isinstance(exc, ToolError)
        assert isinstance(exc, KeyError)

    def test_unknown_server_str_is_plain_message(self):
        """KeyError.__str__ would repr() the message — ours must stay readable."""
        exc = UnknownServer("ghost")
        assert not str(exc).startswith("'")
        assert str(exc).startswith("Server 'ghost'")

    def test_unknown_server_lists_available_servers(self):
        cm = ConnectionManager()
        cm.add_server(_live_config(name="prod-1"))
        with pytest.raises(UnknownServer) as exc_info:
            cm.get_config("ghost")
        assert "prod-1" in str(exc_info.value)

    def test_connect_unknown_raises_unknown_server(self):
        cm = ConnectionManager()
        with pytest.raises(UnknownServer):
            cm.connect("ghost")

    def test_predicate_helpers_still_return_false_for_unknown(self):
        """Boolean predicates must keep returning False (UnknownServer is a KeyError)."""
        cm = ConnectionManager()
        assert is_local_server(cm, "ghost") is False


# ---------------------------------------------------------------------------
# require_live_server
# ---------------------------------------------------------------------------


class TestRequireLiveServer:
    def test_unknown_server_raises(self):
        """Previously it silently returned for unknown names."""
        cm = ConnectionManager()
        with pytest.raises(UnknownServer):
            require_live_server(cm, "ghost", "ldap_search")

    def test_offline_server_still_raises_live_required(self):
        cm = ConnectionManager()
        cm.add_server(
            _live_config(
                name="offline",
                is_local=True,
                serverid="standalone",
                is_offline=True,
            )
        )
        with pytest.raises(LiveServerRequired):
            require_live_server(cm, "offline", "ldap_search")

    def test_live_server_passes(self):
        cm = ConnectionManager()
        cm.add_server(_live_config(name="live"))
        require_live_server(cm, "live", "ldap_search")  # Should not raise


# ---------------------------------------------------------------------------
# Connect timeout knob
# ---------------------------------------------------------------------------


class TestConnectTimeout:
    def test_default(self, monkeypatch):
        monkeypatch.delenv("LDAP_CONNECT_TIMEOUT", raising=False)
        assert _get_connect_timeout() == DEFAULT_CONNECT_TIMEOUT

    def test_env_override(self, monkeypatch):
        monkeypatch.setenv("LDAP_CONNECT_TIMEOUT", "7.5")
        assert _get_connect_timeout() == 7.5

    def test_invalid_value_falls_back(self, monkeypatch):
        monkeypatch.setenv("LDAP_CONNECT_TIMEOUT", "bogus")
        assert _get_connect_timeout() == DEFAULT_CONNECT_TIMEOUT

    def test_non_positive_value_falls_back(self, monkeypatch):
        monkeypatch.setenv("LDAP_CONNECT_TIMEOUT", "-1")
        assert _get_connect_timeout() == DEFAULT_CONNECT_TIMEOUT

    def test_connect_sets_ldap_timeouts(self, monkeypatch):
        """connect() must set OPT_NETWORK_TIMEOUT and OPT_TIMEOUT before open()."""
        monkeypatch.setenv("LDAP_CONNECT_TIMEOUT", "11")
        cm = ConnectionManager()
        cm.add_server(_live_config(name="t"))

        with patch("ldap_assistant_mcp.dirsrv_mcp.connection.DirSrv") as mock_dirsrv, \
                patch("ldap_assistant_mcp.dirsrv_mcp.connection.ldap.set_option") as mock_set:
            mock_dirsrv.return_value = MagicMock()
            cm.connect("t")

        opts = {call.args[0]: call.args[1] for call in mock_set.call_args_list}
        assert opts.get(ldap.OPT_NETWORK_TIMEOUT) == 11.0
        assert opts.get(ldap.OPT_TIMEOUT) == 11.0


# ---------------------------------------------------------------------------
# ConnectionFailed
# ---------------------------------------------------------------------------


class TestConnectionFailed:
    def test_is_tool_error_and_connection_error(self):
        exc = ConnectionFailed("boom")
        assert isinstance(exc, ToolError)
        assert isinstance(exc, ConnectionError)

    def test_unreachable_host_raises_connection_failed_quickly(self, monkeypatch):
        """Closed local port → ldap.SERVER_DOWN → ConnectionFailed, fast."""
        monkeypatch.setenv("LDAP_CONNECT_TIMEOUT", "2")
        cm = ConnectionManager()
        # Port 9 (discard) on loopback is refused immediately on any sane host.
        cm.add_server(_live_config(name="dead", ldap_url="ldap://127.0.0.1:9"))

        start = time.monotonic()
        with pytest.raises(ConnectionFailed) as exc_info:
            cm.connect("dead")
        elapsed = time.monotonic() - start

        assert elapsed < 5.0, f"connect() took {elapsed:.1f}s — timeout not applied"
        message = str(exc_info.value)
        assert "dead" in message
        assert "unreachable" in message or "connect" in message.lower()

    def test_invalid_credentials_raises_connection_failed(self):
        cm = ConnectionManager()
        cm.add_server(_live_config(name="badpw"))

        with patch("ldap_assistant_mcp.dirsrv_mcp.connection.DirSrv") as mock_dirsrv:
            mock_ds = MagicMock()
            mock_ds.open.side_effect = ldap.INVALID_CREDENTIALS({"desc": "Invalid credentials"})
            mock_dirsrv.return_value = mock_ds
            with pytest.raises(ConnectionFailed) as exc_info:
                cm.connect("badpw")

        assert "bind_dn" in str(exc_info.value)

    def test_anonymous_denied_raises_connection_failed(self):
        """The anonymous-bind guidance must survive mask_error_details."""
        cm = ConnectionManager()
        cm.add_server(
            _live_config(name="anon", bind_dn="", bind_password="", auth_method="anonymous")
        )

        with patch("ldap_assistant_mcp.dirsrv_mcp.connection.DirSrv") as mock_dirsrv:
            mock_ds = MagicMock()
            mock_ds.open.side_effect = ldap.INAPPROPRIATE_AUTH({"desc": "no"})
            mock_dirsrv.return_value = mock_ds
            with pytest.raises(ConnectionFailed) as exc_info:
                cm.connect("anon")

        assert isinstance(exc_info.value, ToolError)
        assert "nsslapd-allow-anonymous-access" in str(exc_info.value)


# ---------------------------------------------------------------------------
# Remote LDAPS certificate verification (tls_verify)
# ---------------------------------------------------------------------------


class TestTlsVerify:
    def _connect_and_capture_open(self, config: ServerConfig):
        cm = ConnectionManager()
        cm.add_server(config)
        with patch("ldap_assistant_mcp.dirsrv_mcp.connection.DirSrv") as mock_dirsrv:
            mock_ds = MagicMock()
            mock_dirsrv.return_value = mock_ds
            cm.connect(config.name)
        return mock_ds.open

    def test_remote_ldaps_defaults_to_hard_verification(self):
        open_mock = self._connect_and_capture_open(
            _live_config(name="sec", ldap_url="ldaps://remote.example.com:636")
        )
        open_mock.assert_called_once_with(reqcert=ldap.OPT_X_TLS_HARD)

    def test_remote_ldaps_opt_out_uses_never(self):
        open_mock = self._connect_and_capture_open(
            _live_config(
                name="lab",
                ldap_url="ldaps://lab.example.com:636",
                tls_verify=False,
            )
        )
        open_mock.assert_called_once_with(reqcert=ldap.OPT_X_TLS_NEVER)

    def test_plain_ldap_does_not_force_reqcert(self):
        # allow_insecure_plaintext=True: a simple bind with
        # a password over ldap:// to a non-loopback host is refused unless
        # explicitly allowed; this test only cares about reqcert handling.
        open_mock = self._connect_and_capture_open(
            _live_config(
                name="plain",
                ldap_url="ldap://remote.example.com:389",
                allow_insecure_plaintext=True,
            )
        )
        open_mock.assert_called_once_with()

    def test_local_ldaps_keeps_lib389_certdir_behavior(self):
        open_mock = self._connect_and_capture_open(
            _live_config(
                name="local-tls",
                ldap_url="ldaps://localhost:636",
                is_local=True,
                serverid="standalone",
            )
        )
        open_mock.assert_called_once_with()

    def test_server_config_default_is_true(self):
        assert _live_config().tls_verify is True

    def test_json_config_parses_tls_verify_false(self):
        cfg = _server_config_from_dict(
            {
                "name": "s",
                "ldap_url": "ldaps://h.example.com:636",
                "bind_dn": "cn=dm",
                "bind_password": "x",
                "tls_verify": False,
            }
        )
        assert cfg.tls_verify is False

    def test_json_config_defaults_to_true(self, monkeypatch):
        monkeypatch.delenv("LDAP_TLS_VERIFY", raising=False)
        cfg = _server_config_from_dict(
            {"name": "s", "ldap_url": "ldaps://h.example.com:636"}
        )
        assert cfg.tls_verify is True

    def test_json_config_falls_back_to_env(self, monkeypatch):
        monkeypatch.setenv("LDAP_TLS_VERIFY", "false")
        cfg = _server_config_from_dict(
            {"name": "s", "ldap_url": "ldaps://h.example.com:636"}
        )
        assert cfg.tls_verify is False

    def test_json_field_wins_over_env(self, monkeypatch):
        monkeypatch.setenv("LDAP_TLS_VERIFY", "false")
        cfg = _server_config_from_dict(
            {"name": "s", "ldap_url": "ldaps://h.example.com:636", "tls_verify": True}
        )
        assert cfg.tls_verify is True

    def test_core_from_env_parses_tls_verify(self, monkeypatch):
        monkeypatch.setenv("LDAP_TLS_VERIFY", "false")
        assert LDAPServerConfig.from_env().tls_verify is False
        monkeypatch.delenv("LDAP_TLS_VERIFY")
        assert LDAPServerConfig.from_env().tls_verify is True

    def test_tls_verify_propagates_through_add_server(self):
        cm = ConnectionManager()
        cm.add_server(
            LDAPServerConfig(
                name="conv",
                hostname="remote.example.com",
                port=636,
                use_ssl=True,
                bind_dn="cn=dm",
                bind_password="x",
                tls_verify=False,
            )
        )
        assert cm.get_config("conv").tls_verify is False

    def test_server_list_round_trip_preserves_tls_verify(self):
        config = ServerListConfig.from_dict(
            {
                "servers": [
                    {
                        "name": "lab",
                        "ldap_url": "ldaps://lab.example.com:636",
                        "bind_dn": "cn=dm",
                        "bind_password": "x",
                        "tls_verify": False,
                    }
                ]
            }
        )
        assert config.servers[0].tls_verify is False
        dumped = config.to_dict()
        assert dumped["servers"][0]["tls_verify"] is False
        reloaded = ServerListConfig.from_dict(dumped)
        assert reloaded.servers[0].tls_verify is False


# ---------------------------------------------------------------------------
# ResponseSizeMiddleware structured_content guard
# ---------------------------------------------------------------------------


class _FakeTextItem:
    def __init__(self, text: str):
        self.text = text


class _FakeResult:
    def __init__(self, content=None, structured_content=None):
        self.content = content if content is not None else []
        self.structured_content = structured_content


class TestResponseSizeStructuredContent:
    def test_oversized_structured_content_raises_tool_error(self):
        """Oversize is a real tool error (isError=true), not a
        silently-replaced payload logged as success."""
        mw = ResponseSizeMiddleware(max_chars=100)
        result = _FakeResult(structured_content={"data": "x" * 500})
        with pytest.raises(ToolError) as exc:
            mw._guard(result)
        assert "Response too large" in str(exc.value)
        assert "LAMCP-OVERSIZE-001" in str(exc.value)

    def test_small_structured_content_untouched(self):
        mw = ResponseSizeMiddleware(max_chars=100)
        result = _FakeResult(structured_content={"ok": True})
        assert mw._guard(result).structured_content == {"ok": True}

    def test_none_structured_content_untouched(self):
        mw = ResponseSizeMiddleware(max_chars=100)
        result = _FakeResult(structured_content=None)
        assert mw._guard(result).structured_content is None

    def test_text_truncation_still_works(self):
        mw = ResponseSizeMiddleware(max_chars=100)
        result = _FakeResult(content=[_FakeTextItem("y" * 500)])
        guarded = mw._guard(result)
        text = guarded.content[0].text
        assert "[TRUNCATED" in text
        assert len(text) < 500

    def test_real_fastmcp_toolresult_oversize_raises(self):
        from fastmcp.tools.tool import ToolResult

        mw = ResponseSizeMiddleware(max_chars=100)
        result = ToolResult(structured_content={"data": "z" * 500})
        with pytest.raises(ToolError):
            mw._guard(result)

    def test_oversize_error_names_the_limit(self):
        mw = ResponseSizeMiddleware(max_chars=1000)
        result = _FakeResult(structured_content={"data": "x" * 5000})
        with pytest.raises(ToolError) as exc:
            mw._guard(result)
        assert "1000" in str(exc.value)
