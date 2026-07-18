"""Phase 2 release-blocker tests.

Config contract honesty:
- LDAP_IS_OFFLINE parsed by LDAPServerConfig.from_env (implies is_local,
  requires LDAP_SERVERID) — previously documented but silently ignored
- Clear config errors for invalid LDAP_PORT / LDAP_AUTH_METHOD values
- connect() rejects unimplemented sasl_* auth methods instead of silently
  degrading to a simple bind with an empty password
- connect() rejects is_offline configs missing is_local/serverid instead of
  falling through to a live bind

Privacy blockers:
- IPv4/IPv6 redaction in sanitize_text (bare, ports, CIDR, compressed,
  bracketed, zone-indexed) with deterministic per-session tokens
- Deny-by-default for unrecognized backend-result and finding-metadata keys
- Startup WARNING when expose_sensitive_data=true

No live LDAP server is required: connections are mocked.
"""

from __future__ import annotations

import logging
import os
from unittest.mock import MagicMock, patch

import pytest
from fastmcp.exceptions import ToolError

from ldap_assistant_mcp.core import LDAPServerConfig, MCPSettings
from ldap_assistant_mcp.dirsrv_mcp.connection import ConnectionManager, ServerConfig
from ldap_assistant_mcp.lib.privacy import PrivacySanitizer


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
# 2.1: LDAP_IS_OFFLINE in from_env
# ---------------------------------------------------------------------------


class TestFromEnvOffline:
    def test_offline_with_serverid_parses(self):
        env = {"LDAP_IS_OFFLINE": "true", "LDAP_SERVERID": "localhost"}
        with patch.dict(os.environ, env, clear=True):
            cfg = LDAPServerConfig.from_env()
        assert cfg.is_offline is True
        assert cfg.serverid == "localhost"

    def test_offline_implies_is_local(self):
        """Mirror of the JSON-loader invariant (loader.py)."""
        env = {"LDAP_IS_OFFLINE": "true", "LDAP_SERVERID": "localhost"}
        with patch.dict(os.environ, env, clear=True):
            cfg = LDAPServerConfig.from_env()
        assert cfg.is_local is True

    def test_offline_without_serverid_raises(self):
        with patch.dict(os.environ, {"LDAP_IS_OFFLINE": "true"}, clear=True):
            with pytest.raises(ValueError, match="LDAP_SERVERID"):
                LDAPServerConfig.from_env()

    def test_default_is_not_offline(self):
        with patch.dict(os.environ, {}, clear=True):
            cfg = LDAPServerConfig.from_env()
        assert cfg.is_offline is False

    def test_offline_false_value_ignored(self):
        env = {"LDAP_IS_OFFLINE": "false"}
        with patch.dict(os.environ, env, clear=True):
            cfg = LDAPServerConfig.from_env()
        assert cfg.is_offline is False
        assert cfg.is_local is False


# ---------------------------------------------------------------------------
# 2.1: clear config errors for bad env values
# ---------------------------------------------------------------------------


class TestFromEnvParseErrors:
    def test_invalid_port_names_the_variable(self):
        with patch.dict(os.environ, {"LDAP_PORT": "abc"}, clear=True):
            with pytest.raises(ValueError, match="LDAP_PORT"):
                LDAPServerConfig.from_env()

    def test_valid_port_still_parses(self):
        with patch.dict(os.environ, {"LDAP_PORT": "3389"}, clear=True):
            cfg = LDAPServerConfig.from_env()
        assert cfg.port == 3389

    def test_invalid_auth_method_names_the_variable_and_valid_values(self):
        with patch.dict(os.environ, {"LDAP_AUTH_METHOD": "kerberos"}, clear=True):
            with pytest.raises(ValueError) as exc_info:
                LDAPServerConfig.from_env()
        message = str(exc_info.value)
        assert "LDAP_AUTH_METHOD" in message
        assert "simple" in message
        assert "anonymous" in message

    def test_valid_auth_methods_still_parse(self):
        for value in ("simple", "anonymous", "SIMPLE"):
            with patch.dict(os.environ, {"LDAP_AUTH_METHOD": value}, clear=True):
                cfg = LDAPServerConfig.from_env()
            assert cfg.auth_method.value == value.lower()


# ---------------------------------------------------------------------------
# 2.1: connect() rejects unimplemented auth methods
# ---------------------------------------------------------------------------


class TestConnectAuthMethodRejection:
    @pytest.mark.parametrize(
        "method", ["sasl_gssapi", "sasl_digest_md5", "sasl_external"]
    )
    def test_sasl_methods_rejected_before_any_connection(self, method):
        cm = ConnectionManager()
        cm.add_server(_live_config(name="sasl", auth_method=method))

        with patch("ldap_assistant_mcp.dirsrv_mcp.connection.DirSrv") as mock_dirsrv:
            with pytest.raises(ToolError) as exc_info:
                cm.connect("sasl")

        mock_dirsrv.assert_not_called()
        message = str(exc_info.value)
        assert method in message
        assert "not implemented" in message
        assert "use_ldapi" in message

    def test_ldapi_ignores_auth_method(self):
        """LDAPI/SASL EXTERNAL is keyed off use_ldapi, not auth_method."""
        cm = ConnectionManager()
        cm.add_server(
            _live_config(
                name="ldapi",
                auth_method="sasl_external",
                is_local=True,
                serverid="standalone",
                use_ldapi=True,
            )
        )
        with patch("ldap_assistant_mcp.dirsrv_mcp.connection.DirSrv") as mock_dirsrv:
            mock_ds = MagicMock()
            mock_dirsrv.return_value = mock_ds
            cm.connect("ldapi")
        mock_ds.open.assert_called_once_with(saslmethod="EXTERNAL")

    def test_offline_ignores_auth_method(self):
        """Offline servers never bind, so any auth_method value is fine."""
        cm = ConnectionManager()
        cm.add_server(
            _live_config(
                name="off",
                auth_method="sasl_gssapi",
                is_local=True,
                serverid="standalone",
                is_offline=True,
            )
        )
        with patch("ldap_assistant_mcp.dirsrv_mcp.connection.DirSrv") as mock_dirsrv:
            mock_ds = MagicMock()
            mock_dirsrv.return_value = mock_ds
            cm.connect("off")
        mock_ds.open.assert_not_called()

    @pytest.mark.parametrize("method", ["simple", "anonymous"])
    def test_implemented_methods_pass_the_guard(self, method):
        cm = ConnectionManager()
        cm.add_server(_live_config(name="ok", auth_method=method))
        with patch("ldap_assistant_mcp.dirsrv_mcp.connection.DirSrv") as mock_dirsrv:
            mock_ds = MagicMock()
            mock_dirsrv.return_value = mock_ds
            cm.connect("ok")
        mock_ds.open.assert_called_once()


# ---------------------------------------------------------------------------
# 2.1: is_offline without is_local/serverid must not fall through to a bind
# ---------------------------------------------------------------------------


class TestConnectOfflineEdgeCase:
    @pytest.mark.parametrize(
        "overrides",
        [
            {"is_offline": True},  # neither is_local nor serverid
            {"is_offline": True, "is_local": True},  # no serverid
            {"is_offline": True, "serverid": "standalone"},  # not is_local
        ],
    )
    def test_incomplete_offline_config_raises_instead_of_binding(self, overrides):
        cm = ConnectionManager()
        cm.add_server(_live_config(name="broken-offline", **overrides))

        with patch("ldap_assistant_mcp.dirsrv_mcp.connection.DirSrv") as mock_dirsrv:
            with pytest.raises(ToolError) as exc_info:
                cm.connect("broken-offline")

        mock_dirsrv.assert_not_called()
        message = str(exc_info.value)
        assert "is_offline" in message
        assert "serverid" in message

    def test_complete_offline_config_returns_without_open(self):
        cm = ConnectionManager()
        cm.add_server(
            _live_config(
                name="offline",
                is_local=True,
                serverid="standalone",
                is_offline=True,
            )
        )
        with patch("ldap_assistant_mcp.dirsrv_mcp.connection.DirSrv") as mock_dirsrv:
            mock_ds = MagicMock()
            mock_dirsrv.return_value = mock_ds
            result = cm.connect("offline")
        assert result is mock_ds
        mock_ds.open.assert_not_called()


# ---------------------------------------------------------------------------
# 2.2: IP redaction in sanitize_text
# ---------------------------------------------------------------------------


class TestSanitizeTextIPv4:
    def setup_method(self):
        self.sanitizer = PrivacySanitizer()

    def test_bare_ipv4_redacted(self):
        out = self.sanitizer.sanitize_text("connection from 192.168.10.5 accepted")
        assert "192.168.10.5" not in out
        assert "[ip-" in out

    def test_deterministic_tokens(self):
        first = self.sanitizer.sanitize_text("peer 10.1.2.3")
        second = self.sanitizer.sanitize_text("again 10.1.2.3")
        other = self.sanitizer.sanitize_text("other 10.1.2.4")
        token = first.split()[1]
        assert token.startswith("[ip-")
        assert second.split()[1] == token
        assert other.split()[1] != token

    def test_ipv4_with_port(self):
        out = self.sanitizer.sanitize_text("listening on 10.0.0.1:389")
        assert "10.0.0.1" not in out
        assert ":[port]" in out
        assert ":389" not in out

    def test_ipv4_in_cidr(self):
        out = self.sanitizer.sanitize_text("subnet 10.0.0.0/24 allowed")
        assert "10.0.0.0" not in out
        assert "/24" in out

    def test_ipv4_inside_ldap_url_consumed_by_url_rule(self):
        out = self.sanitizer.sanitize_text("bind to ldap://10.1.2.3:389 failed")
        assert "[ldap-url]" in out
        assert "10.1.2.3" not in out

    def test_invalid_octets_not_matched(self):
        text = "id 999.999.999.999 stays"
        assert self.sanitizer.sanitize_text(text) == text

    def test_short_dotted_numbers_not_matched(self):
        text = "version 2.4.5 unchanged"
        assert self.sanitizer.sanitize_text(text) == text

    def test_four_component_version_over_redacted(self):
        # A 4-component version like 1.4.3.28 is indistinguishable from an
        # IPv4 address; over-redaction is the accepted failure mode.
        out = self.sanitizer.sanitize_text("389-ds-base 1.4.3.28")
        assert "1.4.3.28" not in out


class TestSanitizeTextIPv6:
    def setup_method(self):
        self.sanitizer = PrivacySanitizer()

    def test_full_form(self):
        out = self.sanitizer.sanitize_text(
            "from 2001:0db8:85a3:0000:0000:8a2e:0370:7334 denied"
        )
        assert "2001:0db8" not in out
        assert "[ip-" in out

    def test_compressed_form(self):
        out = self.sanitizer.sanitize_text("client 2001:db8::1 connected")
        assert "2001:db8::1" not in out
        assert "[ip-" in out

    def test_loopback(self):
        out = self.sanitizer.sanitize_text("bound to ::1 only")
        assert " ::1 " not in out
        assert "[ip-" in out

    def test_bracketed_with_port(self):
        out = self.sanitizer.sanitize_text("url [2001:db8::1]:636 refused")
        assert "2001:db8::1" not in out
        assert ":[port]" in out
        assert ":636" not in out

    def test_zone_index(self):
        out = self.sanitizer.sanitize_text("link-local fe80::1%eth0 up")
        assert "fe80::1" not in out
        assert "[ip-" in out

    def test_log_timestamp_not_redacted(self):
        text = "[01/Jan/2024:10:00:01.000000000 +0000] conn=1 op=2 RESULT"
        assert self.sanitizer.sanitize_text(text) == text

    def test_time_of_day_not_redacted(self):
        text = "at 12:34:56 the server restarted"
        assert self.sanitizer.sanitize_text(text) == text

    def test_mac_address_not_redacted(self):
        text = "interface aa:bb:cc:dd:ee:ff up"
        assert self.sanitizer.sanitize_text(text) == text

    def test_cpp_scope_operator_not_redacted(self):
        text = "std::vector in the stack trace"
        assert self.sanitizer.sanitize_text(text) == text


# ---------------------------------------------------------------------------
# 2.2: deny-by-default sanitization for unrecognized keys
# ---------------------------------------------------------------------------


class TestFailClosedBackendSanitizer:
    def test_config_tool_backend_unknown_key_redacted(self):
        from ldap_assistant_mcp.dirsrv_mcp.tools.config import _sanitize_backend

        backend = {
            "name": "userRoot",
            "suffix": "dc=example,dc=com",
            "statistics": {"entries": 5},
            "replication": {"enabled": True, "role": "supplier"},
            "future_sensitive_key": "cn=dm,dc=example,dc=com",
        }
        result = _sanitize_backend(PrivacySanitizer(), backend)
        assert result["future_sensitive_key"] == "[REDACTED]"
        # Vetted keys keep their existing handling
        assert result["name"] == "[backend]"
        assert result["suffix"].startswith("[suffix-")
        assert result["statistics"] == {"entries": 5}
        assert result["replication"] == {"enabled": True, "role": "supplier"}


class TestFailClosedFindingMetadata:
    def setup_method(self):
        self.sanitizer = PrivacySanitizer()

    def _sanitize_meta(self, metadata):
        finding = {"title": "t", "severity": "high", "metadata": metadata}
        return self.sanitizer.sanitize_finding(finding)["metadata"]

    def test_unknown_hostname_value_scrubbed(self):
        meta = self._sanitize_meta({"client_host": "ldap1.example.com"})
        assert meta["client_host"] == "[hostname]"

    def test_unknown_ip_value_scrubbed(self):
        meta = self._sanitize_meta({"client_addr": "10.20.30.40"})
        assert meta["client_addr"].startswith("[ip-")

    def test_unknown_dn_value_scrubbed(self):
        meta = self._sanitize_meta({"who": "cn=admin,dc=example,dc=com"})
        assert meta["who"] == "[dn]"

    def test_numeric_and_bool_values_kept(self):
        meta = self._sanitize_meta(
            {"count": 3, "ratio": 0.5, "capped": True, "missing": None}
        )
        assert meta == {"count": 3, "ratio": 0.5, "capped": True, "missing": None}

    def test_structured_value_redacted(self):
        meta = self._sanitize_meta({"extra": {"nested": "cn=x,dc=y,dc=z"}})
        assert meta["extra"] == "[REDACTED]"

    def test_unknown_list_values_scrubbed_per_item(self):
        meta = self._sanitize_meta({"vals": ["cn=a,dc=b,dc=c", 5]})
        assert meta["vals"] == ["[dn]", 5]

    def test_safe_enum_like_strings_survive(self):
        """Diagnostic enum-ish values must not be destroyed by the scrub."""
        meta = self._sanitize_meta(
            {"attribute": "nsslapd-rootpwstoragescheme", "current": "off"}
        )
        assert meta["attribute"] == "nsslapd-rootpwstoragescheme"
        assert meta["current"] == "off"


# ---------------------------------------------------------------------------
# 2.2: startup WARNING when privacy mode is disabled
# ---------------------------------------------------------------------------


def _dirsrv_config() -> LDAPServerConfig:
    return LDAPServerConfig(
        name="warn-test",
        hostname="localhost",
        port=389,
        base_dn="dc=example,dc=com",
        bind_dn="cn=Directory Manager",
        bind_password="secret",
    )


def _make_dirsrv(settings: MCPSettings):
    from ldap_assistant_mcp.dirsrv_mcp.server import DirSrvMCP

    env = {k: v for k, v in os.environ.items() if k != "LDAP_SERVERS_CONFIG"}
    with patch.dict(os.environ, env, clear=True):
        return DirSrvMCP(servers=[_dirsrv_config()], settings=settings)


class TestExposeSensitiveWarning:
    def test_warning_when_privacy_disabled(self, caplog):
        with caplog.at_level(logging.WARNING, logger="ldap_assistant_mcp.DirSrvMCP"):
            _make_dirsrv(MCPSettings(expose_sensitive_data=True))
        warnings = [
            r.getMessage()
            for r in caplog.records
            if r.levelno == logging.WARNING
            and r.name == "ldap_assistant_mcp.DirSrvMCP"
        ]
        assert any("Privacy mode is DISABLED" in m for m in warnings)

    def test_no_warning_when_privacy_enabled(self, caplog):
        with caplog.at_level(logging.WARNING, logger="ldap_assistant_mcp.DirSrvMCP"):
            _make_dirsrv(MCPSettings(expose_sensitive_data=False))
        assert not any(
            "Privacy mode is DISABLED" in r.getMessage() for r in caplog.records
        )
