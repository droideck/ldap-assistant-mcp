"""Strict-config and transport-hardening tests (0.6.0).

Covers:

- Boolean config values are parsed strictly — a typo like
  "flase" fails startup instead of silently disabling TLS verification.
  JSON fields and environment variables share the same parser.
- The URL is authoritative for the transport. Unknown
  schemes raise; a use_ssl/hostname/port that conflicts with ldap_url
  raises instead of being silently reconciled into plaintext.
- An explicitly provided config source that yields zero servers
  raises at startup instead of silently booting a default localhost server.
- Duplicate server names and unknown server keys are rejected.
- A simple bind with a password over plain ldap:// to a
  non-loopback host is refused (loopback and is_local instances stay
  allowed; allow_insecure_plaintext / LDAP_ALLOW_INSECURE_PLAINTEXT is
  the lab escape hatch).
- The OpenLDAP provider honors tls_verify (verified certs by
  default) and applies the same plaintext-bind rejection.

No live LDAP server is required: connections are mocked.
"""

from __future__ import annotations

import json
import os
from unittest.mock import MagicMock, patch

import ldap
import pytest
from fastmcp.exceptions import ToolError

from ldap_assistant_mcp.config.loader import ServerListConfig, _server_config_from_dict
from ldap_assistant_mcp.core import LDAPServerConfig, _is_loopback_host, parse_strict_bool
from ldap_assistant_mcp.dirsrv_mcp.connection import (
    ConnectionFailed,
    ConnectionManager,
    ServerConfig,
)
from ldap_assistant_mcp.dirsrv_mcp.server import DirSrvMCP
from ldap_assistant_mcp.openldap_mcp.server import OpenLDAPMCP


@pytest.fixture(autouse=True)
def clean_t007_env(monkeypatch):
    """Isolate tests from the outer environment."""
    for var in (
        "LDAP_SERVERS_CONFIG",
        "LDAP_ALLOW_INSECURE_PLAINTEXT",
        "LDAP_TLS_VERIFY",
        "LDAP_USE_SSL",
        "LDAP_URL",
    ):
        monkeypatch.delenv(var, raising=False)


def _base_server(**overrides):
    data = {
        "name": "t007",
        "hostname": "ldap.example.com",
        "base_dn": "dc=test,dc=com",
        "bind_dn": "cn=Directory Manager",
        "bind_password": "secret",
    }
    data.update(overrides)
    return data


def _write_config(tmp_path, data, name="servers.json"):
    path = tmp_path / name
    path.write_text(json.dumps(data))
    # Inline bind_password requires an owner-only readable config.
    path.chmod(0o600)
    return str(path)


def _live_config(name="live", **overrides) -> ServerConfig:
    defaults = dict(
        name=name,
        ldap_url="ldap://localhost:389",
        base_dn="dc=test,dc=com",
        bind_dn="cn=Directory Manager",
        bind_password="secret",
    )
    defaults.update(overrides)
    return ServerConfig(**defaults)


def _connect_mocked(config: ServerConfig):
    """connect() with DirSrv mocked; returns the mock DirSrv instance."""
    cm = ConnectionManager()
    cm.add_server(config)
    with patch("ldap_assistant_mcp.dirsrv_mcp.connection.DirSrv") as mock_dirsrv:
        mock_ds = MagicMock()
        mock_dirsrv.return_value = mock_ds
        cm.connect(config.name)
    return mock_ds


# ---------------------------------------------------------------------------
# Strict boolean parsing
# ---------------------------------------------------------------------------


BOOL_FIELDS = [
    "use_ssl",
    "tls_verify",
    "allow_insecure_plaintext",
    "is_local",
    "use_ldapi",
    "is_offline",
    "is_archive",
]

BAD_BOOL_VALUES = ["flase", "ture", "TRUE ish", "maybe", "enabled", "2", 2, 1.0, [True]]

GOOD_BOOL_VALUES = [
    ("true", True),
    ("false", False),
    ("TRUE", True),
    ("False", False),
    ("1", True),
    ("0", False),
    ("yes", True),
    ("no", False),
    ("on", True),
    ("off", False),
    (True, True),
    (False, False),
    (1, True),
    (0, False),
]


class TestStrictBooleans:
    @pytest.mark.parametrize("field", BOOL_FIELDS)
    @pytest.mark.parametrize("value", ["flase", "ture", "maybe", 2])
    def test_misspelled_boolean_raises_naming_field(self, field, value):
        data = _base_server(**{field: value})
        with pytest.raises(ValueError) as exc_info:
            _server_config_from_dict(data)
        msg = str(exc_info.value)
        assert field in msg
        assert repr(value) in msg

    @pytest.mark.parametrize("value,expected", GOOD_BOOL_VALUES)
    def test_valid_boolean_spellings_accepted(self, value, expected):
        config = _server_config_from_dict(_base_server(tls_verify=value))
        assert config.tls_verify is expected

    @pytest.mark.parametrize("value,expected", GOOD_BOOL_VALUES)
    def test_parse_strict_bool_accepts_documented_values(self, value, expected):
        assert parse_strict_bool(value, "field") is expected

    @pytest.mark.parametrize("value", BAD_BOOL_VALUES)
    def test_parse_strict_bool_rejects_garbage(self, value):
        with pytest.raises(ValueError, match="Accepted values"):
            parse_strict_bool(value, "some_field")

    def test_misspelled_tls_verify_fails_startup(self, tmp_path):
        """'flase' must fail startup, not silently disable verification."""
        config_path = _write_config(
            tmp_path, {"servers": [_base_server(tls_verify="flase")]}
        )
        with pytest.raises(RuntimeError) as exc_info:
            DirSrvMCP(config_path=config_path)
        msg = str(exc_info.value)
        assert config_path in msg
        assert "tls_verify" in msg
        assert "flase" in msg

    def test_misspelled_settings_boolean_fails_startup(self, tmp_path):
        config_path = _write_config(
            tmp_path,
            {"servers": [_base_server()], "settings": {"debug": "ture"}},
        )
        with pytest.raises(RuntimeError, match="debug"):
            DirSrvMCP(config_path=config_path)

    # -- env parity: the env vars use the same parser as JSON fields -------

    @pytest.mark.parametrize(
        "var",
        ["LDAP_TLS_VERIFY", "LDAP_USE_SSL", "LDAP_IS_LOCAL", "LDAP_USE_LDAPI",
         "LDAP_ALLOW_INSECURE_PLAINTEXT"],
    )
    def test_env_garbage_boolean_raises(self, monkeypatch, var):
        monkeypatch.setenv(var, "flase")
        with pytest.raises(ValueError) as exc_info:
            LDAPServerConfig.from_env()
        assert var in str(exc_info.value)

    def test_env_tls_verify_valid_values(self, monkeypatch):
        monkeypatch.setenv("LDAP_TLS_VERIFY", "off")
        assert LDAPServerConfig.from_env().tls_verify is False
        monkeypatch.setenv("LDAP_TLS_VERIFY", "on")
        assert LDAPServerConfig.from_env().tls_verify is True

    def test_env_unset_or_empty_keeps_safe_defaults(self, monkeypatch):
        monkeypatch.setenv("LDAP_TLS_VERIFY", "")
        config = LDAPServerConfig.from_env()
        assert config.tls_verify is True
        assert config.use_ssl is False
        assert config.allow_insecure_plaintext is False


# ---------------------------------------------------------------------------
# The URL is authoritative for the transport
# ---------------------------------------------------------------------------


class TestUrlAuthoritative:
    @pytest.mark.parametrize(
        "url",
        ["ldapx://host.example.com:389", "http://host.example.com", "ldaps:/host.example.com"],
    )
    def test_unsupported_or_malformed_url_raises(self, url):
        # "ldaps:/host" parses as scheme=ldaps with no hostname — also rejected.
        data = _base_server(ldap_url=url)
        del data["hostname"]
        with pytest.raises(ValueError, match="ldap_url"):
            _server_config_from_dict(data)

    def test_ldaps_url_with_use_ssl_false_raises(self):
        """The silent TLS→plaintext downgrade is now a config error."""
        data = _base_server(ldap_url="ldaps://secure.example.com:636", use_ssl=False)
        del data["hostname"]
        with pytest.raises(ValueError, match="use_ssl"):
            _server_config_from_dict(data)

    def test_ldap_url_with_use_ssl_true_raises(self):
        data = _base_server(ldap_url="ldap://plain.example.com:389", use_ssl=True)
        del data["hostname"]
        with pytest.raises(ValueError, match="use_ssl"):
            _server_config_from_dict(data)

    def test_ldapi_url_accepted(self):
        data = _base_server(ldap_url="ldapi://%2Frun%2Fslapd-x.socket")
        del data["hostname"]
        config = _server_config_from_dict(data)
        assert config.use_ssl is False

    def test_ldapi_url_with_use_ssl_true_raises(self):
        data = _base_server(ldap_url="ldapi://%2Frun%2Fslapd-x.socket", use_ssl=True)
        del data["hostname"]
        with pytest.raises(ValueError, match="ldapi"):
            _server_config_from_dict(data)

    def test_hostname_conflicting_with_url_raises(self):
        data = _base_server(
            hostname="other.example.com", ldap_url="ldap://plain.example.com:389"
        )
        with pytest.raises(ValueError, match="hostname"):
            _server_config_from_dict(data)

    def test_port_conflicting_with_url_raises(self):
        data = _base_server(ldap_url="ldap://plain.example.com:389", port=636)
        del data["hostname"]
        with pytest.raises(ValueError, match="port"):
            _server_config_from_dict(data)

    def test_consistent_hostname_and_port_accepted(self):
        data = _base_server(
            hostname="plain.example.com",
            port=1389,
            ldap_url="ldap://plain.example.com:1389",
        )
        config = _server_config_from_dict(data)
        assert config.hostname == "plain.example.com"
        assert config.port == 1389

    # -- env parity ---------------------------------------------------------

    def test_env_unknown_url_scheme_raises(self, monkeypatch):
        monkeypatch.setenv("LDAP_URL", "ldapx://host.example.com:389")
        with pytest.raises(ValueError, match="LDAP_URL"):
            LDAPServerConfig.from_env()

    def test_env_url_use_ssl_conflict_raises(self, monkeypatch):
        monkeypatch.setenv("LDAP_URL", "ldaps://secure.example.com:636")
        monkeypatch.setenv("LDAP_USE_SSL", "false")
        with pytest.raises(ValueError, match="LDAP_USE_SSL"):
            LDAPServerConfig.from_env()

    def test_env_url_use_ssl_consistent_accepted(self, monkeypatch):
        monkeypatch.setenv("LDAP_URL", "ldaps://secure.example.com:636")
        monkeypatch.setenv("LDAP_USE_SSL", "true")
        config = LDAPServerConfig.from_env()
        assert config.use_ssl is True
        assert config.port == 636


# ---------------------------------------------------------------------------
# An explicitly provided config with zero servers must raise
# ---------------------------------------------------------------------------


class TestEmptyExplicitConfig:
    def test_empty_servers_list_raises(self, tmp_path):
        config_path = _write_config(tmp_path, {"servers": []})
        with pytest.raises(RuntimeError) as exc_info:
            DirSrvMCP(config_path=config_path)
        msg = str(exc_info.value)
        assert config_path in msg
        assert "no servers" in msg

    def test_empty_config_via_env_var_raises(self, tmp_path, monkeypatch):
        config_path = _write_config(tmp_path, {"servers": []})
        monkeypatch.setenv("LDAP_SERVERS_CONFIG", config_path)
        with pytest.raises(RuntimeError, match="no servers"):
            DirSrvMCP()

    def test_typoed_servers_key_raises(self, tmp_path):
        """A misspelled top-level "servers" key yields zero servers → raise."""
        config_path = _write_config(tmp_path, {"servres": [_base_server()]})
        with pytest.raises(RuntimeError, match="no servers"):
            DirSrvMCP(config_path=config_path)

    def test_env_fallback_without_explicit_config_unchanged(self, monkeypatch):
        """No explicit config source: the env fallback keeps working."""
        monkeypatch.setenv("LDAP_URL", "ldap://localhost:33891")
        server = DirSrvMCP()
        assert "default" in server.server_configs
        assert server.server_configs["default"].hostname == "localhost"


# ---------------------------------------------------------------------------
# Duplicate names and unknown keys
# ---------------------------------------------------------------------------


class TestDuplicatesAndUnknownKeys:
    def test_duplicate_server_names_raise(self):
        data = {"servers": [_base_server(), _base_server()]}
        with pytest.raises(ValueError, match="Duplicate server name 't007'"):
            ServerListConfig.from_dict(data)

    def test_duplicate_server_names_fail_startup(self, tmp_path):
        config_path = _write_config(
            tmp_path, {"servers": [_base_server(), _base_server()]}
        )
        with pytest.raises(RuntimeError, match="Duplicate server name"):
            DirSrvMCP(config_path=config_path)

    def test_distinct_server_names_accepted(self):
        data = {
            "servers": [_base_server(), _base_server(name="t007-second")]
        }
        config = ServerListConfig.from_dict(data)
        assert len(config.servers) == 2

    @pytest.mark.parametrize("key", ["tls_verfy", "use_sssl", "bindpassword"])
    def test_unknown_server_key_raises(self, key):
        data = _base_server(**{key: True})
        with pytest.raises(ValueError) as exc_info:
            _server_config_from_dict(data)
        msg = str(exc_info.value)
        assert key in msg
        assert "unknown configuration key" in msg

    def test_unknown_server_key_fails_startup(self, tmp_path):
        config_path = _write_config(
            tmp_path, {"servers": [_base_server(tls_verfy=False)]}
        )
        with pytest.raises(RuntimeError, match="tls_verfy"):
            DirSrvMCP(config_path=config_path)


# ---------------------------------------------------------------------------
# Plaintext simple-bind rejection (dirsrv connection path)
# ---------------------------------------------------------------------------


class TestPlaintextBindRejection:
    def test_non_loopback_plaintext_simple_bind_raises(self):
        cm = ConnectionManager()
        cm.add_server(_live_config(name="wan", ldap_url="ldap://remote.example.com:389"))
        with pytest.raises(ConnectionFailed) as exc_info:
            cm.connect("wan")
        msg = str(exc_info.value)
        assert "cleartext" in msg
        assert "ldaps://" in msg
        assert "allow_insecure_plaintext" in msg

    @pytest.mark.parametrize(
        "url",
        [
            "ldap://localhost:389",
            "ldap://localhost:33891",
            "ldap://127.0.0.1:389",
            "ldap://127.1.2.3:389",
            "ldap://[::1]:389",
        ],
    )
    def test_loopback_plaintext_still_connects(self, url):
        mock_ds = _connect_mocked(_live_config(name="loop", ldap_url=url))
        mock_ds.open.assert_called_once()

    def test_allow_insecure_plaintext_config_permits(self):
        mock_ds = _connect_mocked(
            _live_config(
                name="lab",
                ldap_url="ldap://remote.example.com:389",
                allow_insecure_plaintext=True,
            )
        )
        mock_ds.open.assert_called_once()

    def test_env_escape_hatch_permits(self, monkeypatch):
        """The env hatch is honored at config-LOAD time (strict parsing);
        connect() trusts the resolved config field and never re-reads the
        raw environment."""
        monkeypatch.setenv("LDAP_ALLOW_INSECURE_PLAINTEXT", "true")
        data = _base_server(name="lab-env", ldap_url="ldap://remote.example.com:389")
        data.pop("hostname")
        config = _server_config_from_dict(data)
        assert config.allow_insecure_plaintext is True
        mock_ds = _connect_mocked(config)
        mock_ds.open.assert_called_once()

    def test_explicit_false_beats_env_hatch(self, monkeypatch):
        """An explicit allow_insecure_plaintext=false in the server config
        wins over an ambient env hatch: cleartext stays refused."""
        monkeypatch.setenv("LDAP_ALLOW_INSECURE_PLAINTEXT", "true")
        data = _base_server(
            name="wan-locked",
            ldap_url="ldap://remote.example.com:389",
            allow_insecure_plaintext=False,
        )
        data.pop("hostname")
        config = _server_config_from_dict(data)
        assert config.allow_insecure_plaintext is False
        cm = ConnectionManager()
        cm.add_server(config)
        with pytest.raises(ConnectionFailed):
            cm.connect("wan-locked")

    def test_garbage_env_escape_hatch_stays_closed(self, monkeypatch):
        """A typo in the escape hatch must NOT open it (fail closed)."""
        monkeypatch.setenv("LDAP_ALLOW_INSECURE_PLAINTEXT", "ture")
        cm = ConnectionManager()
        cm.add_server(_live_config(name="wan", ldap_url="ldap://remote.example.com:389"))
        with pytest.raises(ConnectionFailed):
            cm.connect("wan")

    def test_anonymous_bind_unaffected(self):
        mock_ds = _connect_mocked(
            _live_config(
                name="anon",
                ldap_url="ldap://remote.example.com:389",
                bind_dn="",
                bind_password="",
                auth_method="anonymous",
            )
        )
        mock_ds.open.assert_called_once()

    def test_ldaps_unaffected(self):
        mock_ds = _connect_mocked(
            _live_config(name="tls", ldap_url="ldaps://remote.example.com:636")
        )
        mock_ds.open.assert_called_once_with(reqcert=ldap.OPT_X_TLS_HARD)

    def test_local_instance_with_fqdn_url_exempt(self):
        """is_local + serverid binds to the same machine — no network crossed."""
        mock_ds = _connect_mocked(
            _live_config(
                name="local-fqdn",
                ldap_url="ldap://myhost.example.com:389",
                is_local=True,
                serverid="standalone",
            )
        )
        mock_ds.open.assert_called_once()

    def test_allow_insecure_plaintext_propagates_from_ldap_server_config(self):
        cm = ConnectionManager()
        cm.add_server(
            LDAPServerConfig(
                name="conv",
                hostname="remote.example.com",
                port=389,
                bind_dn="cn=dm",
                bind_password="x",
                allow_insecure_plaintext=True,
            )
        )
        assert cm.get_config("conv").allow_insecure_plaintext is True

    def test_loader_round_trip_preserves_allow_insecure_plaintext(self):
        config = ServerListConfig.from_dict(
            {"servers": [_base_server(allow_insecure_plaintext=True)]}
        )
        assert config.servers[0].allow_insecure_plaintext is True
        dumped = config.to_dict()
        assert dumped["servers"][0]["allow_insecure_plaintext"] is True
        reloaded = ServerListConfig.from_dict(dumped)
        assert reloaded.servers[0].allow_insecure_plaintext is True

    def test_loader_default_is_false(self):
        config = _server_config_from_dict(_base_server())
        assert config.allow_insecure_plaintext is False


# ---------------------------------------------------------------------------
# _is_loopback_host helper
# ---------------------------------------------------------------------------


class TestLoopbackHelper:
    @pytest.mark.parametrize(
        "host", ["localhost", "LOCALHOST", "127.0.0.1", "127.255.0.1", "::1", "[::1]"]
    )
    def test_loopback_hosts(self, host):
        assert _is_loopback_host(host) is True

    @pytest.mark.parametrize(
        "host", ["remote.example.com", "10.0.0.1", "128.0.0.1", "::2", "", None]
    )
    def test_non_loopback_hosts(self, host):
        assert _is_loopback_host(host) is False


# ---------------------------------------------------------------------------
# OpenLDAP provider TLS verification and plaintext rejection
# ---------------------------------------------------------------------------


def _openldap_server(config: LDAPServerConfig) -> OpenLDAPMCP:
    env = {k: v for k, v in os.environ.items() if k != "LDAP_SERVERS_CONFIG"}
    with patch.dict(os.environ, env, clear=True):
        return OpenLDAPMCP(servers=[config])


def _openldap_config(**overrides) -> LDAPServerConfig:
    defaults = dict(
        name="openldap-test",
        hostname="ldap.example.com",
        port=389,
        base_dn="dc=example,dc=com",
        bind_dn="cn=admin,dc=example,dc=com",
        bind_password="secret",
        provider_type="openldap",
    )
    defaults.update(overrides)
    return LDAPServerConfig(**defaults)


class TestOpenLDAPTls:
    def _bind_and_capture(self, config: LDAPServerConfig):
        server = _openldap_server(config)
        with patch(
            "ldap_assistant_mcp.openldap_mcp.server.ldap.initialize"
        ) as mock_init:
            mock_conn = MagicMock()
            mock_init.return_value = mock_conn
            server._ldap_bind(config)
        return mock_conn

    def test_ssl_defaults_to_verified_certificates(self):
        config = _openldap_config(port=636, use_ssl=True)
        conn = self._bind_and_capture(config)
        opts = {c.args[0]: c.args[1] for c in conn.set_option.call_args_list}
        assert opts.get(ldap.OPT_X_TLS_REQUIRE_CERT) == ldap.OPT_X_TLS_HARD
        assert opts.get(ldap.OPT_X_TLS_NEWCTX) == 0

    def test_ssl_tls_verify_false_relaxes(self):
        config = _openldap_config(port=636, use_ssl=True, tls_verify=False)
        conn = self._bind_and_capture(config)
        opts = {c.args[0]: c.args[1] for c in conn.set_option.call_args_list}
        assert opts.get(ldap.OPT_X_TLS_REQUIRE_CERT) == ldap.OPT_X_TLS_NEVER

    def test_never_uses_tls_allow(self):
        """The old hard-coded OPT_X_TLS_ALLOW must be gone in both modes."""
        for tls_verify in (True, False):
            config = _openldap_config(port=636, use_ssl=True, tls_verify=tls_verify)
            conn = self._bind_and_capture(config)
            values = [c.args[1] for c in conn.set_option.call_args_list]
            assert ldap.OPT_X_TLS_ALLOW not in values

    def test_non_loopback_plaintext_simple_bind_raises(self):
        config = _openldap_config()
        server = _openldap_server(config)
        with pytest.raises(ToolError) as exc_info:
            server._ldap_bind(config)
        msg = str(exc_info.value)
        assert "cleartext" in msg
        assert "allow_insecure_plaintext" in msg

    def test_loopback_plaintext_simple_bind_allowed(self):
        config = _openldap_config(hostname="localhost")
        conn = self._bind_and_capture(config)
        conn.simple_bind_s.assert_called_once()

    def test_allow_insecure_plaintext_permits(self):
        config = _openldap_config(allow_insecure_plaintext=True)
        conn = self._bind_and_capture(config)
        conn.simple_bind_s.assert_called_once()
