"""Policy-boundary tests: sanitizer scope and bind-password indirection.

Covers:
- PrivacySanitizer thread safety: concurrent tool calls must not race the
  bounded mapping caches (eviction / insert-then-read), and keyed-hash
  determinism must survive eviction churn.
- Sanitizer scope: each DirSrvMCP instance owns its own PrivacySanitizer
  (per-investigation pseudonym scope); the process-global get_sanitizer()
  singleton contract stays intact for the stderr logging filter.
- Bind-password secret indirection: bind_password_env / bind_password_file
  as alternatives to inline bind_password, with strict exclusivity and
  file-permission checks.
- Serialization: ServerListConfig.to_dict() never emits the secret.
- Config-file hygiene: a servers.json with an inline bind_password must be
  a regular, owner-only-readable file.

Pure unit tests — no live LDAP server required.
"""

from __future__ import annotations

import json
import logging
import threading
from concurrent.futures import ThreadPoolExecutor

import pytest

from ldap_assistant_mcp.config.loader import (
    ServerListConfig,
    _server_config_from_dict,
    load_config,
)
from ldap_assistant_mcp.core import (
    LDAPServerConfig,
    read_bind_password_file,
    resolve_bind_password,
)
from ldap_assistant_mcp.dirsrv_mcp.server import DirSrvMCP
from ldap_assistant_mcp.lib import privacy
from ldap_assistant_mcp.lib.privacy import PrivacySanitizer, get_sanitizer


@pytest.fixture(autouse=True)
def clean_config_env(monkeypatch):
    """Isolate tests from config/credential env vars in the outer environment."""
    for var in (
        "LDAP_SERVERS_CONFIG",
        "LDAP_BIND_PASSWORD",
        "LDAP_BIND_PASSWORD_FILE",
        "LDAP_URL",
        "LDAP_HOSTNAME",
    ):
        monkeypatch.delenv(var, raising=False)


def _write_secret_file(tmp_path, content="  file-secret-42\n", mode=0o600, name="pw.txt"):
    path = tmp_path / name
    path.write_text(content)
    path.chmod(mode)
    return str(path)


def _live_server_config(name="t009-live") -> LDAPServerConfig:
    return LDAPServerConfig(
        name=name,
        hostname="ldap.example.com",
        port=3389,
        base_dn="dc=example,dc=com",
        bind_dn="cn=Directory Manager",
        bind_password="Secret.123",
    )


# ---------------------------------------------------------------------------
# Sanitizer thread safety
# ---------------------------------------------------------------------------


class TestSanitizerThreadSafety:
    def test_concurrent_churn_with_small_cap_no_crash_and_deterministic(
        self, monkeypatch
    ):
        """8 threads churning past a tiny eviction cap: no KeyError races,
        and tokens stay deterministic across evictions."""
        monkeypatch.setattr(privacy, "_MAX_MAPPING_SIZE", 64)
        sanitizer = PrivacySanitizer()

        baseline_host = sanitizer.sanitize_hostname("fixed.example.com")
        baseline_dn = sanitizer.sanitize_dn("uid=fixed,ou=people,dc=example,dc=com")
        baseline_text = sanitizer.sanitize_text("client 10.99.99.99 connected")

        n_threads = 8
        barrier = threading.Barrier(n_threads)

        def churn(thread_no: int) -> None:
            barrier.wait()
            for i in range(500):
                k = (i * 7 + thread_no) % 150
                sanitizer.sanitize_hostname(f"host{k}.example.com")
                sanitizer.sanitize_dn(f"uid=user{k},ou=people,dc=example,dc=com")
                sanitizer.sanitize_text(
                    f"error on node{k}.example.com from 10.0.{k % 200}.5"
                )
                sanitizer.sanitize_suffix(f"dc=t{k},dc=example,dc=com")

        with ThreadPoolExecutor(max_workers=n_threads) as pool:
            futures = [pool.submit(churn, t) for t in range(n_threads)]
            for future in futures:
                future.result()  # re-raises any KeyError from a race

        # Bounded: eviction kept every map at or under the (patched) cap.
        assert len(sanitizer._hostname_map) <= 64
        assert len(sanitizer._dn_map) <= 64
        assert len(sanitizer._ip_map) <= 64

        # Deterministic: values evicted long ago come back with the same token.
        assert sanitizer.sanitize_hostname("fixed.example.com") == baseline_host
        assert (
            sanitizer.sanitize_dn("uid=fixed,ou=people,dc=example,dc=com")
            == baseline_dn
        )
        assert sanitizer.sanitize_text("client 10.99.99.99 connected") == baseline_text

    def test_concurrent_same_key_yields_single_token(self, monkeypatch):
        """All threads asking for the same value get one and the same token."""
        monkeypatch.setattr(privacy, "_MAX_MAPPING_SIZE", 32)
        sanitizer = PrivacySanitizer()
        results = []
        lock = threading.Lock()

        def worker(thread_no: int) -> None:
            for i in range(200):
                sanitizer.sanitize_hostname(f"filler{(i + thread_no) % 100}.example.com")
                token = sanitizer.sanitize_hostname("shared.example.com")
                with lock:
                    results.append(token)

        with ThreadPoolExecutor(max_workers=8) as pool:
            futures = [pool.submit(worker, t) for t in range(8)]
            for future in futures:
                future.result()

        assert len(set(results)) == 1
        assert results[0].startswith("[host-")

    def test_reset_is_safe_under_lock(self):
        sanitizer = PrivacySanitizer()
        token = sanitizer.sanitize_hostname("a.example.com")
        sanitizer.reset()
        assert sanitizer._hostname_map == {}
        # Keyed hash: same instance, same key -> same token even after reset.
        assert sanitizer.sanitize_hostname("a.example.com") == token


# ---------------------------------------------------------------------------
# Per-instance sanitizer scope
# ---------------------------------------------------------------------------


class TestSanitizerScope:
    def test_each_dirsrv_mcp_instance_has_own_sanitizer(self):
        mcp1 = DirSrvMCP(servers=[_live_server_config("a")], include_env_fallback=False)
        mcp2 = DirSrvMCP(servers=[_live_server_config("b")], include_env_fallback=False)

        assert mcp1.sanitizer is not mcp2.sanitizer
        assert mcp1.sanitizer is not get_sanitizer()
        assert mcp2.sanitizer is not get_sanitizer()

    def test_instances_produce_different_pseudonyms_for_same_hostname(self):
        mcp1 = DirSrvMCP(servers=[_live_server_config("a")], include_env_fallback=False)
        mcp2 = DirSrvMCP(servers=[_live_server_config("b")], include_env_fallback=False)

        t1 = mcp1.sanitizer.sanitize_hostname("corr.example.com")
        t2 = mcp2.sanitizer.sanitize_hostname("corr.example.com")

        assert t1.startswith("[host-") and t2.startswith("[host-")
        # Different random keys => uncorrelatable pseudonym scopes.
        assert t1 != t2

    def test_single_instance_is_internally_consistent(self):
        mcp = DirSrvMCP(servers=[_live_server_config()], include_env_fallback=False)
        first = mcp.sanitizer.sanitize_hostname("corr.example.com")
        again = mcp.sanitizer.sanitize_hostname("corr.example.com")
        via_text = mcp.sanitizer.sanitize_text("failure on 10.4.5.6")
        via_text_again = mcp.sanitizer.sanitize_text("failure on 10.4.5.6")
        assert first == again
        assert via_text == via_text_again

    def test_global_singleton_contract_unchanged(self):
        """get_sanitizer() stays a process-level singleton (stderr filter)."""
        assert get_sanitizer() is get_sanitizer()


# ---------------------------------------------------------------------------
# bind_password_env indirection
# ---------------------------------------------------------------------------


class TestBindPasswordEnv:
    def test_env_indirection_resolves_at_load(self, monkeypatch):
        monkeypatch.setenv("TEST_BIND_PW", "env-secret-7")
        config = _server_config_from_dict(
            {
                "name": "envsrv",
                "hostname": "ldap.example.com",
                "bind_dn": "cn=dm",
                "bind_password_env": "TEST_BIND_PW",
            }
        )
        assert config.bind_password == "env-secret-7"
        assert config.bind_password_env == "TEST_BIND_PW"
        assert config.bind_password_file is None

    def test_missing_env_var_raises_naming_it(self, monkeypatch):
        monkeypatch.delenv("TEST_MISSING_BIND_PW", raising=False)
        with pytest.raises(ValueError, match="TEST_MISSING_BIND_PW"):
            _server_config_from_dict(
                {
                    "name": "envsrv",
                    "hostname": "ldap.example.com",
                    "bind_password_env": "TEST_MISSING_BIND_PW",
                }
            )


# ---------------------------------------------------------------------------
# bind_password_file indirection
# ---------------------------------------------------------------------------


class TestBindPasswordFile:
    def test_file_with_0600_works_and_strips(self, tmp_path):
        pw_path = _write_secret_file(tmp_path, "  file-secret-42\n", 0o600)
        config = _server_config_from_dict(
            {
                "name": "filesrv",
                "hostname": "ldap.example.com",
                "bind_password_file": pw_path,
            }
        )
        assert config.bind_password == "file-secret-42"
        assert config.bind_password_file == pw_path

    def test_file_with_0644_raises_with_chmod_hint(self, tmp_path):
        pw_path = _write_secret_file(tmp_path, "secret", 0o644)
        with pytest.raises(ValueError) as excinfo:
            _server_config_from_dict(
                {
                    "name": "filesrv",
                    "hostname": "ldap.example.com",
                    "bind_password_file": pw_path,
                }
            )
        msg = str(excinfo.value)
        assert pw_path in msg
        assert "chmod 600" in msg

    def test_group_readable_raises(self, tmp_path):
        pw_path = _write_secret_file(tmp_path, "secret", 0o640)
        with pytest.raises(ValueError, match="chmod 600"):
            read_bind_password_file(pw_path)

    def test_symlink_raises(self, tmp_path):
        real = _write_secret_file(tmp_path, "secret", 0o600, name="real-pw.txt")
        link = tmp_path / "link-pw.txt"
        link.symlink_to(real)
        with pytest.raises(ValueError, match="symlink"):
            _server_config_from_dict(
                {
                    "name": "filesrv",
                    "hostname": "ldap.example.com",
                    "bind_password_file": str(link),
                }
            )

    def test_missing_file_raises(self, tmp_path):
        missing = str(tmp_path / "nope.txt")
        with pytest.raises(ValueError, match="does not exist"):
            _server_config_from_dict(
                {
                    "name": "filesrv",
                    "hostname": "ldap.example.com",
                    "bind_password_file": missing,
                }
            )

    def test_empty_file_raises(self, tmp_path):
        pw_path = _write_secret_file(tmp_path, "   \n", 0o600)
        with pytest.raises(ValueError, match="empty"):
            read_bind_password_file(pw_path)

    def test_relative_path_resolves_against_config_dir(self, tmp_path):
        _write_secret_file(tmp_path, "rel-secret\n", 0o600, name="pw.txt")
        config_path = tmp_path / "servers.json"
        config_path.write_text(
            json.dumps(
                {
                    "servers": [
                        {
                            "name": "relsrv",
                            "hostname": "ldap.example.com",
                            "bind_password_file": "pw.txt",
                        }
                    ]
                }
            )
        )
        loaded = load_config(config_file=str(config_path))
        assert loaded.servers[0].bind_password == "rel-secret"


# ---------------------------------------------------------------------------
# Password source exclusivity
# ---------------------------------------------------------------------------


class TestPasswordSourceExclusivity:
    @pytest.mark.parametrize(
        "extra",
        [
            {"bind_password": "a", "bind_password_env": "TEST_CONFLICT_BIND_PW"},
            {"bind_password": "a", "bind_password_file": "/tmp/whatever"},
            {"bind_password_env": "TEST_CONFLICT_BIND_PW", "bind_password_file": "/tmp/whatever"},
            {
                "bind_password": "a",
                "bind_password_env": "TEST_CONFLICT_BIND_PW",
                "bind_password_file": "/tmp/whatever",
            },
        ],
    )
    def test_more_than_one_source_raises(self, monkeypatch, extra):
        monkeypatch.setenv("TEST_CONFLICT_BIND_PW", "x")
        with pytest.raises(ValueError, match="at most one"):
            _server_config_from_dict(
                {"name": "conflict", "hostname": "ldap.example.com", **extra}
            )

    def test_resolver_names_the_server_and_fields(self):
        with pytest.raises(ValueError) as excinfo:
            resolve_bind_password(
                label="prod-1",
                bind_password="a",
                bind_password_env="VAR",
            )
        msg = str(excinfo.value)
        assert "prod-1" in msg
        assert "bind_password_env" in msg

    def test_single_inline_source_still_works(self):
        config = _server_config_from_dict(
            {
                "name": "plain",
                "hostname": "ldap.example.com",
                "bind_password": "inline-secret",
            }
        )
        assert config.bind_password == "inline-secret"


# ---------------------------------------------------------------------------
# from_env LDAP_BIND_PASSWORD_FILE
# ---------------------------------------------------------------------------


class TestFromEnvPasswordFile:
    def test_password_file_env_var_resolves(self, tmp_path, monkeypatch):
        pw_path = _write_secret_file(tmp_path, "env-file-secret\n", 0o600)
        monkeypatch.setenv("LDAP_BIND_PASSWORD_FILE", pw_path)
        config = LDAPServerConfig.from_env()
        assert config.bind_password == "env-file-secret"
        assert config.bind_password_file == pw_path

    def test_both_password_and_file_raises(self, tmp_path, monkeypatch):
        pw_path = _write_secret_file(tmp_path, "s", 0o600)
        monkeypatch.setenv("LDAP_BIND_PASSWORD", "inline")
        monkeypatch.setenv("LDAP_BIND_PASSWORD_FILE", pw_path)
        with pytest.raises(ValueError, match="LDAP_BIND_PASSWORD_FILE"):
            LDAPServerConfig.from_env()

    def test_bad_mode_file_fails_from_env(self, tmp_path, monkeypatch):
        pw_path = _write_secret_file(tmp_path, "s", 0o644)
        monkeypatch.setenv("LDAP_BIND_PASSWORD_FILE", pw_path)
        with pytest.raises(ValueError, match="chmod 600"):
            LDAPServerConfig.from_env()


# ---------------------------------------------------------------------------
# Serialization never leaks the secret
# ---------------------------------------------------------------------------


class TestSerializationNoSecrets:
    def test_to_dict_never_contains_inline_password(self):
        config = ServerListConfig.from_dict(
            {
                "servers": [
                    {
                        "name": "s1",
                        "hostname": "ldap.example.com",
                        "bind_dn": "cn=dm",
                        "bind_password": "Sup3rSecret!",
                    }
                ]
            }
        )
        dumped = config.to_dict()
        assert "Sup3rSecret!" not in json.dumps(dumped)
        entry = dumped["servers"][0]
        assert "bind_password" not in entry
        assert entry["bind_password_set"] is True

    def test_to_dict_never_contains_env_resolved_password(self, monkeypatch):
        monkeypatch.setenv("TEST_DUMP_BIND_PW", "EnvSecret!9")
        config = ServerListConfig.from_dict(
            {
                "servers": [
                    {
                        "name": "s1",
                        "hostname": "ldap.example.com",
                        "bind_password_env": "TEST_DUMP_BIND_PW",
                    }
                ]
            }
        )
        dumped = config.to_dict()
        assert "EnvSecret!9" not in json.dumps(dumped)
        entry = dumped["servers"][0]
        assert entry["bind_password_set"] is True
        assert entry["bind_password_env"] == "TEST_DUMP_BIND_PW"

    def test_to_dict_reports_no_password_when_none(self):
        config = ServerListConfig(
            servers=[
                LDAPServerConfig(name="anon", hostname="ldap.example.com", port=389)
            ]
        )
        entry = config.to_dict()["servers"][0]
        assert entry["bind_password_set"] is False

    def test_dump_roundtrips_through_from_dict(self, monkeypatch):
        """to_dict output (with bind_password_set marker) must re-load."""
        monkeypatch.setenv("TEST_ROUNDTRIP_BIND_PW", "RoundTrip!1")
        config = ServerListConfig.from_dict(
            {
                "servers": [
                    {
                        "name": "s1",
                        "hostname": "ldap.example.com",
                        "bind_password_env": "TEST_ROUNDTRIP_BIND_PW",
                    }
                ]
            }
        )
        restored = ServerListConfig.from_dict(config.to_dict())
        assert restored.servers[0].bind_password == "RoundTrip!1"
        assert restored.servers[0].bind_password_env == "TEST_ROUNDTRIP_BIND_PW"


# ---------------------------------------------------------------------------
# Config file permission checks
# ---------------------------------------------------------------------------


def _config_with_inline_password():
    return {
        "servers": [
            {
                "name": "s1",
                "hostname": "ldap.example.com",
                "bind_dn": "cn=dm",
                "bind_password": "FileSecret!",
            }
        ]
    }


class TestConfigFilePermissions:
    def test_world_readable_config_with_inline_password_raises(self, tmp_path):
        path = tmp_path / "servers.json"
        path.write_text(json.dumps(_config_with_inline_password()))
        path.chmod(0o644)
        with pytest.raises(ValueError) as excinfo:
            load_config(config_file=str(path))
        msg = str(excinfo.value)
        assert str(path) in msg
        assert "chmod 600" in msg

    def test_0600_config_with_inline_password_loads(self, tmp_path):
        path = tmp_path / "servers.json"
        path.write_text(json.dumps(_config_with_inline_password()))
        path.chmod(0o600)
        config = load_config(config_file=str(path))
        assert config.servers[0].bind_password == "FileSecret!"

    def test_dirsrv_mcp_surfaces_permission_error(self, tmp_path):
        path = tmp_path / "servers.json"
        path.write_text(json.dumps(_config_with_inline_password()))
        path.chmod(0o644)
        with pytest.raises(RuntimeError) as excinfo:
            DirSrvMCP(config_path=str(path))
        assert "chmod 600" in str(excinfo.value)

    def test_symlinked_config_with_inline_password_raises(self, tmp_path):
        real = tmp_path / "real-servers.json"
        real.write_text(json.dumps(_config_with_inline_password()))
        real.chmod(0o600)
        link = tmp_path / "link-servers.json"
        link.symlink_to(real)
        with pytest.raises(ValueError, match="symlink"):
            load_config(config_file=str(link))

    def test_symlinked_config_without_inline_password_warns_but_loads(
        self, tmp_path, caplog
    ):
        real = tmp_path / "real-servers.json"
        real.write_text(
            json.dumps(
                {"servers": [{"name": "nopw", "hostname": "ldap.example.com"}]}
            )
        )
        link = tmp_path / "link-servers.json"
        link.symlink_to(real)
        with caplog.at_level(logging.WARNING, logger="ldap_assistant_mcp.config.loader"):
            config = load_config(config_file=str(link))
        assert config.servers[0].name == "nopw"
        assert any("symlink" in rec.getMessage() for rec in caplog.records)

    def test_world_readable_config_without_secrets_loads(self, tmp_path):
        """The mode check only applies to configs carrying inline secrets."""
        path = tmp_path / "servers.json"
        path.write_text(
            json.dumps(
                {"servers": [{"name": "nopw", "hostname": "ldap.example.com"}]}
            )
        )
        path.chmod(0o644)
        config = load_config(config_file=str(path))
        assert config.servers[0].name == "nopw"
