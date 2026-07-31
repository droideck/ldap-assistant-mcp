"""Credential/secret attribute VALUES must never escape.

Covers the fail-closed secret-attribute matching introduced in
``ldap_assistant_mcp.lib.privacy``:

- ``normalize_attribute_name``: strips LDAP attribute options
  (``;binary``, ``;lang-en``), whitespace, and case; unparseable input
  normalizes to ``""``.
- ``is_secret_attribute``: exact denylist + fail-closed family matching
  ("password", "credential", "passphrase", "secret", "symmetrickey",
  "pwdhistory"); empty/unparseable names are treated as secret.
- ``strip_credential_attributes`` and ``sanitize_attribute_value`` route
  through ``is_secret_attribute`` so ``userPassword;binary`` and unlisted
  credential-like names cannot bypass redaction.
- ``ldap_search`` withholds secret attribute values unconditionally — in
  privacy mode AND with LDAP_MCP_EXPOSE_SENSITIVE_DATA=true.

Design choices:

1. False-positive boundary: 389 DS password POLICY and per-user password
   STATE attributes (passwordStorageScheme, passwordMaxAge,
   passwordExpirationTime, passwordRetryCount, nsslapd-pwpolicy-local,
   ...) contain the substring "password" but carry switches, counts,
   timestamps, or scheme names — never password material — and are
   essential for lockout/expiration diagnostics.  They are enumerated in
   an explicit vetted allowlist (_NON_SECRET_PASSWORD_LIKE_ATTRIBUTES,
   verified against lib389 pwpolicy.py and 389-ds-base schema); anything
   password-like NOT on that list is treated as secret (fail closed).
2. passwordHistory/pwdHistory are SECRET even though passwordHistory is
   also an on/off policy switch in policy entries: on user entries the
   same attribute stores previous password hashes.  Hiding the on/off
   value in config output is accepted collateral.
3. "secretary" (RFC 4519, DN-valued) is allowlisted so the "secret"
   family match does not strip a standard identifier attribute; its
   value still goes through the identifier sanitization paths in
   privacy mode.
4. is_secret_attribute decides whether a VALUE is withheld.  It is not
   used to hide attribute NAMES from schema or name listings.

No live LDAP server is required: the LDAP layer is mocked using the
fake-connection idiom from test_phase0_privacy.py.
"""

from __future__ import annotations

import json
import os
from contextlib import contextmanager
from unittest.mock import MagicMock, patch

import pytest
from fastmcp import Client

from ldap_assistant_mcp.core import LDAPServerConfig, MCPSettings
from ldap_assistant_mcp.dirsrv_mcp.server import DirSrvMCP
from ldap_assistant_mcp.lib.privacy import (
    ALWAYS_REDACT_ATTRIBUTES,
    PrivacySanitizer,
    is_secret_attribute,
    normalize_attribute_name,
    strip_credential_attributes,
)


# ── Helpers (fake-connection idiom from test_phase0_privacy.py) ──────

def _make_server(expose: bool) -> DirSrvMCP:
    """Create a DirSrvMCP with one live-mode server config (never contacted)."""
    config = LDAPServerConfig(
        name="ds-mock",
        hostname="localhost",
        port=33891,
        base_dn="dc=example,dc=com",
        bind_dn="cn=Directory Manager",
        bind_password="TestPassword123",
    )
    env = {k: v for k, v in os.environ.items() if k != "LDAP_SERVERS_CONFIG"}
    with patch.dict(os.environ, env, clear=True):
        return DirSrvMCP(
            servers=[config],
            include_env_fallback=False,
            settings=MCPSettings(expose_sensitive_data=expose),
        )


def _install_fake_connection(server: DirSrvMCP, ds) -> None:
    """Replace server._connection so tools never open a real LDAP connection."""

    @contextmanager
    def _conn(server_name=None):
        yield (server_name or server.default_server, ds)

    server._connection = _conn


# Canary values — one per secret attribute so a leak is attributable.
_CANARIES = {
    "userPassword;binary": "SECRET-CANARY-123",
    "nsds5ReplicaBootstrapCredentials": "SECRET-CANARY-BOOTSTRAP-456",
    "nsmultiplexorcredentials": "SECRET-CANARY-CHAIN-789",
    "passwordHistory": "SECRET-CANARY-HISTORY-321",
    "unhashed#user#password": "SECRET-CANARY-CLEAR-654",
}


def _fake_search_side_effect():
    """ds.result side effect returning one entry full of secret canaries."""
    import ldap as _ldap

    attrs = {name: [value.encode("utf-8")] for name, value in _CANARIES.items()}
    attrs.update(
        {
            "uid": [b"jdoe"],
            "mail": [b"jdoe@example.com"],
            "passwordExpirationTime": [b"20370101000000Z"],
        }
    )
    return [
        (_ldap.RES_SEARCH_ENTRY, [("uid=jdoe,dc=example,dc=com", attrs)]),
        (_ldap.RES_SEARCH_RESULT, []),
    ]


# ── normalize_attribute_name (unit) ──────────────────────────────────

class TestNormalizeAttributeName:
    def test_plain_lowercase_passthrough(self):
        assert normalize_attribute_name("userpassword") == "userpassword"

    def test_case_folded(self):
        assert normalize_attribute_name("UserPassword") == "userpassword"
        assert normalize_attribute_name("USERPASSWORD") == "userpassword"

    def test_binary_option_stripped(self):
        assert normalize_attribute_name("userPassword;binary") == "userpassword"

    def test_lang_option_stripped(self):
        assert normalize_attribute_name("userPassword;lang-en") == "userpassword"

    def test_multiple_options_stripped(self):
        assert (
            normalize_attribute_name("userCertificate;binary;lang-en")
            == "usercertificate"
        )

    def test_whitespace_stripped(self):
        assert normalize_attribute_name("  userPassword ;binary") == "userpassword"

    def test_none_normalizes_empty(self):
        assert normalize_attribute_name(None) == ""

    def test_empty_normalizes_empty(self):
        assert normalize_attribute_name("") == ""
        assert normalize_attribute_name("   ") == ""

    def test_option_only_normalizes_empty(self):
        assert normalize_attribute_name(";binary") == ""

    def test_bytes_decoded(self):
        assert normalize_attribute_name(b"userPassword;binary") == "userpassword"

    def test_undecodable_bytes_normalize_empty(self):
        assert normalize_attribute_name(b"\xff\xfe") == ""

    def test_unhashed_pseudo_attribute_kept_whole(self):
        # '#' is not an option separator — the pseudo-attribute name survives
        assert (
            normalize_attribute_name("unhashed#user#password")
            == "unhashed#user#password"
        )


# ── is_secret_attribute (unit) ───────────────────────────────────────

class TestIsSecretAttribute:
    @pytest.mark.parametrize(
        "attr",
        [
            "userPassword",
            "USERPASSWORD",
            "userPassword;binary",
            "userPassword;lang-en",
            "nsslapd-rootpw",
            "nsDS5ReplicaCredentials",
            "nsds5ReplicaBootstrapCredentials",
            "nsds5ReplicaBootstrapCredentials;binary",
            "nsmultiplexorcredentials",
            "nsSymmetricKey",
            "passwordHistory",
            "pwdHistory",
            "unhashed#user#password",
            "sambaLMPassword",
            "sambaNTPassword",
            "krbPrincipalKey",
            "krbMKey",
            "ipaNTHash",
            "ipatokenOTPkey",
            "userPKCS12",
            "userCertificate;binary",
        ],
    )
    def test_known_secret_attributes(self, attr):
        assert is_secret_attribute(attr) is True

    @pytest.mark.parametrize(
        "attr",
        [
            # unknown-but-credential-like names: family match, fail closed
            "adminPassword",
            "myAppPassword;lang-en",
            "bindCredentials",
            "replicaPassphrase",
            "apiSecret",
            "someSymmetricKeyBlob",
            "krbPwdHistory",
        ],
    )
    def test_unknown_credential_like_names_fail_closed(self, attr):
        assert is_secret_attribute(attr) is True

    @pytest.mark.parametrize(
        "attr",
        [
            None,
            "",
            "   ",
            ";binary",
            b"\xff\xfe",
        ],
    )
    def test_unparseable_names_fail_closed(self, attr):
        assert is_secret_attribute(attr) is True

    @pytest.mark.parametrize(
        "attr",
        [
            # vetted 389 DS password policy / state attributes stay visible
            "passwordStorageScheme",
            "passwordMaxAge",
            "passwordInHistory",
            "passwordLockout",
            "passwordAdminDN",
            "nsslapd-pwpolicy-local",
            "nsslapd-allow-hashed-passwords",
            "passwordExpirationTime",
            "passwordRetryCount",
            "passwordTPRMaxUse",
            # standard DN-valued attribute containing "secret"
            "secretary",
            # ordinary attributes
            "uid",
            "cn",
            "mail",
            "objectClass",
            "nsslapd-port",
        ],
    )
    def test_policy_and_ordinary_attributes_not_secret(self, attr):
        assert is_secret_attribute(attr) is False

    def test_policy_allowlist_cannot_override_denylist(self):
        # every denylisted name stays secret even if someone later adds it
        # to the allowlist by mistake — deny check runs first
        for name in ALWAYS_REDACT_ATTRIBUTES:
            assert is_secret_attribute(name) is True

    def test_rootpw_storage_scheme_is_not_secret(self):
        # nsslapd-rootpwstoragescheme is a scheme name, not the root pw
        # itself; it matches no family substring and stays visible
        assert is_secret_attribute("nsslapd-rootpwstoragescheme") is False


# ── strip_credential_attributes routes through is_secret_attribute ───

class TestStripCredentialAttributesOptions:
    def test_binary_option_stripped(self):
        attrs = {
            "userPassword;binary": ["SECRET-CANARY-123"],
            "uid": ["jdoe"],
        }
        stripped = strip_credential_attributes(attrs)
        assert stripped == {"uid": ["jdoe"]}

    def test_new_denylist_members_stripped(self):
        attrs = {
            "nsds5ReplicaBootstrapCredentials": ["SECRET-CANARY-BOOTSTRAP-456"],
            "nsmultiplexorcredentials": ["SECRET-CANARY-CHAIN-789"],
            "nsSymmetricKey": ["SECRET-CANARY-KEY"],
            "passwordHistory": ["SECRET-CANARY-HISTORY-321"],
            "pwdHistory": ["SECRET-CANARY-HISTORY-322"],
            "unhashed#user#password": ["SECRET-CANARY-CLEAR-654"],
            "cn": ["John Doe"],
        }
        stripped = strip_credential_attributes(attrs)
        assert stripped == {"cn": ["John Doe"]}

    def test_policy_attributes_preserved(self):
        attrs = {
            "passwordExpirationTime": ["20370101000000Z"],
            "passwordRetryCount": ["2"],
            "passwordStorageScheme": ["PBKDF2-SHA512"],
            "secretary": ["cn=assistant,dc=example,dc=com"],
        }
        assert strip_credential_attributes(attrs) == attrs


# ── sanitize_attribute_value routes through is_secret_attribute ──────

class TestSanitizeAttributeValueOptions:
    def setup_method(self):
        self.sanitizer = PrivacySanitizer()

    def test_binary_option_redacted(self):
        assert (
            self.sanitizer.sanitize_attribute_value(
                "userPassword;binary", "{SSHA512}SECRET-CANARY-123"
            )
            == "[REDACTED]"
        )

    def test_lang_option_redacted(self):
        assert (
            self.sanitizer.sanitize_attribute_value(
                "userPassword;lang-en", "SECRET-CANARY-123"
            )
            == "[REDACTED]"
        )

    def test_new_denylist_members_redacted(self):
        for attr in (
            "nsds5ReplicaBootstrapCredentials",
            "nsmultiplexorcredentials",
            "nsSymmetricKey",
            "passwordHistory",
        ):
            assert (
                self.sanitizer.sanitize_attribute_value(attr, "SECRET-CANARY")
                == "[REDACTED]"
            )

    def test_unknown_credential_like_name_redacted(self):
        assert (
            self.sanitizer.sanitize_attribute_value(
                "adminPassword", "SECRET-CANARY-123"
            )
            == "[REDACTED]"
        )

    def test_policy_scheme_value_stays_readable(self):
        assert (
            self.sanitizer.sanitize_attribute_value(
                "passwordStorageScheme", "PBKDF2-SHA512"
            )
            == "PBKDF2-SHA512"
        )


# ── ldap_search: canaries never escape, in EITHER privacy mode ───────

class TestLdapSearchSecretDenial:
    @pytest.mark.asyncio
    async def test_exposed_mode_never_returns_secret_values(self):
        """LDAP_MCP_EXPOSE_SENSITIVE_DATA=true must not expose secrets."""
        server = _make_server(expose=True)
        ds = MagicMock()
        ds.search_ext.return_value = 1
        ds.result.side_effect = _fake_search_side_effect()
        _install_fake_connection(server, ds)

        async with Client(server) as client:
            result = await client.call_tool(
                "ldap_search",
                {"base_dn": "dc=example,dc=com", "filter": "(uid=jdoe)"},
            )
            data = result.data

        # entry is still returned (secret attrs withheld, not the entry)
        assert data["type"] == "ldap_search"
        assert data["total_returned"] == 1
        attrs = data["items"][0]["attrs"]
        assert attrs["uid"] == ["jdoe"]
        assert attrs["mail"] == ["jdoe@example.com"]
        # diagnostically-important password state survives
        assert attrs["passwordExpirationTime"] == ["20370101000000Z"]
        # no secret attribute key survives, under any spelling
        for key in attrs:
            assert not is_secret_attribute(key), f"secret attr leaked: {key}"
        # and no canary VALUE appears anywhere in the serialized result
        serialized = json.dumps(data)
        for attr, canary in _CANARIES.items():
            assert canary not in serialized, f"canary for {attr} leaked"

    @pytest.mark.asyncio
    async def test_privacy_mode_never_returns_secret_values(self):
        """Privacy mode disables ldap_search entirely — nothing escapes."""
        server = _make_server(expose=False)
        ds = MagicMock()
        ds.search_ext.return_value = 1
        ds.result.side_effect = _fake_search_side_effect()
        _install_fake_connection(server, ds)

        async with Client(server) as client:
            result = await client.call_tool(
                "ldap_search",
                {"base_dn": "dc=example,dc=com", "filter": "(uid=jdoe)"},
            )
            data = result.data

        assert data["type"] == "privacy_restricted"
        serialized = json.dumps(data)
        for attr, canary in _CANARIES.items():
            assert canary not in serialized, f"canary for {attr} leaked"

    @pytest.mark.asyncio
    async def test_explicitly_requested_secret_attr_still_withheld(self):
        """Requesting userPassword;binary by name returns the entry without it."""
        server = _make_server(expose=True)
        ds = MagicMock()
        ds.search_ext.return_value = 1
        ds.result.side_effect = _fake_search_side_effect()
        _install_fake_connection(server, ds)

        async with Client(server) as client:
            result = await client.call_tool(
                "ldap_search",
                {
                    "base_dn": "dc=example,dc=com",
                    "filter": "(uid=jdoe)",
                    "attributes": "uid,userPassword;binary",
                },
            )
            data = result.data

        assert data["total_returned"] == 1
        attrs = data["items"][0]["attrs"]
        assert attrs["uid"] == ["jdoe"]
        serialized = json.dumps(data)
        assert "SECRET-CANARY-123" not in serialized
        for key in attrs:
            assert normalize_attribute_name(key) != "userpassword"


# ── Confusable attribute spellings (review fix: NFKC + casefold) ─────

class TestConfusableAttributeNames:
    """Unicode spellings that are visually/foldingly equivalent to a
    credential family name must not bypass fail-closed matching."""

    def test_fullwidth_char_normalizes(self):
        # U+FF52 FULLWIDTH LATIN SMALL LETTER R
        assert normalize_attribute_name("userPasswoｒd") == "userpassword"
        assert is_secret_attribute("userPasswoｒd") is True

    def test_turkish_dotted_capital_folds(self):
        # U+0130 casefolds to "i" + combining dot; the mark is stripped
        assert is_secret_attribute("credentİal") is True

    def test_remaining_non_ascii_fails_closed(self):
        # RFC 4512 keystrings are ASCII: anything still non-ASCII after
        # NFKC cannot be a legitimate schema name -> treated as secret.
        assert normalize_attribute_name("passаword") == ""  # Cyrillic а
        assert is_secret_attribute("passаword") is True

    def test_plain_ascii_names_unaffected(self):
        assert normalize_attribute_name("telephoneNumber") == "telephonenumber"
        assert is_secret_attribute("telephoneNumber") is False


# ── cn=config resources (review fix: unconditional stripping) ────────

_CONFIG_ATTRS_JSON = json.dumps({
    "dn": "cn=config",
    "attrs": {
        "cn": ["config"],
        "nsslapd-port": ["389"],
        "nsslapd-rootpw": ["{PBKDF2-SHA512}10000$ROOTPW-CANARY-999"],
    },
})


class TestConfigResourceCredentialDenial:
    """The cn=config resources honor the credential-denial contract:
    credential values are stripped/refused in BOTH privacy and
    sensitive-data modes."""

    async def _read(self, server: DirSrvMCP, uri: str) -> str:
        ds = MagicMock()
        _install_fake_connection(server, ds)
        mock_config = MagicMock()
        mock_config.get_all_attrs_json.return_value = _CONFIG_ATTRS_JSON
        with patch(
            "ldap_assistant_mcp.dirsrv_mcp.server.Config",
            return_value=mock_config,
        ):
            async with Client(server) as client:
                contents = await client.read_resource(uri)
        return contents[0].text

    async def test_config_all_strips_rootpw_in_exposed_mode(self):
        text = await self._read(_make_server(expose=True), "config://config-all")
        assert "ROOTPW-CANARY" not in text
        assert "nsslapd-rootpw" not in text
        assert "nsslapd-port" in text  # non-secret attrs survive

    async def test_server_addressable_config_strips_rootpw(self):
        text = await self._read(_make_server(expose=True), "ldap://ds-mock/config")
        assert "ROOTPW-CANARY" not in text
        assert "nsslapd-port" in text

    async def test_config_all_strips_rootpw_in_privacy_mode(self):
        text = await self._read(_make_server(expose=False), "config://config-all")
        assert "ROOTPW-CANARY" not in text

    async def test_config_attribute_rootpw_refused_in_exposed_mode(self):
        server = _make_server(expose=True)
        _install_fake_connection(server, MagicMock())
        async with Client(server) as client:
            with pytest.raises(Exception) as excinfo:
                await client.read_resource(
                    "config://config-attribute/nsslapd-rootpw"
                )
        assert "credential attribute" in str(excinfo.value)

    async def test_config_attribute_options_spelling_refused(self):
        server = _make_server(expose=True)
        _install_fake_connection(server, MagicMock())
        async with Client(server) as client:
            with pytest.raises(Exception) as excinfo:
                await client.read_resource(
                    "config://config-attribute/nsslapd-rootpw;binary"
                )
        assert "credential attribute" in str(excinfo.value)
