"""Privacy utilities for sanitizing sensitive data in MCP outputs.

This module provides utilities to redact sensitive information from tool
outputs to prevent accidental exposure to AI agents/LLMs. By default,
the MCP server operates in privacy mode where sensitive data is redacted.

Anonymization is keyed-hash based: each sanitizer instance holds a random
128-bit key (generated once at startup via ``os.urandom``).  Placeholders
are derived via BLAKE2s keyed by this secret, so:

- Same instance + same input = same placeholder (deterministic across
  parallel tool calls).
- Different instances = different placeholders (the key never leaves RAM).
- Brute-force reversal requires ~2^128 work — physically infeasible.
"""

from __future__ import annotations

import hashlib
import os
import re
from typing import Any, Dict, List, Optional, Set

# Pattern matchers for sensitive data
DN_PATTERN = re.compile(r'^[a-zA-Z]+=.+', re.IGNORECASE)
HOSTNAME_PATTERN = re.compile(r'^[a-zA-Z0-9]([a-zA-Z0-9\-]*[a-zA-Z0-9])?(\.[a-zA-Z0-9]([a-zA-Z0-9\-]*[a-zA-Z0-9])?)*$')
PATH_PATTERN = re.compile(r'^/[^\s]+')
URL_PATTERN = re.compile(r'^ldaps?://[^\s]+', re.IGNORECASE)

# IP address literals in free text.  IPv4: exactly four dotted octets 0-255
# (4-component version strings like 1.4.3.28 are indistinguishable and get
# redacted too — over-redaction is the right failure mode for privacy).
_IPV4_SEG = r"(?:25[0-5]|2[0-4][0-9]|1[0-9][0-9]|[1-9]?[0-9])"
IPV4_ADDR_PATTERN = re.compile(
    rf"(?<![\w.]){_IPV4_SEG}(?:\.{_IPV4_SEG}){{3}}(?![\w.])"
)
# IPv6: the full 8-group form or a compressed form containing "::" with at
# least one hex group (bare "::" is never matched).  Requiring "::" or all
# 8 groups keeps timestamps (12:34:56) and MAC addresses out.  Optional
# surrounding brackets and zone index ([fe80::1%eth0]) are consumed so a
# following :port is recognizable.
_H16 = r"[0-9A-Fa-f]{1,4}"
_IPV6_BODY = (
    rf"(?:{_H16}:){{7}}{_H16}"                                # full form
    rf"|{_H16}(?::{_H16})*::(?:{_H16}(?::{_H16})*)?"           # a::b / a::
    rf"|::{_H16}(?::{_H16})*"                                  # ::b
)
_IPV6_ZONE = r"(?:%[\w.~-]+)?"
IPV6_ADDR_PATTERN = re.compile(
    rf"(?<![\w:.])"
    rf"(?:\[(?:{_IPV6_BODY}){_IPV6_ZONE}\]"        # [addr] — may be followed by :port
    rf"|(?:{_IPV6_BODY}){_IPV6_ZONE}(?![\w:]))"    # bare addr — must end cleanly
)

# Maximum entries per anonymization mapping dict.  When a mapping grows
# past this size, the oldest half is evicted (dicts preserve insertion
# order).  Tokens are derived from a keyed hash, so an evicted value that
# reappears later gets the same placeholder — eviction only bounds memory,
# it never breaks determinism.
_MAX_MAPPING_SIZE = 10_000

# Attribute names that should always be redacted (case-insensitive)
ALWAYS_REDACT_ATTRIBUTES: Set[str] = {
    # Credentials
    "userpassword", "userpkcs12", "sshpublickey",
    "usersmimecertificate", "usercertificate",
    "nsslapd-rootpw", "nsds5replicacredentials",
    # Binary data
    "jpegphoto", "photo", "audio",
}

# Attribute names containing sensitive identifiers
SENSITIVE_IDENTIFIER_ATTRIBUTES: Set[str] = {
    # DNs and names
    "dn", "cn", "uid", "mail", "displayname", "givenname", "sn",
    "manager", "secretary", "member", "uniquemember", "memberof",
    "owner", "seealso", "creatorsname", "modifiersname",
    "nsslapd-rootdn",
    # Hostnames and URLs
    "nsds5replicahost", "nsslapd-localhost", "nsslapd-listenhost",
    "nsslapd-securelistenhost", "nsslapd-referral",
    "nsslapd-ldapifilepath", "nsslapd-certdir", "nsslapd-ldifdir",
    "nsslapd-bakdir", "nsslapd-tmpdir", "nsslapd-schemadir",
    "nsslapd-instancedir", "nsslapd-accesslog", "nsslapd-errorlog",
    "nsslapd-auditlog", "nsslapd-auditfailedlog", "nsslapd-securitylog",
    "nsslapd-rundir", "nsslapd-lockdir", "nsslapd-db-home-directory",
    # Suffixes and base DNs
    "nsslapd-suffix", "nsds5replicaroot", "nsslapd-defaultnamingcontext",
}


class PrivacySanitizer:
    """Sanitizes sensitive data from tool outputs.

    Maintains consistent anonymization mappings within a session so that
    the same value always maps to the same anonymized identifier — even
    across parallel tool calls.

    Placeholders are derived via BLAKE2s with a per-instance random key
    and the category as the ``person`` parameter (domain separation).
    The key is generated once at init and never leaves memory, making
    brute-force reversal require ~2^128 work — physically infeasible.

    A mapping cache avoids recomputing hashes on repeated lookups.
    """

    def __init__(self) -> None:
        """Initialize the sanitizer with a random key and empty caches."""
        self._key: bytes = os.urandom(16)
        self._hostname_map: Dict[str, str] = {}
        self._dn_map: Dict[str, str] = {}
        self._suffix_map: Dict[str, str] = {}
        self._server_map: Dict[str, str] = {}
        self._user_map: Dict[str, str] = {}
        self._group_map: Dict[str, str] = {}
        self._ip_map: Dict[str, str] = {}

    def reset(self) -> None:
        """Reset all anonymization mapping caches."""
        self._hostname_map.clear()
        self._dn_map.clear()
        self._suffix_map.clear()
        self._server_map.clear()
        self._user_map.clear()
        self._group_map.clear()
        self._ip_map.clear()

    def _token(self, category: str, value: str) -> str:
        """Derive a deterministic placeholder token from *value*.

        Uses BLAKE2s with each parameter for its designed purpose:

        - ``key``:    per-instance random secret (prevents reversal).
        - ``person``: category string (domain separation — same value
          in different categories yields different tokens).
        - message:    the value to anonymize.

        The 8-byte digest (16 hex chars) balances readability with
        collision resistance (~2^64 birthday bound).
        """
        return hashlib.blake2s(
            value.encode("utf-8"),
            key=self._key,
            person=category.encode("utf-8"),
            digest_size=8,
        ).hexdigest()

    @staticmethod
    def _bounded_insert(mapping: Dict[str, str], key: str, value: str) -> None:
        """Insert into *mapping*, evicting the oldest half at the size cap.

        Dicts preserve insertion order, so the first half of the keys are
        the oldest.  Because placeholders are derived from a keyed hash,
        re-inserting an evicted key later yields the same token, keeping
        anonymization consistent across evictions.
        """
        if key not in mapping and len(mapping) >= _MAX_MAPPING_SIZE:
            for old_key in list(mapping)[:_MAX_MAPPING_SIZE // 2]:
                del mapping[old_key]
        mapping[key] = value

    def _get_anon_hostname(self, hostname: str) -> str:
        """Get anonymized hostname, deterministic within this session."""
        if not hostname:
            return hostname
        key = hostname.lower()
        if key not in self._hostname_map:
            self._bounded_insert(self._hostname_map, key, f"[host-{self._token('host', key)}]")
        return self._hostname_map[key]

    def _get_anon_server(self, server_name: str) -> str:
        """Get anonymized server name, deterministic within this session."""
        if not server_name:
            return server_name
        key = server_name.lower()
        if key not in self._server_map:
            self._bounded_insert(self._server_map, key, f"[server-{self._token('server', key)}]")
        return self._server_map[key]

    def _get_anon_suffix(self, suffix: str) -> str:
        """Get anonymized suffix, deterministic within this session."""
        if not suffix:
            return suffix
        key = suffix.lower()
        if key not in self._suffix_map:
            self._bounded_insert(self._suffix_map, key, f"[suffix-{self._token('suffix', key)}]")
        return self._suffix_map[key]

    def _get_anon_dn(self, dn: str) -> str:
        """Get anonymized DN, deterministic within this session."""
        if not dn:
            return dn
        key = dn.lower()
        if key not in self._dn_map:
            self._bounded_insert(self._dn_map, key, f"[entry-{self._token('entry', key)}]")
        return self._dn_map[key]

    def _get_anon_user(self, user: str) -> str:
        """Get anonymized user, deterministic within this session."""
        if not user:
            return user
        key = user.lower()
        if key not in self._user_map:
            self._bounded_insert(self._user_map, key, f"[user-{self._token('user', key)}]")
        return self._user_map[key]

    def _get_anon_group(self, group: str) -> str:
        """Get anonymized group, deterministic within this session."""
        if not group:
            return group
        key = group.lower()
        if key not in self._group_map:
            self._bounded_insert(self._group_map, key, f"[group-{self._token('group', key)}]")
        return self._group_map[key]

    def _get_anon_ip(self, address: str) -> str:
        """Get anonymized IP address, deterministic within this session."""
        if not address:
            return address
        # Strip brackets so [2001:db8::1] and 2001:db8::1 share one token.
        key = address.strip("[]").lower()
        if key not in self._ip_map:
            self._bounded_insert(self._ip_map, key, f"[ip-{self._token('ip', key)}]")
        return self._ip_map[key]

    def sanitize_hostname(self, hostname: Optional[str]) -> Optional[str]:
        """Sanitize a hostname value."""
        if not hostname:
            return hostname
        return self._get_anon_hostname(hostname)

    def sanitize_server_name(self, server_name: Optional[str]) -> Optional[str]:
        """Sanitize a server name value."""
        if not server_name:
            return server_name
        return self._get_anon_server(server_name)

    def sanitize_dn(self, dn: Optional[str]) -> Optional[str]:
        """Sanitize a DN value."""
        if not dn:
            return dn
        return self._get_anon_dn(dn)

    def sanitize_suffix(self, suffix: Optional[str]) -> Optional[str]:
        """Sanitize a suffix value."""
        if not suffix:
            return suffix
        return self._get_anon_suffix(suffix)

    def sanitize_url(self, url: Optional[str]) -> Optional[str]:
        """Sanitize an LDAP URL."""
        if not url:
            return url
        # Extract and anonymize hostname from URL
        if url.lower().startswith("ldap://") or url.lower().startswith("ldaps://"):
            return "[ldap-url]"
        return "[url]"

    def sanitize_path(self, path: Optional[str]) -> Optional[str]:
        """Sanitize a file path."""
        if not path:
            return path
        return "[path]"

    def sanitize_attribute_value(
        self,
        attr_name: str,
        value: Any,
    ) -> Any:
        """Sanitize an attribute value based on attribute name.

        Args:
            attr_name: The attribute name (case-insensitive matching)
            value: The attribute value to sanitize

        Returns:
            Sanitized value or [REDACTED] for sensitive attributes
        """
        attr_lower = attr_name.lower()

        # Always redact credentials and binary data
        if attr_lower in ALWAYS_REDACT_ATTRIBUTES:
            return "[REDACTED]"

        # Handle lists
        if isinstance(value, list):
            return [self.sanitize_attribute_value(attr_name, v) for v in value]

        # Recurse into nested dicts (e.g. lib389 get_all_attrs_json returns
        # a {"type", "dn", "attrs": {...}} envelope) so per-attribute
        # sanitization applies instead of redacting the whole structure.
        if isinstance(value, dict):
            return self.sanitize_dict(value)

        # Convert to string for pattern matching
        str_value = str(value) if value is not None else ""

        # Redact sensitive identifiers
        if attr_lower in SENSITIVE_IDENTIFIER_ATTRIBUTES:
            # Check if it looks like a DN
            if DN_PATTERN.match(str_value):
                return self._get_anon_dn(str_value)
            # Check if it looks like a path
            if PATH_PATTERN.match(str_value):
                return "[path]"
            # Check if it looks like a URL
            if URL_PATTERN.match(str_value):
                return "[ldap-url]"
            # Check if it looks like a hostname
            if HOSTNAME_PATTERN.match(str_value) and "." in str_value:
                return self._get_anon_hostname(str_value)
            # Generic identifier redaction
            return "[REDACTED]"

        # Fail-closed for attributes outside the sensitive sets: values
        # shaped like identifiers are tokenized and free text is
        # pattern-scrubbed, so an attribute name missing from the sets
        # does not pass identifier-shaped values through raw.
        if value is None or isinstance(value, (bool, int, float)):
            return value
        if not isinstance(value, str):
            # Structured/binary values can't be vetted — redact outright.
            return "[REDACTED]"
        if DN_PATTERN.match(str_value):
            return self._get_anon_dn(str_value)
        if PATH_PATTERN.match(str_value):
            return "[path]"
        if URL_PATTERN.match(str_value):
            return "[ldap-url]"
        # Hostname only if the final label contains a letter — keeps
        # version strings (3.1.1, TLS1.2) and OIDs readable; bare IPs
        # are still caught by sanitize_text's IP patterns below.
        if (
            HOSTNAME_PATTERN.match(str_value)
            and "." in str_value
            and any(c.isalpha() for c in str_value.rsplit(".", 1)[-1])
        ):
            return self._get_anon_hostname(str_value)
        return self.sanitize_text(str_value)

    def sanitize_dict(self, data: Dict[str, Any]) -> Dict[str, Any]:
        """Sanitize a dictionary of attributes.

        Args:
            data: Dictionary to sanitize

        Returns:
            New dictionary with sanitized values
        """
        result = {}
        for key, value in data.items():
            result[key] = self.sanitize_attribute_value(key, value)
        return result

    def sanitize_text(self, text: str) -> str:
        """Sanitize a text field by replacing sensitive patterns.

        Handles (in order): LDAP URLs, file paths, multi-component LDAP DNs,
        IPv4/IPv6 addresses, email addresses, FQDNs, and port numbers
        following placeholders.
        """
        if not text:
            return text
        # 1. LDAP URLs (before hostname matching to avoid partial matches)
        text = re.sub(r'ldaps?://\S+', '[ldap-url]', text, flags=re.IGNORECASE)
        # 2. File paths (absolute, at least 2 segments: /dir/file)
        text = re.sub(r'(?<![.\w])/(?:[a-zA-Z0-9._-]+/)+[a-zA-Z0-9._-]+', '[path]', text)
        # 3. LDAP DNs (require at least 2 comma-separated attr=value components)
        text = re.sub(
            r'\b[a-zA-Z][a-zA-Z0-9-]*=[^,\s]+(?:,[a-zA-Z][a-zA-Z0-9-]*=[^,\s]+)+',
            '[dn]', text,
        )
        # 4. IP address literals (deterministic tokens, like hostnames)
        text = IPV6_ADDR_PATTERN.sub(lambda m: self._get_anon_ip(m.group(0)), text)
        text = IPV4_ADDR_PATTERN.sub(lambda m: self._get_anon_ip(m.group(0)), text)
        # 5. Email addresses (before FQDNs so the local part goes too)
        text = re.sub(r'\b[\w.+-]+@[\w.-]+\.[A-Za-z]{2,}\b', '[email]', text)
        # 6. FQDNs (expanded TLD list; longer alternatives first)
        text = re.sub(
            r'\b[\w.-]+\.(?:localhost|internal|example|online|cloud|store|'
            r'intra|local|corp|tech|site|info|com|org|net|edu|gov|mil|int|'
            r'biz|dev|app|xyz|lan|test|io|co|ai|me|us|uk|de|fr|eu|ca|au|jp|'
            r'cn|in|br|ru|nl|se|no|fi|dk|ch|at|be|pl|cz|es|it|pt|ie|nz|kr|'
            r'tw|hk|sg|za|mx)\b',
            '[hostname]', text, flags=re.IGNORECASE,
        )
        # 7. Port numbers after placeholders
        text = re.sub(r'\[hostname\]:\d+', '[hostname]:[port]', text)
        text = re.sub(r'\[dn\]:\d+', '[dn]:[port]', text)
        text = re.sub(r'(\[ip-[0-9a-f]+\]):\d+', r'\1:[port]', text)
        return text

    def sanitize_finding(self, finding: Dict[str, Any]) -> Dict[str, Any]:
        """Sanitize a finding dictionary.

        Preserves diagnostic information while redacting specific values.
        Text fields (title, impact, details, remediation) are scrubbed for
        embedded DNs, hostnames, URLs, and paths.  Metadata keys are handled
        individually based on their semantic meaning.  Top-level keys are
        vetted individually — format_finding produces a fixed key set, and
        anything beyond it must not pass through raw.
        """
        result = {}
        for key, value in finding.items():
            key_lower = key.lower()
            if key_lower in ("severity", "server"):
                # Severity is an enum; server names are never sanitized
                # (user-chosen config labels).
                result[key] = value
            elif key_lower in ("title", "impact", "details", "remediation") and isinstance(value, str):
                # Free-text fields may embed sensitive data
                result[key] = self.sanitize_text(value)
            elif key_lower == "metadata" and isinstance(value, dict):
                result[key] = self._sanitize_finding_metadata(value)
            elif value is None or isinstance(value, (bool, int, float)):
                # Numbers/bools cannot carry identifiers (diagnostic counts)
                result[key] = value
            elif isinstance(value, str):
                result[key] = self.sanitize_text(value)
            else:
                # Deny-by-default: unvetted keys must not pass through raw.
                result[key] = "[REDACTED]"
        return result

    def _sanitize_finding_metadata(self, metadata: Dict[str, Any]) -> Dict[str, Any]:
        """Sanitize a finding's metadata dict, key by key."""
        sanitized_meta = {}
        for key, value in metadata.items():
            key_lower = key.lower()
            if key_lower in ("suffix", "base_dn"):
                sanitized_meta[key] = self.sanitize_suffix(str(value)) if value else value
            elif key_lower in ("server", "supplier", "consumer", "consumers"):
                sanitized_meta[key] = value  # Server names are never sanitized
            elif key_lower in ("agreement", "name"):
                sanitized_meta[key] = "[agreement]" if value else value
            elif key_lower in ("dn", "entry", "base"):
                sanitized_meta[key] = self.sanitize_dn(str(value)) if value else value
            elif key_lower == "backend":
                sanitized_meta[key] = "[backend]" if value else value
            elif key_lower == "partition":
                sanitized_meta[key] = "[partition]" if value else value
            elif key_lower == "filter":
                sanitized_meta[key] = "[filter]" if value else value
            elif key_lower == "items":
                if isinstance(value, list):
                    sanitized_meta[key] = [self.sanitize_text(str(item)) for item in value]
                else:
                    sanitized_meta[key] = self.sanitize_text(str(value)) if value else value
            else:
                # Deny-by-default for unrecognized keys: numbers/bools
                # stay (diagnostic counts and ratios), strings get the
                # same pattern scrub as the free-text fields, and
                # anything structured is redacted outright.
                if value is None or isinstance(value, (bool, int, float)):
                    sanitized_meta[key] = value
                elif isinstance(value, str):
                    sanitized_meta[key] = self.sanitize_text(value)
                elif isinstance(value, list):
                    sanitized_meta[key] = [
                        item if isinstance(item, (bool, int, float)) or item is None
                        else self.sanitize_text(str(item))
                        for item in value
                    ]
                else:
                    sanitized_meta[key] = "[REDACTED]"
        return sanitized_meta

    def sanitize_findings(self, findings: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """Sanitize a list of findings."""
        return [self.sanitize_finding(f) for f in findings]

    def sanitize_agreement(self, agreement: Dict[str, Any]) -> Dict[str, Any]:
        """Sanitize a replication agreement dictionary."""
        result = {}
        for key, value in agreement.items():
            key_lower = key.lower()
            if key_lower in ("name", "agreement"):
                result[key] = "[agreement]"
            elif key_lower in ("consumer_host", "target_host", "source"):
                result[key] = self.sanitize_hostname(value)
            elif key_lower in ("consumer_port", "target_port"):
                result[key] = "[port]"
            elif key_lower == "consumer":
                result[key] = "[replica]"
            elif key_lower == "suffix":
                result[key] = self.sanitize_suffix(value)
            elif key_lower == "status" and isinstance(value, dict):
                # Keep status structure but sanitize any embedded values
                result[key] = self._sanitize_status(value)
            elif "csn" in key_lower:
                result[key] = "[csn]"
            elif key_lower == "reason" and isinstance(value, str):
                result[key] = self.sanitize_text(value)
            elif key_lower == "error" and isinstance(value, str):
                result[key] = self.sanitize_text(value)
            elif "status" in key_lower and isinstance(value, str):
                # last_update_status/last_init_status embed free text from
                # the remote server (hostnames, DNs, LDAP URLs); enum-like
                # values (lag_status, sync-state messages) pass unchanged.
                result[key] = self.sanitize_text(value)
            elif key_lower in (
                "transport",
                "bind_method",
                "enabled",
                "state",
                "last_update_start",
                "last_update_end",
                "changes_sent",
            ):
                # Enum-like flags, timestamps, and change counters carry no
                # identifiers.
                result[key] = value
            elif value is None or isinstance(value, (bool, int, float)):
                # Numbers/bools cannot carry identifiers (diagnostic counts)
                result[key] = value
            else:
                # Deny-by-default: unvetted keys must not pass through raw.
                result[key] = "[REDACTED]"
        return result

    def _sanitize_status(self, status: Dict[str, Any]) -> Dict[str, Any]:
        """Sanitize status dictionary, keeping state indicators."""
        result = {}
        for key, value in status.items():
            key_lower = key.lower()
            # Keep state/status indicators (state, msg, lag_status are enum-like)
            if key_lower in ("state", "msg", "lag_status"):
                result[key] = value
            # Reason may contain free text with hostnames/DNs
            elif key_lower == "reason" and isinstance(value, str):
                result[key] = self.sanitize_text(value)
            # Redact CSN values (contain timestamps/server IDs)
            elif "csn" in key_lower:
                result[key] = "[csn]"
            elif key_lower == "error" and isinstance(value, str):
                result[key] = self.sanitize_text(value)
            elif value is None or isinstance(value, (bool, int, float)):
                # Numbers/bools cannot carry identifiers (diagnostic counts)
                result[key] = value
            else:
                # Deny-by-default: unvetted keys must not pass through raw.
                result[key] = "[REDACTED]"
        return result

    def sanitize_replica(self, replica: Dict[str, Any]) -> Dict[str, Any]:
        """Sanitize a replica dictionary."""
        result = {}
        for key, value in replica.items():
            key_lower = key.lower()
            if key_lower == "suffix":
                result[key] = self.sanitize_suffix(value)
            elif key_lower == "agreements" and isinstance(value, list):
                result[key] = [self.sanitize_agreement(a) for a in value]
            elif key_lower == "ruv" and isinstance(value, dict):
                result[key] = self._sanitize_ruv(value)
            elif "error" in key_lower and isinstance(value, str):
                # error / agreements_error carry raw exception text
                result[key] = self.sanitize_text(value)
            elif key_lower in ("role", "replica_id"):
                # Role enum and replica ID carry no identifiers
                result[key] = value
            elif value is None or isinstance(value, (bool, int, float)):
                # Numbers/bools cannot carry identifiers (tombstone_count)
                result[key] = value
            else:
                # Deny-by-default: unvetted keys must not pass through raw.
                result[key] = "[REDACTED]"
        return result

    def _sanitize_ruv(self, ruv: Dict[str, Any]) -> Dict[str, Any]:
        """Sanitize RUV dictionary."""
        result = {}
        for key, value in ruv.items():
            key_lower = key.lower()
            if key_lower == "replicas":
                result[key] = "[ruv-data]"
            elif key_lower == "data_generation":
                result[key] = "[generation-id]"
            elif "error" in key_lower and isinstance(value, str):
                # error carries raw exception text (may embed DNs/hostnames)
                result[key] = self.sanitize_text(value)
            elif value is None or isinstance(value, (bool, int, float)):
                # Numbers/bools cannot carry identifiers (replica_count)
                result[key] = value
            else:
                # Deny-by-default: unvetted keys must not pass through raw.
                result[key] = "[REDACTED]"
        return result

    def sanitize_server_info(self, server_info: Dict[str, Any]) -> Dict[str, Any]:
        """Sanitize server information dictionary."""
        result = {}
        for key, value in server_info.items():
            key_lower = key.lower()
            if key_lower == "name":
                result[key] = value  # Server names are never sanitized
            elif key_lower == "url":
                result[key] = self.sanitize_url(value)
            elif key_lower == "replicas" and isinstance(value, list):
                result[key] = [self.sanitize_replica(r) for r in value]
            elif key_lower == "error" and isinstance(value, str):
                result[key] = self.sanitize_text(value)
            elif value is None or isinstance(value, (bool, int, float)):
                # Numbers/bools cannot carry identifiers (diagnostic counts)
                result[key] = value
            else:
                # Deny-by-default: unvetted keys must not pass through raw.
                result[key] = "[REDACTED]"
        return result


def strip_credential_attributes(attrs: Dict[str, Any]) -> Dict[str, Any]:
    """Return a copy of *attrs* without credential/binary attributes.

    Attributes in :data:`ALWAYS_REDACT_ATTRIBUTES` (userPassword,
    nsslapd-rootpw, certificates, ...) are never diagnostically useful,
    so they are stripped from tool outputs unconditionally — in both
    privacy and sensitive-data modes.
    """
    return {
        key: value
        for key, value in attrs.items()
        if key.lower() not in ALWAYS_REDACT_ATTRIBUTES
    }


# Global sanitizer instance for consistent anonymization within a session
_global_sanitizer: Optional[PrivacySanitizer] = None


def get_sanitizer() -> PrivacySanitizer:
    """Get or create the global privacy sanitizer instance."""
    global _global_sanitizer
    if _global_sanitizer is None:
        _global_sanitizer = PrivacySanitizer()
    return _global_sanitizer


def reset_sanitizer() -> None:
    """Reset the global sanitizer mappings."""
    global _global_sanitizer
    if _global_sanitizer is not None:
        _global_sanitizer.reset()


def create_privacy_error(tool_name: str) -> Dict[str, Any]:
    """Create an error response for tools disabled in privacy mode."""
    return {
        "type": "privacy_restricted",
        "error": f"Tool '{tool_name}' is disabled in privacy mode. "
                 "Set LDAP_MCP_EXPOSE_SENSITIVE_DATA=true to enable.",
        "hint": "This tool exposes sensitive directory data. Enable "
                "expose_sensitive_data in settings for full access.",
    }


def create_count_only_response(
    tool_type: str,
    server: str,
    count: int,
    sanitizer: Optional[PrivacySanitizer] = None,
) -> Dict[str, Any]:
    """Create a count-only response for privacy mode."""
    return {
        "type": tool_type,
        "server": server,  # Server names are never sanitized
        "privacy_mode": True,
        "count": count,
        "message": f"Found {count} entries. Enable expose_sensitive_data for details.",
    }
