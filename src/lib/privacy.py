"""Privacy utilities for sanitizing sensitive data in MCP outputs.

This module provides utilities to redact sensitive information from tool
outputs to prevent accidental exposure to AI agents/LLMs. By default,
the MCP server operates in privacy mode where sensitive data is redacted.

The sanitization maintains consistent anonymization - the same hostname
will always map to the same [server-N] identifier within a session.
"""

from __future__ import annotations

import re
from typing import Any, Dict, List, Optional, Set

# Pattern matchers for sensitive data
DN_PATTERN = re.compile(r'^[a-zA-Z]+=.+', re.IGNORECASE)
HOSTNAME_PATTERN = re.compile(r'^[a-zA-Z0-9]([a-zA-Z0-9\-]*[a-zA-Z0-9])?(\.[a-zA-Z0-9]([a-zA-Z0-9\-]*[a-zA-Z0-9])?)*$')
PATH_PATTERN = re.compile(r'^/[^\s]+')
URL_PATTERN = re.compile(r'^ldaps?://[^\s]+', re.IGNORECASE)

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
    # Hostnames and URLs
    "nsds5replicahost", "nsslapd-localhost", "nsslapd-listenhost",
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
    the same value always maps to the same anonymized identifier.
    """

    def __init__(self) -> None:
        """Initialize the sanitizer with empty mapping caches."""
        self._hostname_map: Dict[str, str] = {}
        self._dn_map: Dict[str, str] = {}
        self._suffix_map: Dict[str, str] = {}
        self._server_map: Dict[str, str] = {}
        self._user_map: Dict[str, str] = {}
        self._group_map: Dict[str, str] = {}

    def reset(self) -> None:
        """Reset all anonymization mappings."""
        self._hostname_map.clear()
        self._dn_map.clear()
        self._suffix_map.clear()
        self._server_map.clear()
        self._user_map.clear()
        self._group_map.clear()

    def _get_anon_hostname(self, hostname: str) -> str:
        """Get anonymized hostname, maintaining consistent mapping."""
        if not hostname:
            return hostname
        key = hostname.lower()
        if key not in self._hostname_map:
            self._hostname_map[key] = f"[host-{len(self._hostname_map) + 1}]"
        return self._hostname_map[key]

    def _get_anon_server(self, server_name: str) -> str:
        """Get anonymized server name, maintaining consistent mapping."""
        if not server_name:
            return server_name
        key = server_name.lower()
        if key not in self._server_map:
            self._server_map[key] = f"[server-{len(self._server_map) + 1}]"
        return self._server_map[key]

    def _get_anon_suffix(self, suffix: str) -> str:
        """Get anonymized suffix, maintaining consistent mapping."""
        if not suffix:
            return suffix
        key = suffix.lower()
        if key not in self._suffix_map:
            self._suffix_map[key] = f"[suffix-{len(self._suffix_map) + 1}]"
        return self._suffix_map[key]

    def _get_anon_dn(self, dn: str) -> str:
        """Get anonymized DN, maintaining consistent mapping."""
        if not dn:
            return dn
        key = dn.lower()
        if key not in self._dn_map:
            self._dn_map[key] = f"[entry-{len(self._dn_map) + 1}]"
        return self._dn_map[key]

    def _get_anon_user(self, user: str) -> str:
        """Get anonymized user identifier, maintaining consistent mapping."""
        if not user:
            return user
        key = user.lower()
        if key not in self._user_map:
            self._user_map[key] = f"[user-{len(self._user_map) + 1}]"
        return self._user_map[key]

    def _get_anon_group(self, group: str) -> str:
        """Get anonymized group identifier, maintaining consistent mapping."""
        if not group:
            return group
        key = group.lower()
        if key not in self._group_map:
            self._group_map[key] = f"[group-{len(self._group_map) + 1}]"
        return self._group_map[key]

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

        return value

    def sanitize_dict(
        self,
        data: Dict[str, Any],
        *,
        sanitize_keys: Optional[Set[str]] = None,
    ) -> Dict[str, Any]:
        """Sanitize a dictionary of attributes.

        Args:
            data: Dictionary to sanitize
            sanitize_keys: Optional set of specific keys to sanitize.
                          If None, uses default sensitive attribute detection.

        Returns:
            New dictionary with sanitized values
        """
        result = {}
        for key, value in data.items():
            if sanitize_keys and key.lower() not in sanitize_keys:
                result[key] = value
            else:
                result[key] = self.sanitize_attribute_value(key, value)
        return result

    def sanitize_entry(self, entry: Dict[str, Any]) -> Dict[str, Any]:
        """Sanitize a complete LDAP entry.

        Args:
            entry: Entry dict with 'dn' and 'attrs' keys

        Returns:
            Sanitized entry
        """
        result = {}

        # Sanitize DN
        if "dn" in entry:
            result["dn"] = self.sanitize_dn(entry["dn"])

        # Sanitize attributes
        if "attrs" in entry and isinstance(entry["attrs"], dict):
            result["attrs"] = self.sanitize_dict(entry["attrs"])

        # Copy other non-sensitive keys
        for key, value in entry.items():
            if key not in ("dn", "attrs"):
                result[key] = value

        return result

    def sanitize_entries(self, entries: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """Sanitize a list of LDAP entries."""
        return [self.sanitize_entry(e) for e in entries]

    def _sanitize_text_field(self, text: str) -> str:
        """Sanitize a text field by replacing DNs and hostnames."""
        if not text:
            return text
        # Replace DNs (e.g., dc=example,dc=com, cn=admin)
        text = re.sub(r'\b[a-zA-Z]+=[\w\s,=]+', '[dn]', text)
        # Replace hostnames
        text = re.sub(r'\b[\w.-]+\.(com|org|net|local|internal)\b', '[hostname]', text)
        # Replace port numbers that follow hostnames (e.g., :389, :636)
        text = re.sub(r'\[hostname\]:\d+', '[hostname]:[port]', text)
        return text

    def sanitize_finding(self, finding: Dict[str, Any]) -> Dict[str, Any]:
        """Sanitize a finding dictionary.

        Preserves diagnostic information while redacting specific values.
        """
        result = dict(finding)

        # Sanitize server name
        if "server" in result:
            result["server"] = self.sanitize_server_name(result["server"])

        # Sanitize title - may contain agreement names, suffixes, etc.
        if "title" in result and isinstance(result["title"], str):
            result["title"] = self._sanitize_text_field(result["title"])

        # Sanitize impact - may contain hostnames, suffixes, ports
        if "impact" in result and isinstance(result["impact"], str):
            result["impact"] = self._sanitize_text_field(result["impact"])

        # Sanitize details - redact specific values but keep structure
        if "details" in result and isinstance(result["details"], str):
            result["details"] = self._sanitize_text_field(result["details"])

        # Sanitize metadata
        if "metadata" in result and isinstance(result["metadata"], dict):
            sanitized_meta = {}
            for key, value in result["metadata"].items():
                key_lower = key.lower()
                if key_lower in ("suffix", "base_dn"):
                    sanitized_meta[key] = self.sanitize_suffix(str(value)) if value else value
                elif key_lower in ("server", "supplier", "consumer"):
                    sanitized_meta[key] = self.sanitize_server_name(str(value)) if value else value
                elif key_lower in ("agreement", "name"):
                    sanitized_meta[key] = "[agreement]" if value else value
                elif key_lower in ("dn", "entry"):
                    sanitized_meta[key] = self.sanitize_dn(str(value)) if value else value
                else:
                    # Keep numeric and status values
                    sanitized_meta[key] = value
            result["metadata"] = sanitized_meta

        return result

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
            else:
                result[key] = value
        return result

    def _sanitize_status(self, status: Dict[str, Any]) -> Dict[str, Any]:
        """Sanitize status dictionary, keeping state indicators."""
        result = {}
        for key, value in status.items():
            key_lower = key.lower()
            # Keep state/status indicators
            if key_lower in ("state", "msg", "lag_status", "reason"):
                result[key] = value
            # Redact CSN values (contain timestamps/server IDs)
            elif "csn" in key_lower:
                result[key] = "[csn]"
            else:
                result[key] = value
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
            else:
                result[key] = value
        return result

    def _sanitize_ruv(self, ruv: Dict[str, Any]) -> Dict[str, Any]:
        """Sanitize RUV dictionary."""
        result = dict(ruv)
        if "replicas" in result:
            result["replicas"] = "[ruv-data]"
        if "data_generation" in result:
            result["data_generation"] = "[generation-id]"
        return result

    def sanitize_backend(self, backend: Dict[str, Any]) -> Dict[str, Any]:
        """Sanitize a backend configuration dictionary."""
        result = {}
        for key, value in backend.items():
            key_lower = key.lower()
            if key_lower == "suffix":
                result[key] = self.sanitize_suffix(value)
            elif key_lower == "name":
                result[key] = "[backend]"
            elif key_lower == "config" and isinstance(value, dict):
                result[key] = self.sanitize_dict(value)
            else:
                result[key] = value
        return result

    def sanitize_server_info(self, server_info: Dict[str, Any]) -> Dict[str, Any]:
        """Sanitize server information dictionary."""
        result = {}
        for key, value in server_info.items():
            key_lower = key.lower()
            if key_lower == "name":
                result[key] = self.sanitize_server_name(value)
            elif key_lower == "url":
                result[key] = self.sanitize_url(value)
            elif key_lower == "replicas" and isinstance(value, list):
                result[key] = [self.sanitize_replica(r) for r in value]
            else:
                result[key] = value
        return result


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
    s = sanitizer or get_sanitizer()
    return {
        "type": tool_type,
        "server": s.sanitize_server_name(server),
        "privacy_mode": True,
        "count": count,
        "message": f"Found {count} entries. Enable expose_sensitive_data for details.",
    }
