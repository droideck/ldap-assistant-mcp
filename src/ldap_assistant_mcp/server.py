from __future__ import annotations

import os
from dataclasses import dataclass, replace
from enum import Enum
from typing import Any, Dict, Iterable, List, Optional
from urllib.parse import urlparse

from fastmcp import FastMCP

__all__ = ["LDAPAssistantMCP", "LDAPAuthMethod", "LDAPServerConfig"]


class LDAPAuthMethod(str, Enum):
    """Supported LDAP authentication mechanisms."""

    SIMPLE = "simple"
    ANONYMOUS = "anonymous"
    SASL_GSSAPI = "sasl_gssapi"
    SASL_DIGEST_MD5 = "sasl_digest_md5"
    SASL_EXTERNAL = "sasl_external"


@dataclass
class LDAPServerConfig:
    """Configuration for connecting to an LDAP directory."""

    name: str
    hostname: str
    port: int = 389
    use_ssl: bool = False
    bind_dn: Optional[str] = None
    bind_password: Optional[str] = None
    base_dn: Optional[str] = None
    auth_method: LDAPAuthMethod = LDAPAuthMethod.SIMPLE
    provider_type: str = "generic"

    @property
    def ldap_url(self) -> str:
        """Return ldap(s) URL for this configuration."""

        scheme = "ldaps" if self.use_ssl else "ldap"
        return f"{scheme}://{self.hostname}:{self.port}"

    def as_dict(self) -> Dict[str, Any]:
        """Serialize the configuration to a dict."""

        return {
            "name": self.name,
            "hostname": self.hostname,
            "port": self.port,
            "use_ssl": self.use_ssl,
            "bind_dn": self.bind_dn,
            "base_dn": self.base_dn,
            "auth_method": self.auth_method.value,
            "provider_type": self.provider_type,
        }

    def copy_with(self, **overrides: Any) -> LDAPServerConfig:
        """Return a copy of this configuration with overrides applied."""

        filtered = {k: v for k, v in overrides.items() if v is not None}
        if "auth_method" in filtered:
            filtered["auth_method"] = (
                filtered["auth_method"]
                if isinstance(filtered["auth_method"], LDAPAuthMethod)
                else LDAPAuthMethod(str(filtered["auth_method"]))
            )
        return replace(self, **filtered)

    @classmethod
    def from_env(cls, name: str = "default") -> LDAPServerConfig:
        """
        Create a server config from environment variables.

        Supported variables:
            LDAP_URL: Full ldap(s):// URL (overrides host/port/use_ssl)
            LDAP_HOSTNAME: Hostname or IP address
            LDAP_PORT: Port number
            LDAP_USE_SSL: true/false to enable LDAPS/StartTLS
            LDAP_BASE_DN: Directory base DN
            LDAP_BIND_DN: Bind DN
            LDAP_BIND_PASSWORD: Bind password
            LDAP_AUTH_METHOD: simple | sasl_gssapi | sasl_digest_md5 | sasl_external
            LDAP_PROVIDER: Optional provider hint (e.g., 389ds, openldap)
        """

        url = os.environ.get("LDAP_URL")
        hostname = os.environ.get("LDAP_HOSTNAME")
        use_ssl_env = os.environ.get("LDAP_USE_SSL")
        port_env = os.environ.get("LDAP_PORT")

        if url:
            parsed = urlparse(url)
            hostname = parsed.hostname or hostname or "localhost"
            use_ssl = parsed.scheme.lower() == "ldaps"
            port = parsed.port or (636 if use_ssl else 389)
        else:
            hostname = hostname or "localhost"
            use_ssl = str(use_ssl_env).lower() in {"1", "true", "yes", "on"}
            port = int(port_env) if port_env else (636 if use_ssl else 389)

        base_dn = os.environ.get("LDAP_BASE_DN", "dc=example,dc=com")
        auth_method = LDAPAuthMethod(
            os.environ.get("LDAP_AUTH_METHOD", LDAPAuthMethod.SIMPLE.value).lower()
        )

        # For anonymous auth, don't use default credentials
        if auth_method == LDAPAuthMethod.ANONYMOUS:
            bind_dn = None
            bind_password = None
        else:
            bind_dn = os.environ.get("LDAP_BIND_DN", "cn=Directory Manager")
            bind_password = os.environ.get("LDAP_BIND_PASSWORD", "Password123")
        provider_type = os.environ.get("LDAP_PROVIDER", "generic")

        return cls(
            name=name,
            hostname=hostname,
            port=port,
            use_ssl=use_ssl,
            bind_dn=bind_dn,
            bind_password=bind_password,
            base_dn=base_dn,
            auth_method=auth_method,
            provider_type=provider_type,
        )


class LDAPAssistantMCP(FastMCP):
    """Base FastMCP server with shared LDAP connection metadata."""

    def __init__(
        self,
        *,
        name: str,
        instructions: Optional[str] = None,
        servers: Optional[Iterable[LDAPServerConfig]] = None,
        default_server: Optional[LDAPServerConfig] = None,
        include_env_fallback: bool = True,
        **kwargs: Any,
    ) -> None:
        super().__init__(name=name, instructions=instructions, **kwargs)

        self.server_configs: Dict[str, LDAPServerConfig] = {}

        if servers:
            for config in servers:
                self.add_server(config)

        if default_server:
            self.add_server(default_server)
            self.default_server = default_server.name
        elif self.server_configs:
            self.default_server = next(iter(self.server_configs))
        elif include_env_fallback:
            env_config = LDAPServerConfig.from_env()
            self.add_server(env_config)
            self.default_server = env_config.name
        else:
            raise ValueError("At least one LDAP server configuration is required.")

    def add_server(self, config: LDAPServerConfig) -> None:
        """Register or update a server configuration."""

        self.server_configs[config.name] = config

    def set_default_server(self, server_name: str) -> None:
        """Set the default server by name."""

        if server_name not in self.server_configs:
            raise KeyError(f"Server '{server_name}' is not defined")
        self.default_server = server_name

    def get_server_config(self, server_name: Optional[str] = None) -> LDAPServerConfig:
        """Return the server configuration for the given name."""

        target = server_name or getattr(self, "default_server", None)
        if not target or target not in self.server_configs:
            raise KeyError(
                f"Server '{server_name or 'default'}' is not registered with this MCP instance"
            )
        return self.server_configs[target]

    def describe_servers(self) -> List[Dict[str, Any]]:
        """Return a list of server descriptions (safe for display)."""

        descriptions: List[Dict[str, Any]] = []
        for config in self.server_configs.values():
            descriptions.append(
                {
                    "name": config.name,
                    "hostname": config.hostname,
                    "port": config.port,
                    "use_ssl": config.use_ssl,
                    "base_dn": config.base_dn,
                    "auth_method": config.auth_method.value,
                    "provider_type": config.provider_type,
                    "is_default": config.name == getattr(self, "default_server", None),
                }
            )
        return descriptions

    def apply_cli_overrides(
        self,
        *,
        hostname: Optional[str] = None,
        port: Optional[int] = None,
        use_ssl: Optional[bool] = None,
        bind_dn: Optional[str] = None,
        bind_password: Optional[str] = None,
        base_dn: Optional[str] = None,
        auth_method: Optional[LDAPAuthMethod] = None,
        server_name: Optional[str] = None,
    ) -> LDAPServerConfig:
        """
        Apply overrides to an existing server config (typically from CLI arguments).

        Returns the updated configuration.
        """

        config = self.get_server_config(server_name)
        updated = config.copy_with(
            hostname=hostname,
            port=port,
            use_ssl=use_ssl,
            bind_dn=bind_dn,
            bind_password=bind_password,
            base_dn=base_dn,
            auth_method=auth_method,
        )
        self.add_server(updated)
        return updated

