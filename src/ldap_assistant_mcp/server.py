from __future__ import annotations

import os
from dataclasses import dataclass, field, replace
from enum import Enum
from typing import Any, Dict, Iterable, List, Optional
from urllib.parse import urlparse

from fastmcp import FastMCP

__all__ = ["LDAPAssistantMCP", "LDAPAuthMethod", "LDAPServerConfig", "MCPSettings"]


@dataclass
class MCPSettings:
    """Settings controlling MCP server behavior.

    Privacy and security settings that control what information is exposed
    through MCP tool outputs. By default, sensitive information is redacted
    to prevent accidental exposure to AI agents/LLMs.

    Attributes:
        expose_sensitive_data: When False (default), sensitive data is redacted
            from all tool outputs. This includes:
            - User/group DNs and names
            - Hostnames and server names
            - Configuration values (bind DNs, paths, etc.)
            - Replication agreement targets
            - Suffixes and base DNs
            When True, full data is exposed (use only in trusted environments).

        # Future settings (commented placeholders):
        # allow_write_operations: Enable tools that modify directory data
        # allow_task_operations: Enable tools that run server tasks
    """

    expose_sensitive_data: bool = False

    # Future: Allow write/modify operations (create users, modify config, etc.)
    # allow_write_operations: bool = False

    # Future: Allow task execution (reindex, backup, export, import, etc.)
    # allow_task_operations: bool = False

    @classmethod
    def from_env(cls) -> "MCPSettings":
        """Create settings from environment variables.

        Environment variables:
            LDAP_MCP_EXPOSE_SENSITIVE_DATA: true/false (default: false)
            # LDAP_MCP_ALLOW_WRITE_OPERATIONS: true/false (default: false)
            # LDAP_MCP_ALLOW_TASK_OPERATIONS: true/false (default: false)
        """
        expose_env = os.environ.get("LDAP_MCP_EXPOSE_SENSITIVE_DATA", "")
        expose_sensitive = str(expose_env).lower() in {"1", "true", "yes", "on"}

        return cls(
            expose_sensitive_data=expose_sensitive,
        )

    def to_dict(self) -> Dict[str, Any]:
        """Convert settings to dictionary."""
        return {
            "expose_sensitive_data": self.expose_sensitive_data,
            # "allow_write_operations": self.allow_write_operations,
            # "allow_task_operations": self.allow_task_operations,
        }


class LDAPAuthMethod(str, Enum):
    """Supported LDAP authentication mechanisms."""

    SIMPLE = "simple"
    ANONYMOUS = "anonymous"
    SASL_GSSAPI = "sasl_gssapi"
    SASL_DIGEST_MD5 = "sasl_digest_md5"
    SASL_EXTERNAL = "sasl_external"


@dataclass
class LDAPServerConfig:
    """Configuration for connecting to an LDAP directory.

    For local instances (is_local=True), the serverid is required and enables:
    - Access to server log files (access, error, audit logs)
    - File system checks (permissions, disk space for server paths)
    - DSE.ldif access for offline configuration inspection
    - LDAPI socket connections (if use_ldapi=True)

    Remote instances only support LDAP protocol operations.

    LDAPI (Unix socket) connections:
    - Set is_local=True, serverid=<instance>, and use_ldapi=True
    - Uses SASL EXTERNAL authentication (no password needed)
    - Authenticates based on Unix socket peer credentials
    - Requires the process to run as root or the dirsrv user
    """

    name: str
    hostname: str
    port: int = 389
    use_ssl: bool = False
    bind_dn: Optional[str] = None
    bind_password: Optional[str] = None
    base_dn: Optional[str] = None
    auth_method: LDAPAuthMethod = LDAPAuthMethod.SIMPLE
    provider_type: str = "generic"
    # Local instance support
    is_local: bool = False
    serverid: Optional[str] = None
    # LDAPI socket connection (requires is_local=True and serverid)
    use_ldapi: bool = False

    @property
    def ldap_url(self) -> str:
        """Return ldap(s) URL for this configuration."""

        scheme = "ldaps" if self.use_ssl else "ldap"
        return f"{scheme}://{self.hostname}:{self.port}"

    def as_dict(self) -> Dict[str, Any]:
        """Serialize the configuration to a dict."""

        result = {
            "name": self.name,
            "hostname": self.hostname,
            "port": self.port,
            "use_ssl": self.use_ssl,
            "bind_dn": self.bind_dn,
            "base_dn": self.base_dn,
            "auth_method": self.auth_method.value,
            "provider_type": self.provider_type,
        }
        # Only include local fields if configured
        if self.is_local:
            result["is_local"] = self.is_local
            if self.serverid:
                result["serverid"] = self.serverid
            if self.use_ldapi:
                result["use_ldapi"] = self.use_ldapi
        return result

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
            LDAP_IS_LOCAL: true/false - if true, enables local instance access
            LDAP_SERVERID: Instance name (e.g., 'standalone') - required if is_local=true
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

        # Local instance configuration
        is_local_env = os.environ.get("LDAP_IS_LOCAL", "")
        is_local = str(is_local_env).lower() in {"1", "true", "yes", "on"}
        serverid = os.environ.get("LDAP_SERVERID")
        use_ldapi_env = os.environ.get("LDAP_USE_LDAPI", "")
        use_ldapi = str(use_ldapi_env).lower() in {"1", "true", "yes", "on"}

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
            is_local=is_local,
            serverid=serverid,
            use_ldapi=use_ldapi,
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
            desc = {
                "name": config.name,
                "hostname": config.hostname,
                "port": config.port,
                "use_ssl": config.use_ssl,
                "base_dn": config.base_dn,
                "auth_method": config.auth_method.value,
                "provider_type": config.provider_type,
                "is_default": config.name == getattr(self, "default_server", None),
                "is_local": config.is_local,
            }
            if config.is_local and config.serverid:
                desc["serverid"] = config.serverid
                desc["use_ldapi"] = config.use_ldapi
            descriptions.append(desc)
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

