from __future__ import annotations

import logging
import os
import sys
from dataclasses import dataclass, replace
from enum import Enum
from importlib.metadata import PackageNotFoundError
from importlib.metadata import version as _dist_version
from typing import Any, Dict, Iterable, List, Optional
from urllib.parse import urlparse

from fastmcp import FastMCP

__all__ = [
    "LDAPAssistantMCP",
    "LDAPAuthMethod",
    "LDAPServerConfig",
    "MCPSettings",
    "__version__",
    "configure_package_logging",
]

try:
    __version__ = _dist_version("ldap-assistant-mcp")
except PackageNotFoundError:  # running from a source tree without an install
    __version__ = "0.0.0.dev0"

_PACKAGE_LOGGER = "ldap_assistant_mcp"


def _env_flag(name: str) -> bool:
    """Return True if the environment variable is set to a truthy value."""
    return str(os.environ.get(name, "")).lower() in {"1", "true", "yes", "on"}


def configure_package_logging(debug: Optional[bool] = None) -> None:
    """Attach a stderr handler to the ``ldap_assistant_mcp`` logger tree.

    Without this, no handler is ever configured and middleware INFO logs
    (and even LDAP_MCP_DEBUG output) go nowhere — Python's lastResort
    handler only emits WARNING and above.  stderr is safe for the stdio
    transport: only stdout carries MCP protocol data.

    Idempotent: repeated calls do not add duplicate handlers, they only
    adjust the level.  When *debug* is None, the LDAP_MCP_DEBUG
    environment variable decides.
    """
    if debug is None:
        debug = _env_flag("LDAP_MCP_DEBUG")

    pkg_logger = logging.getLogger(_PACKAGE_LOGGER)
    if not any(
        getattr(h, "_ldap_assistant_mcp_handler", False) for h in pkg_logger.handlers
    ):
        handler = logging.StreamHandler(stream=sys.stderr)
        handler.setFormatter(
            logging.Formatter("%(asctime)s %(levelname)s %(name)s %(message)s")
        )
        handler._ldap_assistant_mcp_handler = True  # type: ignore[attr-defined]
        pkg_logger.addHandler(handler)
    pkg_logger.setLevel(logging.DEBUG if debug else logging.INFO)


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
            - Hostnames and ports
            - Configuration values (bind DNs, paths, etc.)
            - Replication agreement targets
            - Suffixes and base DNs
            Note: Server names (the ``name`` field in servers.json) are never
            redacted — they are user-chosen labels that must remain stable
            across tool calls.  Do not put private information in server names.
            When True, full data is exposed (use only in trusted environments).

        debug: When True, enables verbose/debug output:
            - Logging level set to DEBUG for ``src.*`` loggers
            - Tool error responses include full tracebacks
            - DirSrv connections created with verbose=True

        # Future settings (commented placeholders):
        # allow_write_operations: Enable tools that modify directory data
        # allow_task_operations: Enable tools that run server tasks
    """

    expose_sensitive_data: bool = False
    debug: bool = False
    tool_timeout: float = 30.0
    max_tool_timeout: float = 120.0

    # Future: Allow write/modify operations (create users, modify config, etc.)
    # allow_write_operations: bool = False

    # Future: Allow task execution (reindex, backup, export, import, etc.)
    # allow_task_operations: bool = False

    @classmethod
    def from_env(cls) -> "MCPSettings":
        """Create settings from environment variables.

        Environment variables:
            LDAP_MCP_EXPOSE_SENSITIVE_DATA: true/false (default: false)
            LDAP_MCP_DEBUG: true/false (default: false)
            LDAP_MCP_TOOL_TIMEOUT: seconds (default: 30.0)
            LDAP_MCP_MAX_TOOL_TIMEOUT: seconds (default: 120.0)
        """
        expose_env = os.environ.get("LDAP_MCP_EXPOSE_SENSITIVE_DATA", "")
        expose_sensitive = str(expose_env).lower() in {"1", "true", "yes", "on"}

        debug_env = os.environ.get("LDAP_MCP_DEBUG", "")
        debug = str(debug_env).lower() in {"1", "true", "yes", "on"}

        try:
            tool_timeout = max(1.0, float(os.environ.get("LDAP_MCP_TOOL_TIMEOUT", "30.0")))
        except (ValueError, TypeError):
            tool_timeout = 30.0
        try:
            max_tool_timeout = max(1.0, float(os.environ.get("LDAP_MCP_MAX_TOOL_TIMEOUT", "120.0")))
        except (ValueError, TypeError):
            max_tool_timeout = 120.0

        return cls(
            expose_sensitive_data=expose_sensitive,
            debug=debug,
            tool_timeout=tool_timeout,
            max_tool_timeout=max_tool_timeout,
        )

    def to_dict(self) -> Dict[str, Any]:
        """Convert settings to dictionary."""
        return {
            "expose_sensitive_data": self.expose_sensitive_data,
            "debug": self.debug,
            "tool_timeout": self.tool_timeout,
            "max_tool_timeout": self.max_tool_timeout,
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

    Offline instance mode (is_offline=True):
    - Requires is_local=True and serverid
    - Uses local_simple_allocate() but skips ds.open() (no LDAP bind)
    - Allows offline analysis via DSEldif, DirsrvAccessLog, etc.
    - Tools requiring live LDAP will return clear error messages

    Archive mode (is_archive=True):
    - For SOS reports or manually extracted config/log files
    - Requires archive_path (directory or tarball) OR config_path
    - Does not require hostname, port, or credentials
    - Uses ArchiveDirSrv stub instead of real DirSrv
    - Mutually exclusive with is_offline
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
    # Verify the server certificate for remote ldaps:// connections (default
    # True).  Set False only for trusted lab setups with self-signed
    # certificates — it disables certificate verification entirely.
    tls_verify: bool = True
    # Local instance support
    is_local: bool = False
    serverid: Optional[str] = None
    # LDAPI socket connection (requires is_local=True and serverid)
    use_ldapi: bool = False
    # Offline instance mode (stopped local server, no LDAP connection)
    is_offline: bool = False
    # Archive mode (SOS report or extracted files)
    is_archive: bool = False
    archive_path: Optional[str] = None
    config_path: Optional[str] = None
    logs_path: Optional[str] = None
    instance_name: Optional[str] = None

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
        # Only include tls_verify when it differs from the (safe) default
        if not self.tls_verify:
            result["tls_verify"] = False
        # Only include local fields if configured
        if self.is_local:
            result["is_local"] = self.is_local
            if self.serverid:
                result["serverid"] = self.serverid
            if self.use_ldapi:
                result["use_ldapi"] = self.use_ldapi
            if self.is_offline:
                result["is_offline"] = self.is_offline
        if self.is_archive:
            result["is_archive"] = self.is_archive
            if self.archive_path:
                result["archive_path"] = self.archive_path
            if self.config_path:
                result["config_path"] = self.config_path
            if self.logs_path:
                result["logs_path"] = self.logs_path
            if self.instance_name:
                result["instance_name"] = self.instance_name
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
            LDAP_TLS_VERIFY: true/false - verify server certificate for remote
                LDAPS connections (default: true)
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
            bind_password = os.environ.get("LDAP_BIND_PASSWORD")
        provider_type = os.environ.get("LDAP_PROVIDER", "generic")

        # Local instance configuration
        is_local_env = os.environ.get("LDAP_IS_LOCAL", "")
        is_local = str(is_local_env).lower() in {"1", "true", "yes", "on"}
        serverid = os.environ.get("LDAP_SERVERID")
        use_ldapi_env = os.environ.get("LDAP_USE_LDAPI", "")
        use_ldapi = str(use_ldapi_env).lower() in {"1", "true", "yes", "on"}

        # Fail safe: only an explicit false-y value disables TLS verification.
        tls_verify = (
            os.environ.get("LDAP_TLS_VERIFY", "").strip().lower()
            not in {"0", "false", "no", "off"}
        )

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
            tls_verify=tls_verify,
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
        configure_package_logging()
        # Report the package version to MCP clients (serverInfo.version).
        kwargs.setdefault("version", __version__)
        super().__init__(
            name=name,
            instructions=instructions,
            mask_error_details=True,
            **kwargs,
        )

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
            if config.is_archive:
                desc["is_archive"] = True
                desc["mode"] = "archive"
                if config.archive_path:
                    desc["archive_path"] = config.archive_path
                if config.instance_name:
                    desc["instance_name"] = config.instance_name
            elif config.is_offline:
                desc["is_offline"] = True
                desc["mode"] = "offline"
            else:
                desc["mode"] = "live"
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

