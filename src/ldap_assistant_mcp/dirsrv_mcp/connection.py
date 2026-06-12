"""Connection management for 389 Directory Server."""

from __future__ import annotations

import logging
import os
from dataclasses import dataclass
from typing import Dict, List, Optional, Union

import ldap
from fastmcp.exceptions import ToolError
from lib389 import DirSrv

from ldap_assistant_mcp.core import LDAPServerConfig

__all__ = [
    "ServerConfig",
    "ConnectionManager",
    "get_connection_manager",
    "get_connection",
    "is_local_server",
    "require_local_server",
    "LocalServerRequired",
    "is_offline_server",
    "is_archive_server",
    "is_offline_or_archive",
    "require_live_server",
    "LiveServerRequired",
    "UnknownServer",
    "ConnectionFailed",
    "DEFAULT_CONNECT_TIMEOUT",
]


class LocalServerRequired(ToolError):
    """Raised when a local server is required but a remote connection is used."""

    def __init__(self, feature: str, server_name: str):
        self.feature = feature
        self.server_name = server_name
        super().__init__(
            f"'{feature}' requires a local server configuration. "
            f"Server '{server_name}' is configured as remote. "
            f"To enable local features, configure the server with is_local=True and serverid=<instance>."
        )


class UnknownServer(ToolError, KeyError):
    """Raised when a tool references a server name that is not configured.

    Subclasses ToolError so the message reaches MCP clients despite
    ``mask_error_details=True``, and KeyError for backward compatibility
    with callers that catch ``KeyError`` from ``get_config()``.
    """

    def __init__(self, server_name: str, available: Optional[List[str]] = None):
        self.server_name = server_name
        self.available = list(available or [])
        message = f"Server '{server_name}' is not configured."
        if self.available:
            message += " Available servers: " + ", ".join(sorted(self.available)) + "."
        message += " Use the list_servers tool to see configured servers."
        self._message = message
        super().__init__(message)

    def __str__(self) -> str:
        # KeyError.__str__ would repr() the message (adding quotes); return it plain.
        return self._message


class ConnectionFailed(ToolError, ConnectionError):
    """Raised when establishing an LDAP connection or bind fails.

    Subclasses ToolError so the guidance reaches MCP clients despite
    ``mask_error_details=True``, and the builtin ConnectionError for
    backward compatibility with callers that catch ``ConnectionError``.
    """

logger = logging.getLogger(__name__)


# Default network/operation timeout (seconds) for LDAP connections created by
# ``ConnectionManager.connect()``.  Without it, a hung or unreachable server
# blocks until the OS TCP timeout expires — and because FastMCP runs sync
# tools inline, TimeoutMiddleware cannot interrupt that wait.  Override with
# the LDAP_CONNECT_TIMEOUT environment variable (seconds).
DEFAULT_CONNECT_TIMEOUT = 30.0


def _get_connect_timeout() -> float:
    """Return the LDAP connect/operation timeout in seconds.

    Reads LDAP_CONNECT_TIMEOUT from the environment; falls back to
    DEFAULT_CONNECT_TIMEOUT for missing, non-numeric, or non-positive values.
    """
    raw = os.environ.get("LDAP_CONNECT_TIMEOUT")
    if raw:
        try:
            value = float(raw)
        except ValueError:
            logger.warning(
                "Invalid LDAP_CONNECT_TIMEOUT=%r, using default %.0fs",
                raw,
                DEFAULT_CONNECT_TIMEOUT,
            )
        else:
            if value > 0:
                return value
            logger.warning(
                "LDAP_CONNECT_TIMEOUT must be positive (got %r), using default %.0fs",
                raw,
                DEFAULT_CONNECT_TIMEOUT,
            )
    return DEFAULT_CONNECT_TIMEOUT


@dataclass
class ServerConfig:
    """Configuration for a single LDAP server.

    For local instances (is_local=True), the serverid is required and enables:
    - Access to server log files (access, error, audit logs)
    - File system checks (permissions, disk space for server paths)
    - DSE.ldif access for offline configuration inspection
    - LDAPI socket connections (if use_ldapi=True)

    LDAPI (Unix socket) connections:
    - Set is_local=True, serverid=<instance>, and use_ldapi=True
    - Uses SASL EXTERNAL authentication (no password needed)
    - Authenticates based on Unix socket peer credentials
    - Requires the process to run as root or the dirsrv user

    Remote instances only support LDAP protocol operations.
    """

    name: str
    ldap_url: str
    base_dn: str
    bind_dn: str
    bind_password: Optional[str] = None
    provider_type: str = "389ds"
    auth_method: str = "simple"
    # Verify the server certificate for remote ldaps:// connections (default
    # True → ldap.OPT_X_TLS_HARD).  Set False only for trusted lab setups with
    # self-signed certificates (uses ldap.OPT_X_TLS_NEVER).
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

    @classmethod
    def from_env(cls, name: str = "default") -> ServerConfig:
        """
        Create a ServerConfig from environment variables.

        This provides backward compatibility with the original LDAP Assistant MCP
        environment-based configuration.
        """

        # Fail safe: only an explicit false-y value disables TLS verification.
        tls_verify = (
            os.environ.get("LDAP_TLS_VERIFY", "").strip().lower()
            not in {"0", "false", "no", "off"}
        )

        return cls(
            name=name,
            ldap_url=os.environ.get("LDAP_URL", "ldap://localhost:389"),
            base_dn=os.environ.get("LDAP_BASE_DN", "dc=example,dc=com"),
            bind_dn=os.environ.get("LDAP_BIND_DN", "cn=directory manager"),
            bind_password=os.environ.get("LDAP_BIND_PASSWORD"),
            provider_type="389ds",
            tls_verify=tls_verify,
        )


class ConnectionManager:
    """
    Manage connections to multiple 389 Directory Server instances.

    Connections are established on demand and are not reused between calls because
    lib389 connection reuse across multiple operations is unreliable in this context.
    """

    def __init__(self) -> None:
        self._configs: Dict[str, ServerConfig] = {}
        self.debug: bool = False

    def add_server(self, config: Union[ServerConfig, LDAPServerConfig]) -> None:
        """Register a server configuration."""

        if isinstance(config, LDAPServerConfig):
            auth_method = config.auth_method.value

            # For anonymous auth, use empty credentials
            if auth_method == "anonymous":
                bind_dn = ""
                bind_password = ""
            else:
                bind_dn = config.bind_dn or "cn=Directory Manager"
                bind_password = config.bind_password or ""

            server_config = ServerConfig(
                name=config.name,
                ldap_url=config.ldap_url,
                base_dn=config.base_dn or "dc=example,dc=com",
                bind_dn=bind_dn,
                bind_password=bind_password,
                provider_type="389ds",
                auth_method=auth_method,
                tls_verify=config.tls_verify,
                is_local=config.is_local,
                serverid=config.serverid,
                use_ldapi=config.use_ldapi,
                is_offline=config.is_offline,
                is_archive=config.is_archive,
                archive_path=config.archive_path,
                config_path=config.config_path,
                logs_path=config.logs_path,
                instance_name=config.instance_name,
            )
        else:
            server_config = config

        self._configs[server_config.name] = server_config
        extra_info = ""
        if server_config.is_archive:
            extra_info = f", archive=True, path={server_config.archive_path or server_config.config_path}"
        elif server_config.is_local:
            ldapi_info = ", ldapi=True" if server_config.use_ldapi else ""
            offline_info = ", offline=True" if server_config.is_offline else ""
            extra_info = f", local=True, serverid={server_config.serverid}{ldapi_info}{offline_info}"
        logger.info(
            "Added DirSrv server '%s' (%s, auth=%s%s)",
            server_config.name,
            server_config.ldap_url,
            server_config.auth_method,
            extra_info,
        )

    def get_server_names(self) -> List[str]:
        """Return configured server names."""

        return list(self._configs.keys())

    def get_config(self, server_name: str) -> ServerConfig:
        """Return configuration for a server.

        Raises:
            UnknownServer: If no server with that name is registered.
                (UnknownServer subclasses both ToolError and KeyError.)
        """

        if server_name not in self._configs:
            raise UnknownServer(server_name, available=self.get_server_names())
        return self._configs[server_name]

    def connect(self, server_name: str) -> DirSrv:
        """Create and return a connection to the requested server.

        For local instances (is_local=True with serverid), uses local_simple_allocate()
        which enables access to server paths (logs, config files, etc.).

        For LDAPI connections (use_ldapi=True), uses SASL EXTERNAL authentication
        via Unix socket. No password is needed - auth is based on peer credentials.

        For remote instances, uses remote_simple_allocate() which only supports
        LDAP protocol operations.
        """

        config = self.get_config(server_name)

        # Archive mode: return ArchiveDirSrv stub
        if config.is_archive:
            return self._connect_archive(config)

        if (
            config.auth_method == "simple"
            and not config.is_offline
            and not config.use_ldapi
            and not config.bind_password
        ):
            raise ToolError(
                f"Server '{server_name}' uses simple auth but no bind password is configured. "
                "Set LDAP_BIND_PASSWORD or use a config file with bind_password."
            )

        local_info = ""
        if config.is_local:
            ldapi_info = ", ldapi=True" if config.use_ldapi else ""
            offline_info = ", offline=True" if config.is_offline else ""
            local_info = f", local=True, serverid={config.serverid}{ldapi_info}{offline_info}"

        if config.is_offline:
            logger.info(
                "Allocating offline DirSrv for %s (serverid=%s)",
                server_name,
                config.serverid,
            )
        else:
            logger.info(
                "Connecting to %s at %s (auth=%s%s)",
                server_name,
                config.ldap_url,
                config.auth_method,
                local_info,
            )

        ds = DirSrv(verbose=self.debug)

        if config.is_local and config.serverid:
            # Local instance: use local_simple_allocate for path access
            if not config.serverid:
                raise ValueError(
                    f"Local server '{server_name}' requires serverid to be set. "
                    "The serverid is the instance name (e.g., 'standalone')."
                )

            if config.use_ldapi:
                # LDAPI connection: no password needed, uses SASL EXTERNAL
                # Must provide explicit LDAPI URI - lib389 defaults to TCP if None
                ldapi_uri = f"ldapi://%2Fvar%2Frun%2Fslapd-{config.serverid}.socket"
                ds.local_simple_allocate(
                    serverid=config.serverid,
                    ldapuri=ldapi_uri,
                    binddn=config.bind_dn or "cn=Directory Manager",
                    password=None,  # No password for LDAPI
                )
                logger.debug(
                    "Using local_simple_allocate with LDAPI for %s (serverid=%s, uri=%s)",
                    server_name,
                    config.serverid,
                    ldapi_uri,
                )
            else:
                # Local with TCP connection (or offline allocation)
                ds.local_simple_allocate(
                    serverid=config.serverid,
                    ldapuri=config.ldap_url,
                    binddn=config.bind_dn if config.auth_method != "anonymous" else None,
                    password=config.bind_password if config.auth_method != "anonymous" else None,
                )
                logger.debug(
                    "Using local_simple_allocate for %s (serverid=%s)",
                    server_name,
                    config.serverid,
                )

            # Offline mode: return allocated DirSrv without opening LDAP connection
            if config.is_offline:
                logger.info(
                    "Offline mode: skipping open() for %s (paths available for offline analysis)",
                    server_name,
                )
                return ds
        elif config.auth_method == "anonymous":
            # Anonymous bind: use empty credentials
            ds.remote_simple_allocate(config.ldap_url, "", "")
            logger.debug("Using anonymous bind for %s", server_name)
        else:
            ds.remote_simple_allocate(
                config.ldap_url,
                config.bind_dn,
                config.bind_password,
            )

        # Bound how long connect/bind (and subsequent operations) may block.
        # FastMCP runs sync tools inline, so TimeoutMiddleware cannot rescue a
        # hung LDAP call — these process-wide defaults are inherited by the
        # connection that lib389 creates inside ds.open().
        connect_timeout = _get_connect_timeout()
        ldap.set_option(ldap.OPT_NETWORK_TIMEOUT, connect_timeout)
        ldap.set_option(ldap.OPT_TIMEOUT, connect_timeout)

        # Remote LDAPS: enforce certificate verification instead of silently
        # inheriting whatever policy /etc/openldap/ldap.conf has.  lib389's
        # open(reqcert=...) sets OPT_X_TLS_REQUIRE_CERT and then
        # OPT_X_TLS_NEWCTX=0 so the option takes effect.  Local instances keep
        # lib389's behavior (the instance's own NSS certificate directory).
        open_kwargs: Dict[str, int] = {}
        if not config.is_local and config.ldap_url.lower().startswith("ldaps://"):
            if config.tls_verify:
                open_kwargs["reqcert"] = ldap.OPT_X_TLS_HARD
            else:
                open_kwargs["reqcert"] = ldap.OPT_X_TLS_NEVER
                logger.warning(
                    "TLS certificate verification DISABLED for server '%s' "
                    "(tls_verify=false)",
                    server_name,
                )

        try:
            if config.use_ldapi and config.is_local:
                # LDAPI uses SASL EXTERNAL authentication
                ds.open(saslmethod='EXTERNAL')
                logger.debug("Opened LDAPI connection with SASL EXTERNAL for %s", server_name)
            else:
                ds.open(**open_kwargs)
        except ldap.SERVER_DOWN as exc:
            raise ConnectionFailed(
                f"Cannot connect to server '{server_name}': the server is "
                f"unreachable or did not respond within {connect_timeout:.0f}s "
                "(connection refused, host down, or wrong host/port). "
                "Check that the instance is running and the configured "
                "ldap_url is correct."
            ) from exc
        except ldap.INVALID_CREDENTIALS as exc:
            raise ConnectionFailed(
                f"Bind to server '{server_name}' failed: invalid credentials. "
                "Check the configured bind_dn and bind_password."
            ) from exc
        except ldap.INAPPROPRIATE_AUTH as exc:
            if config.auth_method == "anonymous":
                raise ConnectionFailed(
                    f"Anonymous access denied by server '{server_name}'. "
                    "The server may have anonymous access disabled "
                    "(nsslapd-allow-anonymous-access=off)."
                ) from exc
            raise
        except ldap.UNWILLING_TO_PERFORM as exc:
            if config.auth_method == "anonymous":
                raise ConnectionFailed(
                    f"Server '{server_name}' refused anonymous bind. "
                    "Anonymous access may be restricted to rootdse only "
                    "(nsslapd-allow-anonymous-access=rootdse)."
                ) from exc
            raise

        return ds

    def _connect_archive(self, config: ServerConfig):
        """Create an ArchiveDirSrv stub for archive analysis."""
        from ldap_assistant_mcp.dirsrv_mcp.archive.loader import detect_archive_layout
        from ldap_assistant_mcp.dirsrv_mcp.archive.stub import ArchiveDirSrv

        layout = detect_archive_layout(
            archive_path=config.archive_path,
            config_path=config.config_path,
            logs_path=config.logs_path,
            instance_name=config.instance_name,
        )
        logger.info(
            "Archive mode for '%s': type=%s, instance=%s, config=%s, logs=%s",
            config.name,
            layout.archive_type,
            layout.instance_name,
            layout.config_dir,
            layout.logs_dir,
        )
        stub = ArchiveDirSrv(layout)
        stub.verbose = self.debug
        return stub


_GLOBAL_MANAGER = ConnectionManager()


def get_connection_manager() -> ConnectionManager:
    """Return the global connection manager."""

    return _GLOBAL_MANAGER


def get_connection(server_name: str = "default") -> DirSrv:
    """
    Convenience helper for modules that need a DirSrv connection.

    Automatically provisions a default server config from environment variables
    if none has been registered yet.
    """

    manager = get_connection_manager()
    if server_name not in manager.get_server_names():
        manager.add_server(ServerConfig.from_env(name=server_name))
    return manager.connect(server_name)


def is_local_server(manager: ConnectionManager, server_name: str) -> bool:
    """Check if a server is configured as local.

    Local servers have access to:
    - Log files (access, error, audit)
    - File system checks
    - Process metrics (CPU, memory via psutil)
    - DSE.ldif for offline config
    - NSS certificate database

    Args:
        manager: The connection manager
        server_name: Name of the server to check

    Returns:
        True if the server is configured with is_local=True and has a serverid
    """
    try:
        config = manager.get_config(server_name)
        return config.is_local and config.serverid is not None
    except KeyError:
        return False


def require_local_server(
    manager: ConnectionManager,
    server_name: str,
    feature: str,
) -> None:
    """Raise LocalServerRequired if the server is not local.

    Use this at the start of tools that require local server access.

    Args:
        manager: The connection manager
        server_name: Name of the server to check
        feature: Description of the feature requiring local access

    Raises:
        LocalServerRequired: If the server is not configured as local
    """
    if not is_local_server(manager, server_name):
        raise LocalServerRequired(feature, server_name)


class LiveServerRequired(ToolError):
    """Raised when a live (running) server is required but an offline/archive connection is used."""

    def __init__(self, feature: str, server_name: str, mode: str = "offline"):
        self.feature = feature
        self.server_name = server_name
        if mode == "archive":
            detail = (
                f"Server '{server_name}' is an archive source (is_archive=True). "
                f"Archive mode only supports configuration analysis via dse.ldif, "
                f"log file parsing, and filesystem checks."
            )
        else:
            detail = (
                f"Server '{server_name}' is configured in offline mode (is_offline=True). "
                f"Offline mode only supports configuration analysis via dse.ldif, "
                f"log file parsing, and filesystem checks."
            )
        super().__init__(
            f"'{feature}' requires a running server with a live LDAP connection. {detail}"
        )


def is_offline_server(manager: ConnectionManager, server_name: str) -> bool:
    """Check if a server is configured in offline mode.

    Offline servers are locally installed instances that are analyzed
    without opening an LDAP connection. They support:
    - DSEldif (dse.ldif parsing)
    - DirsrvAccessLog / DirsrvErrorLog (log parsing)
    - FSChecks (file permission checks)

    They do NOT support:
    - LDAP searches (user/group queries)
    - cn=monitor (performance/connection stats)
    - Live replication status

    Args:
        manager: The connection manager
        server_name: Name of the server to check

    Returns:
        True if the server is configured with is_offline=True
    """
    try:
        config = manager.get_config(server_name)
        return config.is_offline
    except KeyError:
        return False


def is_archive_server(manager: ConnectionManager, server_name: str) -> bool:
    """Check if a server is configured in archive mode."""
    try:
        config = manager.get_config(server_name)
        return config.is_archive
    except KeyError:
        return False


def is_offline_or_archive(manager: ConnectionManager, server_name: str) -> bool:
    """Check if server is in offline or archive mode (no live LDAP connection)."""
    try:
        config = manager.get_config(server_name)
        return config.is_offline or config.is_archive
    except KeyError:
        return False


def require_live_server(
    manager: ConnectionManager,
    server_name: str,
    feature: str,
) -> None:
    """Raise LiveServerRequired if the server is offline or archive.

    Use this at the start of tools that require a live LDAP connection
    (e.g., user queries, monitoring, performance stats).

    Args:
        manager: The connection manager
        server_name: Name of the server to check
        feature: Description of the feature requiring a live connection

    Raises:
        LiveServerRequired: If the server is configured in offline or archive mode
        UnknownServer: If no server with that name is registered
    """
    config = manager.get_config(server_name)
    if config.is_archive:
        raise LiveServerRequired(feature, server_name, mode="archive")
    if config.is_offline:
        raise LiveServerRequired(feature, server_name, mode="offline")
