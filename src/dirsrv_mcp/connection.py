"""Connection management for 389 Directory Server."""

from __future__ import annotations

import logging
import os
from dataclasses import dataclass
from typing import Dict, List, Optional, Union

import ldap
from lib389 import DirSrv

from src.ldap_assistant_mcp.server import LDAPServerConfig

__all__ = [
    "ServerConfig",
    "ConnectionManager",
    "get_connection_manager",
    "get_connection",
]

logger = logging.getLogger(__name__)


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
    bind_password: str
    provider_type: str = "389ds"
    auth_method: str = "simple"
    # Local instance support
    is_local: bool = False
    serverid: Optional[str] = None
    # LDAPI socket connection (requires is_local=True and serverid)
    use_ldapi: bool = False

    @classmethod
    def from_env(cls, name: str = "default") -> ServerConfig:
        """
        Create a ServerConfig from environment variables.

        This provides backward compatibility with the original LDAP Assistant MCP
        environment-based configuration.
        """

        return cls(
            name=name,
            ldap_url=os.environ.get("LDAP_URL", "ldap://localhost:389"),
            base_dn=os.environ.get("LDAP_BASE_DN", "dc=example,dc=com"),
            bind_dn=os.environ.get("LDAP_BIND_DN", "cn=directory manager"),
            bind_password=os.environ.get("LDAP_BIND_PASSWORD", "Password123"),
            provider_type="389ds",
        )


class ConnectionManager:
    """
    Manage connections to multiple 389 Directory Server instances.

    Connections are established on demand and are not reused between calls because
    lib389 connection reuse across multiple operations is unreliable in this context.
    """

    def __init__(self) -> None:
        self._configs: Dict[str, ServerConfig] = {}

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
                is_local=config.is_local,
                serverid=config.serverid,
                use_ldapi=config.use_ldapi,
            )
        else:
            server_config = config

        self._configs[server_config.name] = server_config
        local_info = ""
        if server_config.is_local:
            ldapi_info = ", ldapi=True" if server_config.use_ldapi else ""
            local_info = f", local=True, serverid={server_config.serverid}{ldapi_info}"
        logger.info(
            "Added DirSrv server '%s' (%s, auth=%s%s)",
            server_config.name,
            server_config.ldap_url,
            server_config.auth_method,
            local_info,
        )

    def get_server_names(self) -> List[str]:
        """Return configured server names."""

        return list(self._configs.keys())

    def get_config(self, server_name: str) -> ServerConfig:
        """Return configuration for a server."""

        if server_name not in self._configs:
            raise KeyError(f"Server '{server_name}' is not configured")
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
        local_info = ""
        if config.is_local:
            ldapi_info = ", ldapi=True" if config.use_ldapi else ""
            local_info = f", local=True, serverid={config.serverid}{ldapi_info}"
        logger.info(
            "Connecting to %s at %s (auth=%s%s)",
            server_name,
            config.ldap_url,
            config.auth_method,
            local_info,
        )

        ds = DirSrv(verbose=False)

        if config.is_local and config.serverid:
            # Local instance: use local_simple_allocate for path access
            if not config.serverid:
                raise ValueError(
                    f"Local server '{server_name}' requires serverid to be set. "
                    "The serverid is the instance name (e.g., 'standalone')."
                )

            if config.use_ldapi:
                # LDAPI connection: no password needed, uses SASL EXTERNAL
                ds.local_simple_allocate(
                    serverid=config.serverid,
                    ldapuri=None,  # Will use LDAPI socket
                    binddn=config.bind_dn or "cn=Directory Manager",
                    password=None,  # No password for LDAPI
                )
                logger.debug(
                    "Using local_simple_allocate with LDAPI for %s (serverid=%s)",
                    server_name,
                    config.serverid,
                )
            else:
                # Local with TCP connection
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

        try:
            if config.use_ldapi and config.is_local:
                # LDAPI uses SASL EXTERNAL authentication
                ds.open(saslmethod='EXTERNAL')
                logger.debug("Opened LDAPI connection with SASL EXTERNAL for %s", server_name)
            else:
                ds.open()
        except ldap.INAPPROPRIATE_AUTH as exc:
            if config.auth_method == "anonymous":
                raise ConnectionError(
                    f"Anonymous access denied by server '{server_name}'. "
                    "The server may have anonymous access disabled "
                    "(nsslapd-allow-anonymous-access=off)."
                ) from exc
            raise
        except ldap.UNWILLING_TO_PERFORM as exc:
            if config.auth_method == "anonymous":
                raise ConnectionError(
                    f"Server '{server_name}' refused anonymous bind. "
                    "Anonymous access may be restricted to rootdse only "
                    "(nsslapd-allow-anonymous-access=rootdse)."
                ) from exc
            raise

        return ds


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
