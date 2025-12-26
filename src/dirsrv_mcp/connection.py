"""Connection management for 389 Directory Server."""

from __future__ import annotations

import logging
import os
from dataclasses import dataclass
from typing import Dict, List, Union

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
    """Configuration for a single LDAP server."""

    name: str
    ldap_url: str
    base_dn: str
    bind_dn: str
    bind_password: str
    provider_type: str = "389ds"
    auth_method: str = "simple"

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
            )
        else:
            server_config = config

        self._configs[server_config.name] = server_config
        logger.info(
            "Added DirSrv server '%s' (%s, auth=%s)",
            server_config.name,
            server_config.ldap_url,
            server_config.auth_method,
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
        """Create and return a connection to the requested server."""

        config = self.get_config(server_name)
        logger.info(
            "Connecting to %s at %s (auth=%s)",
            server_name,
            config.ldap_url,
            config.auth_method,
        )

        ds = DirSrv(verbose=False)

        if config.auth_method == "anonymous":
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
