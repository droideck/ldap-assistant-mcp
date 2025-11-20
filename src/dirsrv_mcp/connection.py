"""Connection management for 389 Directory Server."""

from __future__ import annotations

import logging
import os
from dataclasses import dataclass
from typing import Dict, List, Union

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
            server_config = ServerConfig(
                name=config.name,
                ldap_url=config.ldap_url,
                base_dn=config.base_dn or "dc=example,dc=com",
                bind_dn=config.bind_dn or "cn=Directory Manager",
                bind_password=config.bind_password or "",
                provider_type="389ds",
            )
        else:
            server_config = config

        self._configs[server_config.name] = server_config
        logger.info("Added DirSrv server '%s' (%s)", server_config.name, server_config.ldap_url)

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
        logger.info("Connecting to %s at %s", server_name, config.ldap_url)

        ds = DirSrv(verbose=False)
        ds.remote_simple_allocate(
            config.ldap_url,
            config.bind_dn,
            config.bind_password,
        )
        ds.open()
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
