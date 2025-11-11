"""Connection management for 389 Directory Server."""

import os
import logging
from typing import Dict, Optional, List
from dataclasses import dataclass
from lib389 import DirSrv

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
    def from_env(cls, name: str = "default") -> "ServerConfig":
        """
        Create a ServerConfig from environment variables.

        This provides backward compatibility with the original DirKeeper
        environment-based configuration.

        Args:
            name: Name identifier for this server

        Returns:
            ServerConfig instance populated from environment variables
        """
        return cls(
            name=name,
            ldap_url=os.environ.get('LDAP_URL', 'ldap://localhost:389'),
            base_dn=os.environ.get('LDAP_BASE_DN', 'dc=example,dc=com'),
            bind_dn=os.environ.get('LDAP_BIND_DN', 'cn=directory manager'),
            bind_password=os.environ.get('LDAP_BIND_PASSWORD', 'Password123'),
            provider_type="389ds"
        )


class ConnectionManager:
    """
    Manages connections to multiple 389 Directory Server instances.

    This class maintains persistent connections to multiple LDAP servers
    for efficient multi-server operations. Connections are established
    on first use and reused for subsequent operations.
    """

    def __init__(self):
        """Initialize the connection manager."""
        self._connections: Dict[str, DirSrv] = {}
        self._configs: Dict[str, ServerConfig] = {}

    def add_server(self, config: ServerConfig) -> None:
        """
        Add a server configuration.

        Args:
            config: ServerConfig instance for the server
        """
        self._configs[config.name] = config
        logger.info(f"Added server configuration: {config.name} ({config.ldap_url})")

    def connect(self, server_name: str) -> DirSrv:
        """
        Get or create a connection to a specific server.

        Args:
            server_name: Name of the server to connect to

        Returns:
            DirSrv instance connected to the server

        Raises:
            KeyError: If server_name is not configured
            Exception: If connection fails
        """
        # Return existing connection if available
        if server_name in self._connections:
            return self._connections[server_name]

        # Get server config
        if server_name not in self._configs:
            raise KeyError(f"Server '{server_name}' not configured")

        config = self._configs[server_name]

        # Create new connection
        logger.info(f"Connecting to {config.name} at {config.ldap_url}")
        ds = DirSrv(verbose=False)

        try:
            ds.remote_simple_allocate(
                config.ldap_url,
                config.bind_dn,
                config.bind_password
            )
            ds.open()
            logger.info(f"Successfully connected to {config.name}")

            # Store connection
            self._connections[server_name] = ds
            return ds

        except Exception as e:
            logger.error(f"Failed to connect to {config.name}: {str(e)}")
            raise

    def disconnect(self, server_name: str) -> None:
        """
        Disconnect from a specific server.

        Args:
            server_name: Name of the server to disconnect from
        """
        if server_name in self._connections:
            try:
                self._connections[server_name].unbind_s()
                logger.info(f"Disconnected from {server_name}")
            except Exception as e:
                logger.warning(f"Error disconnecting from {server_name}: {str(e)}")
            finally:
                del self._connections[server_name]

    def disconnect_all(self) -> None:
        """Disconnect from all servers."""
        for server_name in list(self._connections.keys()):
            self.disconnect(server_name)

    def get_server_names(self) -> List[str]:
        """
        Get list of configured server names.

        Returns:
            List of server names
        """
        return list(self._configs.keys())

    def get_config(self, server_name: str) -> ServerConfig:
        """
        Get configuration for a specific server.

        Args:
            server_name: Name of the server

        Returns:
            ServerConfig for the server

        Raises:
            KeyError: If server is not configured
        """
        return self._configs[server_name]


# Global connection manager instance
_connection_manager = ConnectionManager()


def get_connection_manager() -> ConnectionManager:
    """
    Get the global connection manager instance.

    Returns:
        The global ConnectionManager
    """
    return _connection_manager


def get_connection(server_name: str = "default") -> DirSrv:
    """
    Get a connection to a server (convenience function).

    This function provides a simple interface for tools to get connections.
    For backward compatibility with single-server mode, it defaults to
    a server named "default" which can be configured from environment variables.

    Args:
        server_name: Name of the server to connect to

    Returns:
        DirSrv instance connected to the server
    """
    manager = get_connection_manager()

    # Auto-configure "default" server from environment if not already configured
    if server_name == "default" and server_name not in manager.get_server_names():
        config = ServerConfig.from_env()
        manager.add_server(config)

    return manager.connect(server_name)
