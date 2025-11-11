"""Configuration loader for multi-server LDAP setups."""

import json
import os
import logging
from typing import List, Dict, Any, Optional
from dataclasses import dataclass, field
from src.providers.dirsrv_mcp.connection import ServerConfig, ConnectionManager

logger = logging.getLogger(__name__)


@dataclass
class ServerListConfig:
    """Configuration for multiple LDAP servers."""
    servers: List[ServerConfig] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary representation."""
        return {
            "servers": [
                {
                    "name": s.name,
                    "ldap_url": s.ldap_url,
                    "base_dn": s.base_dn,
                    "bind_dn": s.bind_dn,
                    "bind_password": s.bind_password,
                    "provider_type": s.provider_type
                }
                for s in self.servers
            ]
        }

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "ServerListConfig":
        """Create from dictionary representation."""
        servers = []
        for server_data in data.get("servers", []):
            servers.append(ServerConfig(
                name=server_data["name"],
                ldap_url=server_data["ldap_url"],
                base_dn=server_data["base_dn"],
                bind_dn=server_data["bind_dn"],
                bind_password=server_data["bind_password"],
                provider_type=server_data.get("provider_type", "389ds")
            ))
        return cls(servers=servers)


def load_config(
    config_file: Optional[str] = None,
    config_env_var: str = "LDAP_SERVERS_CONFIG"
) -> ServerListConfig:
    """
    Load server configuration from JSON file or environment variable.

    The configuration can come from three sources (in order of precedence):
    1. Explicit config_file path
    2. Path specified in environment variable (default: LDAP_SERVERS_CONFIG)
    3. Default single-server config from environment variables (backward compatibility)

    JSON format:
    {
        "servers": [
            {
                "name": "prod-ds1",
                "ldap_url": "ldap://ds1.example.com:389",
                "base_dn": "dc=example,dc=com",
                "bind_dn": "cn=Directory Manager",
                "bind_password": "secret",
                "provider_type": "389ds"
            },
            ...
        ]
    }

    Args:
        config_file: Optional path to JSON config file
        config_env_var: Name of environment variable containing config file path

    Returns:
        ServerListConfig with loaded servers

    Examples:
        >>> # Load from explicit file
        >>> config = load_config("/etc/ldap-assistant/servers.json")
        >>>
        >>> # Load from environment variable
        >>> os.environ['LDAP_SERVERS_CONFIG'] = '/etc/servers.json'
        >>> config = load_config()
        >>>
        >>> # Fallback to legacy single-server env vars
        >>> os.environ['LDAP_URL'] = 'ldap://localhost:389'
        >>> config = load_config()  # Creates single "default" server
    """
    # Try explicit file path
    if config_file:
        return _load_from_file(config_file)

    # Try environment variable pointing to file
    env_config_path = os.environ.get(config_env_var)
    if env_config_path:
        return _load_from_file(env_config_path)

    # Fallback to legacy single-server environment variables
    logger.info("No multi-server config found, using legacy environment variables for single server")
    default_server = ServerConfig.from_env(name="default")
    return ServerListConfig(servers=[default_server])


def _load_from_file(file_path: str) -> ServerListConfig:
    """
    Load configuration from JSON file.

    Args:
        file_path: Path to JSON config file

    Returns:
        ServerListConfig loaded from file

    Raises:
        FileNotFoundError: If file doesn't exist
        json.JSONDecodeError: If file is not valid JSON
        KeyError: If required fields are missing
    """
    logger.info(f"Loading server configuration from {file_path}")

    if not os.path.exists(file_path):
        raise FileNotFoundError(f"Config file not found: {file_path}")

    with open(file_path, 'r') as f:
        data = json.load(f)

    config = ServerListConfig.from_dict(data)
    logger.info(f"Loaded configuration for {len(config.servers)} servers")

    return config


def initialize_connection_manager(
    config: ServerListConfig,
    manager: Optional[ConnectionManager] = None
) -> ConnectionManager:
    """
    Initialize a connection manager with servers from config.

    Args:
        config: ServerListConfig with server definitions
        manager: Optional existing ConnectionManager (creates new if None)

    Returns:
        ConnectionManager initialized with all servers from config
    """
    if manager is None:
        from src.providers.dirsrv_mcp.connection import get_connection_manager
        manager = get_connection_manager()

    for server_config in config.servers:
        manager.add_server(server_config)
        logger.info(f"Registered server: {server_config.name}")

    return manager


def save_config(config: ServerListConfig, file_path: str) -> None:
    """
    Save configuration to JSON file.

    Args:
        config: ServerListConfig to save
        file_path: Path to write JSON file

    Note:
        Passwords are saved in plain text. Ensure file permissions are restrictive.
    """
    logger.warning(f"Saving configuration to {file_path} (passwords in plain text)")

    with open(file_path, 'w') as f:
        json.dump(config.to_dict(), f, indent=2)

    # Set restrictive permissions (owner read/write only)
    os.chmod(file_path, 0o600)
    logger.info(f"Configuration saved to {file_path} with mode 0600")
