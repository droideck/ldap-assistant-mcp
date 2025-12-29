"""Configuration loader for multi-server LDAP setups."""

import json
import os
import logging
from typing import List, Dict, Any, Optional
from dataclasses import dataclass, field
from urllib.parse import urlparse

from src.dirsrv_mcp.connection import ConnectionManager, get_connection_manager
from src.ldap_assistant_mcp.server import LDAPAuthMethod, LDAPServerConfig

logger = logging.getLogger(__name__)


@dataclass
class ServerListConfig:
    """Configuration for multiple LDAP servers."""
    servers: List[LDAPServerConfig] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary representation."""
        server_list = []
        for s in self.servers:
            server_dict = {
                "name": s.name,
                "hostname": s.hostname,
                "port": s.port,
                "use_ssl": s.use_ssl,
                "bind_dn": s.bind_dn,
                "bind_password": s.bind_password,
                "base_dn": s.base_dn,
                "auth_method": s.auth_method.value,
                "provider_type": s.provider_type,
            }
            # Only include local fields if configured
            if s.is_local:
                server_dict["is_local"] = s.is_local
                if s.serverid:
                    server_dict["serverid"] = s.serverid
                if s.use_ldapi:
                    server_dict["use_ldapi"] = s.use_ldapi
            server_list.append(server_dict)
        return {"servers": server_list}

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "ServerListConfig":
        """Create from dictionary representation."""
        servers = []
        for server_data in data.get("servers", []):
            servers.append(_server_config_from_dict(server_data))
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
                "provider_type": "389ds",
                "is_local": false
            },
            {
                "name": "local-ds1",
                "ldap_url": "ldap://localhost:389",
                "base_dn": "dc=example,dc=com",
                "bind_dn": "cn=Directory Manager",
                "bind_password": "secret",
                "provider_type": "389ds",
                "is_local": true,
                "serverid": "standalone"
            },
            ...
        ]
    }

    Note: For local instances (is_local=true), the serverid field is required.
    This enables access to server log files, config files, and other local resources.

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
    logger.info(
        "No multi-server config found, using legacy environment variables for single server"
    )
    default_server = LDAPServerConfig.from_env(name="default")
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
        manager = get_connection_manager()

    for server_config in config.servers:
        manager.add_server(server_config)
        logger.info("Registered server: %s", server_config.name)

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
    logger.warning("Saving configuration to %s (passwords in plain text)", file_path)

    with open(file_path, 'w') as f:
        json.dump(config.to_dict(), f, indent=2)

    # Set restrictive permissions (owner read/write only)
    os.chmod(file_path, 0o600)
    logger.info("Configuration saved to %s with mode 0600", file_path)


def _server_config_from_dict(data: Dict[str, Any]) -> LDAPServerConfig:
    """Convert a dictionary entry into an LDAPServerConfig."""
    hostname = data.get("hostname")
    port = data.get("port")
    use_ssl = data.get("use_ssl")

    if not hostname and data.get("ldap_url"):
        parsed = urlparse(data["ldap_url"])
        hostname = parsed.hostname or "localhost"
        inferred_ssl = parsed.scheme.lower() == "ldaps"
        use_ssl = inferred_ssl if use_ssl is None else use_ssl
        if port is None:
            port = parsed.port or (636 if inferred_ssl else 389)

    if hostname is None:
        raise KeyError("Server definition must include either hostname or ldap_url")

    ssl_bool = _coerce_bool(use_ssl)
    if port is None:
        port = 636 if ssl_bool else 389

    auth_value = data.get("auth_method", LDAPAuthMethod.SIMPLE.value)
    auth_method = (
        auth_value
        if isinstance(auth_value, LDAPAuthMethod)
        else LDAPAuthMethod(str(auth_value).lower())
    )

    # Local instance support
    is_local = _coerce_bool(data.get("is_local", False))
    serverid = data.get("serverid")
    use_ldapi = _coerce_bool(data.get("use_ldapi", False))

    # Validate: if is_local is True, serverid should be provided
    if is_local and not serverid:
        logger.warning(
            "Server '%s' has is_local=true but no serverid. "
            "Local features (log access, filesystem checks) will not work.",
            data.get("name", hostname),
        )

    # Validate: if use_ldapi is True, is_local and serverid are required
    if use_ldapi and (not is_local or not serverid):
        logger.warning(
            "Server '%s' has use_ldapi=true but is_local or serverid is not set. "
            "LDAPI requires is_local=true and serverid to be configured.",
            data.get("name", hostname),
        )

    return LDAPServerConfig(
        name=data.get("name", hostname),
        hostname=hostname,
        port=int(port),
        use_ssl=ssl_bool,
        bind_dn=data.get("bind_dn"),
        bind_password=data.get("bind_password"),
        base_dn=data.get("base_dn"),
        auth_method=auth_method,
        provider_type=data.get("provider_type", "389ds"),
        is_local=is_local,
        serverid=serverid,
        use_ldapi=use_ldapi,
    )


def _coerce_bool(value: Any) -> bool:
    if isinstance(value, bool):
        return value
    if isinstance(value, str):
        return value.strip().lower() in {"1", "true", "yes", "on"}
    return bool(value)
