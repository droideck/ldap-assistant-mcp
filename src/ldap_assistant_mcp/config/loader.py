"""Configuration loader for multi-server LDAP setups."""

import json
import os
import logging
from typing import List, Dict, Any, Optional
from dataclasses import dataclass, field
from urllib.parse import urlparse

from ldap_assistant_mcp.core import LDAPAuthMethod, LDAPServerConfig, MCPSettings

logger = logging.getLogger(__name__)

@dataclass
class ServerListConfig:
    """Configuration for multiple LDAP servers and MCP settings."""
    servers: List[LDAPServerConfig] = field(default_factory=list)
    settings: MCPSettings = field(default_factory=MCPSettings)

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
            # Only include tls_verify when it differs from the (safe) default
            if not s.tls_verify:
                server_dict["tls_verify"] = False
            # Only include local fields if configured
            if s.is_local:
                server_dict["is_local"] = s.is_local
                if s.serverid:
                    server_dict["serverid"] = s.serverid
                if s.use_ldapi:
                    server_dict["use_ldapi"] = s.use_ldapi
                if s.is_offline:
                    server_dict["is_offline"] = s.is_offline
            if s.is_archive:
                server_dict["is_archive"] = s.is_archive
                if s.archive_path:
                    server_dict["archive_path"] = s.archive_path
                if s.config_path:
                    server_dict["config_path"] = s.config_path
                if s.logs_path:
                    server_dict["logs_path"] = s.logs_path
                if s.instance_name:
                    server_dict["instance_name"] = s.instance_name
            server_list.append(server_dict)
        result = {"servers": server_list}
        if self.settings.expose_sensitive_data:
            result["settings"] = self.settings.to_dict()
        return result

    @classmethod
    def from_dict(cls, data: Dict[str, Any], base_dir: Optional[str] = None) -> "ServerListConfig":
        """Create from dictionary representation.

        Args:
            data: Dictionary with "servers" and optional "settings" keys.
            base_dir: Directory to resolve relative paths against (typically
                the directory containing the JSON config file).
        """
        servers = []
        for server_data in data.get("servers", []):
            servers.append(_server_config_from_dict(server_data, base_dir=base_dir))

        settings_data = data.get("settings", {})
        settings = _settings_from_dict(settings_data)

        return cls(servers=servers, settings=settings)

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

    Privacy note: The ``name`` field is never redacted in privacy mode — it is
    passed as-is to AI agents so they can reference servers across tool calls.
    Do not put hostnames, IPs, or other private information in server names.

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
    if config_file:
        return _load_from_file(config_file)

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

    config_dir = os.path.dirname(os.path.abspath(file_path))
    config = ServerListConfig.from_dict(data, base_dir=config_dir)
    logger.info(f"Loaded configuration for {len(config.servers)} servers")

    return config

def _server_config_from_dict(data: Dict[str, Any], base_dir: Optional[str] = None) -> LDAPServerConfig:
    """Convert a dictionary entry into an LDAPServerConfig.

    Args:
        data: Server configuration dictionary.
        base_dir: Directory to resolve relative paths against.
    """
    is_offline = _coerce_bool(data.get("is_offline", False))
    is_archive = _coerce_bool(data.get("is_archive", False))
    archive_path = _expand_path(data.get("archive_path"), base_dir)
    config_path_override = _expand_path(data.get("config_path"), base_dir)
    logs_path_override = _expand_path(data.get("logs_path"), base_dir)
    instance_name = data.get("instance_name")

    # Validate: mutually exclusive modes
    if is_offline and is_archive:
        raise ValueError(
            f"Server '{data.get('name', '?')}': is_offline and is_archive are mutually exclusive"
        )

    # Validate: archive requires path
    if is_archive and not (archive_path or config_path_override):
        raise ValueError(
            f"Server '{data.get('name', '?')}': archive mode requires archive_path or config_path"
        )

    # For archive mode, hostname/port/credentials are optional
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
        if is_offline or is_archive:
            hostname = "localhost" if is_offline else "archive"
        else:
            raise KeyError("Server definition must include either hostname or ldap_url")

    ssl_bool = _coerce_bool(use_ssl)
    if port is None:
        port = 0 if is_archive else (636 if ssl_bool else 389)

    try:
        port = int(port)
    except (TypeError, ValueError) as exc:
        raise ValueError(
            f"Server '{data.get('name', hostname)}': invalid port value {port!r} "
            f"(must be an integer)"
        ) from exc

    auth_value = data.get("auth_method", LDAPAuthMethod.SIMPLE.value)
    auth_method = (
        auth_value
        if isinstance(auth_value, LDAPAuthMethod)
        else LDAPAuthMethod(str(auth_value).lower())
    )

    # TLS certificate verification for remote ldaps:// connections.
    # JSON field wins; otherwise fall back to LDAP_TLS_VERIFY (default: on).
    if "tls_verify" in data:
        tls_verify = _coerce_bool(data["tls_verify"])
    else:
        tls_verify = (
            os.environ.get("LDAP_TLS_VERIFY", "").strip().lower()
            not in {"0", "false", "no", "off"}
        )

    # Local instance support
    is_local = _coerce_bool(data.get("is_local", False))
    serverid = data.get("serverid")
    use_ldapi = _coerce_bool(data.get("use_ldapi", False))

    # Offline mode implies is_local
    if is_offline:
        if not is_local:
            is_local = True
        if not serverid:
            raise ValueError(
                f"Server '{data.get('name', hostname)}': offline mode (is_offline=true) "
                f"requires serverid to be set."
            )

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
        port=port,
        use_ssl=ssl_bool,
        bind_dn=data.get("bind_dn"),
        bind_password=data.get("bind_password"),
        base_dn=data.get("base_dn"),
        auth_method=auth_method,
        provider_type=data.get("provider_type", "389ds"),
        tls_verify=tls_verify,
        is_local=is_local,
        serverid=serverid,
        use_ldapi=use_ldapi,
        is_offline=is_offline,
        is_archive=is_archive,
        archive_path=archive_path,
        config_path=config_path_override,
        logs_path=logs_path_override,
        instance_name=instance_name,
    )

def _expand_path(path: Optional[str], base_dir: Optional[str] = None) -> Optional[str]:
    """Expand ~ and resolve a config path to an absolute path.

    Relative paths are resolved against base_dir (the directory containing
    servers.json) so that paths like "sosreport.tar.xz" work regardless
    of what the process CWD happens to be.
    """
    if path is None:
        return None
    path = os.path.expanduser(path)
    if not os.path.isabs(path) and base_dir:
        path = os.path.join(base_dir, path)
    return os.path.abspath(path)


def _coerce_bool(value: Any) -> bool:
    if isinstance(value, bool):
        return value
    if isinstance(value, str):
        return value.strip().lower() in {"1", "true", "yes", "on"}
    return bool(value)


def _coerce_float_setting(key: str, value: Any) -> float:
    """Convert a settings value to float, raising a clear error on failure."""
    try:
        return float(value)
    except (TypeError, ValueError) as exc:
        raise ValueError(
            f"Invalid settings value {key}={value!r} (must be a number)"
        ) from exc

def _settings_from_dict(data: Dict[str, Any]) -> MCPSettings:
    """Create MCPSettings from dictionary, with environment variable fallback.

    Settings can come from:
    1. JSON config file "settings" section
    2. Environment variables (as fallback)

    JSON format:
    {
        "settings": {
            "expose_sensitive_data": true,
            "debug": true
        }
    }

    Environment variables:
        LDAP_MCP_EXPOSE_SENSITIVE_DATA: true/false
        LDAP_MCP_DEBUG: true/false
    """
    # Start with environment-based defaults
    env_settings = MCPSettings.from_env()

    # Override with config file values if present
    if "expose_sensitive_data" in data:
        expose = _coerce_bool(data["expose_sensitive_data"])
    else:
        expose = env_settings.expose_sensitive_data

    if "debug" in data:
        debug = _coerce_bool(data["debug"])
    else:
        debug = env_settings.debug

    if "tool_timeout" in data:
        tool_timeout = _coerce_float_setting("tool_timeout", data["tool_timeout"])
    else:
        tool_timeout = env_settings.tool_timeout

    if "max_tool_timeout" in data:
        max_tool_timeout = _coerce_float_setting("max_tool_timeout", data["max_tool_timeout"])
    else:
        max_tool_timeout = env_settings.max_tool_timeout

    return MCPSettings(
        expose_sensitive_data=expose,
        debug=debug,
        tool_timeout=tool_timeout,
        max_tool_timeout=max_tool_timeout,
    )
