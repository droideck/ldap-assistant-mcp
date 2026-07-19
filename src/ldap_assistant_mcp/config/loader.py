"""Configuration loader for multi-server LDAP setups."""

import json
import os
import logging
from typing import List, Dict, Any, Optional
from dataclasses import dataclass, field
from urllib.parse import urlparse

from ldap_assistant_mcp.core import (
    LDAPAuthMethod,
    LDAPServerConfig,
    MCPSettings,
    env_strict_bool,
    parse_strict_bool,
    resolve_bind_password,
)

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
                # Never serialize the secret itself — only whether
                # one is configured.  Indirection sources (env var name /
                # file path) are kept so a dump can be re-loaded.
                "bind_password_set": bool(
                    s.bind_password or s.bind_password_env or s.bind_password_file
                ),
                "base_dn": s.base_dn,
                "auth_method": s.auth_method.value,
                "provider_type": s.provider_type,
            }
            if s.bind_password_env:
                server_dict["bind_password_env"] = s.bind_password_env
            if s.bind_password_file:
                server_dict["bind_password_file"] = s.bind_password_file
            # Only include tls_verify when it differs from the (safe) default
            if not s.tls_verify:
                server_dict["tls_verify"] = False
            if s.allow_insecure_plaintext:
                server_dict["allow_insecure_plaintext"] = True
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
        servers: List[LDAPServerConfig] = []
        seen_names: Dict[str, int] = {}
        for index, server_data in enumerate(data.get("servers", [])):
            server = _server_config_from_dict(server_data, base_dir=base_dir)
            if server.name in seen_names:
                raise ValueError(
                    f"Duplicate server name '{server.name}' in configuration "
                    f"(entries #{seen_names[server.name] + 1} and #{index + 1}). "
                    "Server names must be unique."
                )
            seen_names[server.name] = index
            servers.append(server)

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

    Secrets: instead of an inline "bind_password" you can set
    "bind_password_env" (name of an environment variable holding the
    password) or "bind_password_file" (path to a chmod-600, owner-owned
    regular file whose stripped content is the password; relative paths
    resolve against the config file's directory). At most one of the three
    may be set per server. A config file that carries an inline
    "bind_password" must itself be a regular file with mode 600
    (not a symlink, not group/other-readable).

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
        ValueError: If the file defines no servers (an explicitly requested
            config must not silently fall back to a default localhost
            server), contains invalid/duplicate/unknown fields, or contains
            an inline "bind_password" while being a symlink or
            group/other-readable
    """
    logger.info(f"Loading server configuration from {file_path}")

    if not os.path.exists(file_path):
        raise FileNotFoundError(f"Config file not found: {file_path}")

    with open(file_path, 'r') as f:
        data = json.load(f)

    _check_config_file_permissions(file_path, data)

    config_dir = os.path.dirname(os.path.abspath(file_path))
    config = ServerListConfig.from_dict(data, base_dir=config_dir)
    if not config.servers:
        raise ValueError(
            f"Config file {file_path} defines no servers. Add at least one "
            'entry to the "servers" list. (An explicitly requested config '
            "file must not silently fall back to a default localhost server.)"
        )
    logger.info(f"Loaded configuration for {len(config.servers)} servers")

    return config

def _check_config_file_permissions(file_path: str, data: Any) -> None:
    """Refuse world-readable / symlinked config files with inline secrets.

    A servers.json that carries an inline ``bind_password`` must be a
    regular file readable only by its owner.  Config files that
    keep secrets out-of-band (``bind_password_env`` / ``bind_password_file``
    or no password at all) are exempt; for those, a symlinked config only
    logs a warning.
    """
    servers_raw = data.get("servers", []) if isinstance(data, dict) else []
    has_inline_password = any(
        isinstance(entry, dict) and entry.get("bind_password")
        for entry in servers_raw
    )
    is_symlink = os.path.islink(file_path)

    if not has_inline_password:
        if is_symlink:
            logger.warning(
                "Config file %s is a symlink. It contains no inline "
                "bind_password, so it will be loaded — but prefer pointing "
                "LDAP_SERVERS_CONFIG at the real file.",
                file_path,
            )
        return

    if is_symlink:
        raise ValueError(
            f"Config file {file_path} is a symlink and contains an inline "
            '"bind_password". Refusing to load secrets through symlinks — '
            "replace the symlink with the real file, or move the secret to "
            "bind_password_file / bind_password_env."
        )
    st = os.stat(file_path)
    if st.st_mode & 0o077:
        raise ValueError(
            f"Config file {file_path} contains an inline \"bind_password\" "
            f"but is group/other-readable (mode {oct(st.st_mode & 0o777)}). "
            f"Fix with: chmod 600 {file_path} — or move the secret to "
            "bind_password_file / bind_password_env."
        )


# Every key accepted in a server entry of servers.json.  Unknown keys are
# rejected so a typo ("tls_verfy", "use_sssl") fails startup instead of
# being silently ignored.
_KNOWN_SERVER_KEYS = frozenset(
    {
        "name",
        "hostname",
        "port",
        "use_ssl",
        "ldap_url",
        "bind_dn",
        "bind_password",
        "bind_password_env",
        "bind_password_file",
        # Output-only marker emitted by to_dict(); accepted and ignored on
        # load so a dumped config can be re-loaded.
        "bind_password_set",
        "base_dn",
        "auth_method",
        "provider_type",
        "tls_verify",
        "allow_insecure_plaintext",
        "is_local",
        "serverid",
        "use_ldapi",
        "is_offline",
        "is_archive",
        "archive_path",
        "config_path",
        "logs_path",
        "instance_name",
    }
)

# URL schemes accepted in ldap_url / LDAP_URL.
_SUPPORTED_URL_SCHEMES = ("ldap", "ldaps", "ldapi")


def _server_config_from_dict(data: Dict[str, Any], base_dir: Optional[str] = None) -> LDAPServerConfig:
    """Convert a dictionary entry into an LDAPServerConfig.

    Args:
        data: Server configuration dictionary.
        base_dir: Directory to resolve relative paths against.

    Raises:
        ValueError: On unknown keys, invalid boolean values, unsupported
            ldap_url schemes, or ldap_url/use_ssl conflicts.
        KeyError: If neither hostname nor ldap_url is provided (non-archive).
    """
    unknown_keys = set(data) - _KNOWN_SERVER_KEYS
    if unknown_keys:
        raise ValueError(
            f"Server '{data.get('name', '?')}': unknown configuration key(s): "
            + ", ".join(sorted(repr(k) for k in unknown_keys))
            + ". Valid keys: "
            + ", ".join(sorted(_KNOWN_SERVER_KEYS))
            + "."
        )

    is_offline = _coerce_bool(data.get("is_offline", False), field="is_offline")
    is_archive = _coerce_bool(data.get("is_archive", False), field="is_archive")
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
    if use_ssl is not None:
        use_ssl = _coerce_bool(use_ssl, field="use_ssl")

    server_label = data.get("name", hostname or data.get("ldap_url", "?"))

    # The URL is authoritative for the transport: unknown
    # schemes and use_ssl/hostname/port values that contradict the URL are
    # configuration errors, never silently reconciled into plaintext.
    url_value = data.get("ldap_url")
    if url_value:
        parsed = urlparse(str(url_value))
        scheme = (parsed.scheme or "").lower()
        if scheme not in _SUPPORTED_URL_SCHEMES:
            raise ValueError(
                f"Server '{server_label}': unsupported scheme {parsed.scheme!r} "
                f"in ldap_url {url_value!r}. Supported schemes: ldap://, "
                "ldaps://, ldapi:// (StartTLS is not yet supported)."
            )
        if scheme == "ldapi":
            if use_ssl:
                raise ValueError(
                    f"Server '{server_label}': use_ssl=true conflicts with the "
                    f"ldapi:// URL {url_value!r} — LDAPI is a Unix socket and "
                    "does not use TLS."
                )
            if hostname is None:
                hostname = parsed.hostname or "localhost"
        else:
            if not parsed.hostname:
                raise ValueError(
                    f"Server '{server_label}': ldap_url {url_value!r} has no "
                    f"hostname (expected e.g. '{scheme}://host:port')."
                )
            url_ssl = scheme == "ldaps"
            if use_ssl is not None and use_ssl != url_ssl:
                raise ValueError(
                    f"Server '{server_label}': use_ssl={str(use_ssl).lower()} "
                    f"conflicts with the {scheme}:// scheme of ldap_url "
                    f"{url_value!r}. The URL is authoritative — remove use_ssl "
                    "or make it match (ldap:// = false, ldaps:// = true)."
                )
            if hostname is not None and hostname != parsed.hostname:
                raise ValueError(
                    f"Server '{server_label}': hostname {hostname!r} conflicts "
                    f"with the host in ldap_url {url_value!r}. Remove one of them."
                )
            if port is not None and parsed.port is not None:
                try:
                    explicit_port = int(port)
                except (TypeError, ValueError):
                    explicit_port = None  # invalid port raises below
                if explicit_port is not None and explicit_port != parsed.port:
                    raise ValueError(
                        f"Server '{server_label}': port {port!r} conflicts with "
                        f"the port in ldap_url {url_value!r}. Remove one of them."
                    )
            hostname = parsed.hostname
            use_ssl = url_ssl
            if port is None:
                port = parsed.port or (636 if url_ssl else 389)

    if hostname is None:
        if is_offline or is_archive:
            hostname = "localhost" if is_offline else "archive"
        else:
            raise KeyError("Server definition must include either hostname or ldap_url")

    ssl_bool = bool(use_ssl)
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
    # Both paths use the same strict parser: a typo raises instead of
    # silently disabling certificate verification.
    if "tls_verify" in data:
        tls_verify = _coerce_bool(data["tls_verify"], field="tls_verify")
    else:
        tls_verify = env_strict_bool("LDAP_TLS_VERIFY", True)

    # Escape hatch for sending a simple-bind password over plain ldap:// to
    # a non-loopback host.  Default: refused at connect time.
    if "allow_insecure_plaintext" in data:
        allow_insecure_plaintext = _coerce_bool(
            data["allow_insecure_plaintext"], field="allow_insecure_plaintext"
        )
    else:
        allow_insecure_plaintext = env_strict_bool(
            "LDAP_ALLOW_INSECURE_PLAINTEXT", False
        )

    # Local instance support
    is_local = _coerce_bool(data.get("is_local", False), field="is_local")
    serverid = data.get("serverid")
    use_ldapi = _coerce_bool(data.get("use_ldapi", False), field="use_ldapi")

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

    # Resolve the bind password from exactly one source:
    # inline "bind_password", "bind_password_env" (environment variable
    # name), or "bind_password_file" (owner-only readable file, relative
    # paths resolved against the config file's directory).
    bind_password_env = data.get("bind_password_env")
    bind_password_file = _expand_path(data.get("bind_password_file"), base_dir)
    bind_password = resolve_bind_password(
        label=data.get("name", hostname),
        bind_password=data.get("bind_password"),
        bind_password_env=bind_password_env,
        bind_password_file=bind_password_file,
    )

    return LDAPServerConfig(
        name=data.get("name", hostname),
        hostname=hostname,
        port=port,
        use_ssl=ssl_bool,
        bind_dn=data.get("bind_dn"),
        bind_password=bind_password,
        bind_password_env=bind_password_env,
        bind_password_file=bind_password_file,
        base_dn=data.get("base_dn"),
        auth_method=auth_method,
        provider_type=data.get("provider_type", "389ds"),
        tls_verify=tls_verify,
        allow_insecure_plaintext=allow_insecure_plaintext,
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


def _coerce_bool(value: Any, field: str = "boolean setting") -> bool:
    """Strictly parse a boolean config value; raise ValueError on garbage.

    Delegates to :func:`ldap_assistant_mcp.core.parse_strict_bool` so JSON
    config fields and environment variables share one parser.
    A typo like ``"flase"`` fails startup instead of silently disabling a
    security setting.
    """
    return parse_strict_bool(value, field)


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
        expose = _coerce_bool(data["expose_sensitive_data"], field="expose_sensitive_data")
    else:
        expose = env_settings.expose_sensitive_data

    if "debug" in data:
        debug = _coerce_bool(data["debug"], field="debug")
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
