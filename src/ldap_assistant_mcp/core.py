from __future__ import annotations

import errno
import ipaddress
import logging
import os
import stat as stat_module
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
    "read_bind_password_file",
    "resolve_bind_password",
]

try:
    __version__ = _dist_version("ldap-assistant-mcp")
except PackageNotFoundError:  # running from a source tree without an install
    __version__ = "0.0.0.dev0"

_PACKAGE_LOGGER = "ldap_assistant_mcp"


def _env_flag(name: str) -> bool:
    """Return True if the environment variable is set to a truthy value."""
    return str(os.environ.get(name, "")).lower() in {"1", "true", "yes", "on"}


_BOOL_TRUE_VALUES = {"1", "true", "yes", "on"}
_BOOL_FALSE_VALUES = {"0", "false", "no", "off"}


def parse_strict_bool(value: Any, field: str) -> bool:
    """Parse a boolean configuration value strictly.

    Accepts real booleans, the integers 0/1, and the strings true/false,
    1/0, yes/no, on/off (case-insensitive).  Anything else — including
    typos like ``"flase"`` — raises ValueError naming the field, so a
    misspelled security setting fails startup instead of silently
    flipping to a default.
    """
    if isinstance(value, bool):
        return value
    if isinstance(value, int) and value in (0, 1):
        return bool(value)
    if isinstance(value, str):
        lowered = value.strip().lower()
        if lowered in _BOOL_TRUE_VALUES:
            return True
        if lowered in _BOOL_FALSE_VALUES:
            return False
    raise ValueError(
        f"Invalid boolean value for {field}: {value!r}. "
        "Accepted values: true/false, 1/0, yes/no, on/off."
    )


def env_strict_bool(name: str, default: bool) -> bool:
    """Read a boolean environment variable with strict parsing.

    Unset or empty variables return *default*; any other value must be a
    valid boolean per :func:`parse_strict_bool` or ValueError is raised.
    This keeps JSON config fields and their environment-variable
    equivalents behaving identically.
    """
    raw = os.environ.get(name)
    if raw is None or raw.strip() == "":
        return default
    return parse_strict_bool(raw, name)


def read_bind_password_file(path: str, field: str = "bind_password_file") -> str:
    """Read a bind password from *path* with strict safety checks.

    The file must be a regular file (not a symlink), owned by the current
    user, and readable by the owner only (no group/other permission bits).
    The returned password is the file content with surrounding whitespace
    stripped.  Every violation raises ValueError naming the file and the
    fix, so a misconfigured secrets file fails startup loudly.
    """
    symlink_error = (
        f"{field}: {path!r} is a symlink. Refusing to read secrets "
        "through symlinks — point it at the regular file directly."
    )
    if os.path.islink(path):
        raise ValueError(symlink_error)
    # Open first, then validate the OPENED file via fstat: a stat-then-open
    # sequence could be raced into reading a different inode (symlink swap
    # between check and open).  O_NOFOLLOW makes the open itself refuse
    # symlinks, so every check below applies to the file actually read.
    try:
        fd = os.open(path, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0))
    except FileNotFoundError:
        raise ValueError(
            f"{field}: password file {path!r} does not exist."
        ) from None
    except OSError as exc:
        if exc.errno == errno.ELOOP:
            raise ValueError(symlink_error) from None
        raise ValueError(
            f"{field}: cannot open password file {path!r}: "
            f"{exc.strerror or exc}."
        ) from None
    try:
        st = os.fstat(fd)
        if not stat_module.S_ISREG(st.st_mode):
            raise ValueError(
                f"{field}: {path!r} is not a regular file."
            )
        if hasattr(os, "getuid") and st.st_uid != os.getuid():
            raise ValueError(
                f"{field}: {path!r} is owned by uid {st.st_uid}, not the "
                f"current user (uid {os.getuid()}). Secrets files must be "
                "owned by the user running the server."
            )
        if st.st_mode & 0o077:
            raise ValueError(
                f"{field}: {path!r} is group/other-accessible "
                f"(mode {oct(st.st_mode & 0o777)}). Fix with: chmod 600 {path}"
            )
        fh = os.fdopen(fd, "r", encoding="utf-8")
        fd = -1  # ownership transferred to the file object
        with fh:
            password = fh.read().strip()
    finally:
        if fd != -1:
            try:
                os.close(fd)
            except OSError:
                pass
    if not password:
        raise ValueError(
            f"{field}: password file {path!r} is empty."
        )
    return password


def resolve_bind_password(
    *,
    label: str,
    bind_password: Optional[str] = None,
    bind_password_env: Optional[str] = None,
    bind_password_file: Optional[str] = None,
) -> Optional[str]:
    """Resolve the bind password from exactly one configured source.

    At most one of ``bind_password`` (inline), ``bind_password_env``
    (name of an environment variable), and ``bind_password_file`` (path
    to an owner-only readable file) may be set; anything else raises
    ValueError naming the server and the conflicting fields.
    Returns the resolved password, or None when no source is configured.
    """
    provided = [
        name
        for name, value in (
            ("bind_password", bind_password),
            ("bind_password_env", bind_password_env),
            ("bind_password_file", bind_password_file),
        )
        if value
    ]
    if len(provided) > 1:
        raise ValueError(
            f"Server '{label}': at most one of bind_password, "
            "bind_password_env, and bind_password_file may be set "
            f"(got {', '.join(provided)}). Keep exactly one password source."
        )
    if bind_password_env:
        value = os.environ.get(bind_password_env)
        if not value:
            raise ValueError(
                f"Server '{label}': bind_password_env names environment "
                f"variable {bind_password_env!r}, which is not set (or "
                "empty). Export it before starting the server."
            )
        return value
    if bind_password_file:
        return read_bind_password_file(
            bind_password_file,
            field=f"Server '{label}': bind_password_file",
        )
    return bind_password


def _is_loopback_host(host: Optional[str]) -> bool:
    """Return True if *host* refers to the local loopback interface.

    Recognizes ``localhost``, any 127.0.0.0/8 IPv4 address, and the IPv6
    loopback ``::1`` (with or without brackets).
    """
    if not host:
        return False
    candidate = host.strip().strip("[]").lower()
    if candidate == "localhost":
        return True
    try:
        return ipaddress.ip_address(candidate).is_loopback
    except ValueError:
        return False


class _RedactingStderrFilter(logging.Filter):
    """Sanitize log records at the stderr boundary in privacy mode.

    stderr is an egress channel like any tool result: MCP clients commonly
    capture and forward server logs. When sensitive-data exposure is not
    explicitly enabled, every record is passed through the privacy
    sanitizer before it can reach a handler. Fails closed: a sanitizer
    error redacts the whole record instead of letting it through raw.
    """

    def filter(self, record: logging.LogRecord) -> bool:
        if _env_flag("LDAP_MCP_EXPOSE_SENSITIVE_DATA"):
            return True
        try:
            # Imported lazily to avoid a core <-> privacy import cycle
            from ldap_assistant_mcp.lib.privacy import get_sanitizer

            message = record.getMessage()
            sanitized = get_sanitizer().sanitize_text(message)
            if sanitized != message:
                record.msg = sanitized
                record.args = ()
        except Exception:
            record.msg = "[redacted log record]"
            record.args = ()
        return True


def configure_package_logging(debug: Optional[bool] = None) -> None:
    """Attach a stderr handler to the ``ldap_assistant_mcp`` logger tree.

    Without this, no handler is ever configured and middleware INFO logs
    (and even LDAP_MCP_DEBUG output) go nowhere — Python's lastResort
    handler only emits WARNING and above.  stderr is safe for the stdio
    transport: only stdout carries MCP protocol data. In privacy mode the
    handler sanitizes every record before emission.

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
        handler.addFilter(_RedactingStderrFilter())
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
    # Secret indirection: alternatives to an inline bind_password.
    # bind_password_env names an environment variable; bind_password_file
    # is a path to an owner-only-readable regular file whose stripped
    # content is the password.  At most one of the three sources may be
    # set; resolution happens at config load and stores the resolved
    # secret in bind_password (these fields keep the provenance).
    bind_password_env: Optional[str] = None
    bind_password_file: Optional[str] = None
    base_dn: Optional[str] = None
    auth_method: LDAPAuthMethod = LDAPAuthMethod.SIMPLE
    provider_type: str = "generic"
    # Verify the server certificate for remote ldaps:// connections (default
    # True).  Set False only for trusted lab setups with self-signed
    # certificates — it disables certificate verification entirely.
    tls_verify: bool = True
    # Allow a simple bind with a password over unencrypted ldap:// to a
    # NON-loopback host (default False).  By default such connections are
    # refused because the bind password would cross the network in
    # cleartext.  Set True only for isolated lab networks.
    allow_insecure_plaintext: bool = False
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
        if self.allow_insecure_plaintext:
            result["allow_insecure_plaintext"] = True
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
            LDAP_URL: Full ldap://, ldaps://, or ldapi:// URL. The URL scheme
                is authoritative: any other scheme raises, and a conflicting
                LDAP_USE_SSL raises instead of being silently reconciled.
            LDAP_HOSTNAME: Hostname or IP address
            LDAP_PORT: Port number
            LDAP_USE_SSL: true/false to enable LDAPS (StartTLS is not yet
                supported — use ldaps:// for encrypted connections)
            LDAP_BASE_DN: Directory base DN
            LDAP_BIND_DN: Bind DN
            LDAP_BIND_PASSWORD: Bind password (inline)
            LDAP_BIND_PASSWORD_FILE: Path to a file whose stripped content
                is the bind password. The file must be a regular file (not
                a symlink), owned by the current user, and chmod 600
                (no group/other access). Mutually exclusive with
                LDAP_BIND_PASSWORD.
            LDAP_AUTH_METHOD: simple | anonymous (the only implemented binds;
                LDAPI/SASL EXTERNAL is selected via LDAP_USE_LDAPI, not here)
            LDAP_PROVIDER: Optional provider hint (e.g., 389ds, openldap)
            LDAP_TLS_VERIFY: true/false - verify server certificate for remote
                LDAPS connections (default: true)
            LDAP_ALLOW_INSECURE_PLAINTEXT: true/false - allow a simple bind
                with a password over unencrypted ldap:// to a non-loopback
                host (default: false; lab use only)
            LDAP_IS_LOCAL: true/false - if true, enables local instance access
            LDAP_SERVERID: Instance name (e.g., 'standalone') - required if is_local=true
            LDAP_USE_LDAPI: true/false - connect over the LDAPI unix socket
                (requires LDAP_IS_LOCAL=true and LDAP_SERVERID)
            LDAP_IS_OFFLINE: true/false - treat the local instance as stopped
                (implies LDAP_IS_LOCAL=true; requires LDAP_SERVERID)

        Boolean variables are parsed strictly: only true/false, 1/0, yes/no,
        on/off (case-insensitive) are accepted; anything else raises so a
        typo cannot silently change a security setting.

        Raises:
            ValueError: On invalid LDAP_PORT / LDAP_AUTH_METHOD values,
                invalid boolean values, an unsupported LDAP_URL scheme, a
                LDAP_URL/LDAP_USE_SSL conflict, or LDAP_IS_OFFLINE=true
                without LDAP_SERVERID.
        """

        url = os.environ.get("LDAP_URL")
        hostname = os.environ.get("LDAP_HOSTNAME")
        use_ssl_env = os.environ.get("LDAP_USE_SSL")
        port_env = os.environ.get("LDAP_PORT")

        explicit_use_ssl: Optional[bool] = None
        if use_ssl_env is not None and use_ssl_env.strip() != "":
            explicit_use_ssl = parse_strict_bool(use_ssl_env, "LDAP_USE_SSL")

        if url:
            parsed = urlparse(url)
            scheme = (parsed.scheme or "").lower()
            if scheme not in ("ldap", "ldaps", "ldapi"):
                raise ValueError(
                    f"Unsupported scheme {parsed.scheme!r} in LDAP_URL {url!r}. "
                    "Supported schemes: ldap://, ldaps://, ldapi:// "
                    "(StartTLS is not yet supported)."
                )
            if scheme == "ldapi":
                if explicit_use_ssl:
                    raise ValueError(
                        f"LDAP_USE_SSL=true conflicts with the ldapi:// LDAP_URL "
                        f"{url!r} — LDAPI is a Unix socket and does not use TLS."
                    )
                use_ssl = False
            else:
                use_ssl = scheme == "ldaps"
                if explicit_use_ssl is not None and explicit_use_ssl != use_ssl:
                    raise ValueError(
                        f"LDAP_USE_SSL={use_ssl_env!r} conflicts with the "
                        f"{scheme}:// scheme of LDAP_URL {url!r}. The URL is "
                        "authoritative — unset LDAP_USE_SSL or make it match "
                        "(ldap:// = false, ldaps:// = true)."
                    )
            hostname = parsed.hostname or hostname or "localhost"
            port = parsed.port or (636 if use_ssl else 389)
        else:
            hostname = hostname or "localhost"
            use_ssl = explicit_use_ssl if explicit_use_ssl is not None else False
            if port_env:
                try:
                    port = int(port_env)
                except ValueError:
                    raise ValueError(
                        f"Invalid LDAP_PORT value {port_env!r} (must be an integer)"
                    ) from None
            else:
                port = 636 if use_ssl else 389

        base_dn = os.environ.get("LDAP_BASE_DN", "dc=example,dc=com")
        auth_env = os.environ.get("LDAP_AUTH_METHOD", LDAPAuthMethod.SIMPLE.value).lower()
        try:
            auth_method = LDAPAuthMethod(auth_env)
        except ValueError:
            valid = ", ".join(m.value for m in LDAPAuthMethod)
            raise ValueError(
                f"Invalid LDAP_AUTH_METHOD value {auth_env!r}. Valid values: {valid}. "
                "Note: only 'simple' and 'anonymous' binds are implemented; "
                "LDAPI/SASL EXTERNAL is selected via LDAP_USE_LDAPI=true."
            ) from None

        # For anonymous auth, don't use default credentials
        bind_password_file = os.environ.get("LDAP_BIND_PASSWORD_FILE") or None
        if auth_method == LDAPAuthMethod.ANONYMOUS:
            bind_dn = None
            bind_password = None
            bind_password_file = None
        else:
            bind_dn = os.environ.get("LDAP_BIND_DN", "cn=Directory Manager")
            bind_password = os.environ.get("LDAP_BIND_PASSWORD")
            if bind_password and bind_password_file:
                raise ValueError(
                    "Both LDAP_BIND_PASSWORD and LDAP_BIND_PASSWORD_FILE are "
                    "set. Keep exactly one password source (unset the other)."
                )
            if bind_password_file:
                bind_password = read_bind_password_file(
                    bind_password_file, field="LDAP_BIND_PASSWORD_FILE"
                )
        provider_type = os.environ.get("LDAP_PROVIDER", "generic")

        # Local instance configuration
        is_local = env_strict_bool("LDAP_IS_LOCAL", False)
        serverid = os.environ.get("LDAP_SERVERID")
        use_ldapi = env_strict_bool("LDAP_USE_LDAPI", False)

        # Offline instance mode: mirrors the JSON-loader invariants —
        # offline implies is_local, and the serverid is needed to locate
        # the instance's dse.ldif and log files.
        is_offline = env_strict_bool("LDAP_IS_OFFLINE", False)
        if is_offline:
            is_local = True
            if not serverid:
                raise ValueError(
                    "LDAP_IS_OFFLINE=true requires LDAP_SERVERID to be set "
                    "(the instance name without the 'slapd-' prefix, "
                    "e.g. 'localhost')."
                )

        # Strict parsing: unset/empty keeps the safe default (verification
        # ON); a typo like "flase" raises instead of changing the setting.
        tls_verify = env_strict_bool("LDAP_TLS_VERIFY", True)
        allow_insecure_plaintext = env_strict_bool(
            "LDAP_ALLOW_INSECURE_PLAINTEXT", False
        )

        return cls(
            name=name,
            hostname=hostname,
            port=port,
            use_ssl=use_ssl,
            bind_dn=bind_dn,
            bind_password=bind_password,
            bind_password_file=bind_password_file,
            base_dn=base_dn,
            auth_method=auth_method,
            provider_type=provider_type,
            tls_verify=tls_verify,
            allow_insecure_plaintext=allow_insecure_plaintext,
            is_local=is_local,
            serverid=serverid,
            use_ldapi=use_ldapi,
            is_offline=is_offline,
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

