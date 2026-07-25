from __future__ import annotations

import argparse
import json
import os
import sys
from dataclasses import dataclass
from typing import Any, Dict, Iterable, List, Optional, Tuple, Type

from ldap_assistant_mcp.dirsrv_mcp.server import DirSrvMCP
from ldap_assistant_mcp.core import (
    LDAPAssistantMCP,
    LDAPServerConfig,
    __version__,
    _env_flag,
)
from ldap_assistant_mcp.openldap_mcp.server import OpenLDAPMCP


@dataclass(frozen=True)
class ServerDefinition:
    """Metadata describing an MCP server implementation."""

    cls: Type[LDAPAssistantMCP]
    supports_config_path: bool = False
    description: str = ""


SERVER_REGISTRY: Dict[str, ServerDefinition] = {
    "dirsrv": ServerDefinition(
        cls=DirSrvMCP,
        supports_config_path=True,
        description="389 Directory Server",
    ),
    "openldap": ServerDefinition(
        cls=OpenLDAPMCP,
        supports_config_path=False,
        description="OpenLDAP Server",
    ),
}

DEFAULT_PROVIDER = "dirsrv"
PROVIDER_ENV_VAR = "LDAP_PROVIDER"
# The OpenLDAP provider is an experimental two-tool stub that bypasses the
# privacy sanitizer and middleware — it must be opted into explicitly.
EXPERIMENTAL_OPENLDAP_ENV_VAR = "LDAP_MCP_EXPERIMENTAL_OPENLDAP"


def create_server(
    *,
    provider: Optional[str] = None,
    config_path: Optional[str] = None,
    servers: Optional[Iterable[LDAPServerConfig]] = None,
    include_env_fallback: bool = True,
    **kwargs,
) -> LDAPAssistantMCP:
    """
    Build an MCP server using registry metadata.

    This helper is the canonical entry point for fastmcp.json.
    """

    _, definition = _resolve_provider(provider)
    init_kwargs = dict(kwargs)

    if servers:
        init_kwargs["servers"] = list(servers)

    if definition.supports_config_path:
        resolved_config_path = (
            config_path if config_path is not None else os.environ.get("LDAP_SERVERS_CONFIG")
        )
        init_kwargs["config_path"] = resolved_config_path

    init_kwargs.setdefault("include_env_fallback", include_env_fallback)

    return definition.cls(**init_kwargs)  # type: ignore[call-arg]


def _resolve_provider(
    provider: Optional[str],
) -> Tuple[str, ServerDefinition]:
    """Resolve provider name to its registry definition.

    Falls back to LDAP_PROVIDER env var, then DEFAULT_PROVIDER.
    """
    requested = (provider or os.environ.get(PROVIDER_ENV_VAR) or DEFAULT_PROVIDER).lower()
    definition = SERVER_REGISTRY.get(requested)
    if not definition:
        valid = ", ".join(sorted(SERVER_REGISTRY))
        raise ValueError(f"Unknown LDAP MCP provider '{requested}'. Valid options: {valid}.")
    if requested == "openldap" and not _env_flag(EXPERIMENTAL_OPENLDAP_ENV_VAR):
        raise ValueError(
            "The OpenLDAP provider is experimental: it exposes only two tools "
            "and bypasses the privacy sanitizer and middleware used by the "
            "389 DS provider. Set LDAP_MCP_EXPERIMENTAL_OPENLDAP=true to opt "
            "in, or use LDAP_PROVIDER=dirsrv (389 Directory Server, the "
            "supported provider)."
        )
    return requested, definition


# ---------------------------------------------------------------------------
# Operability CLI: doctor / support-bundle / --check-config / --list-tools
# ---------------------------------------------------------------------------

# Support bundles must never leak sensitive data.  These placeholder
# hostnames are generic defaults, not deployment identifiers, so they are
# exempt from the forbidden-content scan (a server *named* "localhost"
# would otherwise always trip the scan on its own name).
_GENERIC_HOSTNAMES = frozenset({"localhost", "archive", "127.0.0.1", "::1", ""})

_MAX_BUNDLE_BYTES = 1024 * 1024  # 1 MiB


def _versions() -> Dict[str, str]:
    """Collect package versions relevant for a diagnosis (no secrets)."""
    import platform
    from importlib.metadata import PackageNotFoundError, version

    out = {
        "ldap_assistant_mcp": __version__,
        "python": platform.python_version(),
    }
    for dist in ("fastmcp", "lib389"):
        try:
            out[dist] = version(dist)
        except PackageNotFoundError:
            out[dist] = "unknown"
    return out


def _transport_of(config: LDAPServerConfig) -> str:
    """Transport scheme only — never the hostname or port."""
    if config.is_archive:
        return "file"
    if config.use_ldapi:
        return "ldapi"
    return "ldaps" if config.use_ssl else "ldap"


def _credential_source(config: LDAPServerConfig) -> str:
    if config.bind_password_env:
        return "env"
    if config.bind_password_file:
        return "file"
    if config.bind_password:
        return "inline"
    return "none"


def _build_dirsrv(config_path: Optional[str]) -> DirSrvMCP:
    """Build the diagnostics target (always the dirsrv provider)."""
    return DirSrvMCP(config_path=config_path)


def _doctor_report(mcp: DirSrvMCP, *, connect: bool) -> Dict[str, Any]:
    """Build the doctor report dict (no hostnames, DNs, or secrets)."""
    from ldap_assistant_mcp.dirsrv_mcp.tools.capabilities import (
        evaluate_server_config,
        registered_tools,
        server_mode,
    )

    servers: List[Dict[str, Any]] = []
    problems: List[str] = []
    for config in mcp.server_configs.values():
        state, code, detail = evaluate_server_config(config)
        entry: Dict[str, Any] = {
            "name": config.name,
            "mode": server_mode(config),
            "transport": _transport_of(config),
            "auth_method": getattr(config.auth_method, "value", str(config.auth_method)),
            "credential_source": _credential_source(config),
            "tls_verify": config.tls_verify,
            "config_state": state,
        }
        if state != "valid":
            entry["code"] = code
            entry["detail"] = detail
            problems.append(f"{config.name}: {detail}")
        elif connect:
            ds = None
            try:
                ds = mcp.connection_manager.connect(config.name)
                entry["reachable"] = True
            except Exception as exc:
                entry["reachable"] = False
                entry["reachability_error"] = f"{type(exc).__name__}: {exc}"
                problems.append(f"{config.name}: unreachable")
            finally:
                if ds is not None:
                    try:
                        ds.close()
                    except Exception:
                        pass
        servers.append(entry)

    return {
        "type": "doctor_report",
        "status": "healthy" if not problems else "degraded",
        "versions": _versions(),
        "privacy": {
            "privacy_mode": mcp.privacy_enabled,
            "debug": mcp.debug_enabled,
        },
        "server_count": len(mcp.server_configs),
        "tool_count": len(registered_tools(mcp)),
        "reachability_checked": connect,
        "servers": servers,
        "problems": problems,
    }


def _emit_doctor(report: Dict[str, Any], as_json: bool) -> None:
    if as_json:
        print(json.dumps(report, indent=2))
        return
    print(f"ldap-assistant-mcp doctor — status: {report['status']}")
    versions = report.get("versions", {})
    print(
        "versions: "
        + ", ".join(f"{name} {value}" for name, value in sorted(versions.items()))
    )
    if report["status"] == "config_error":
        print(f"config error: {report.get('error', 'unknown')}")
        return
    privacy = report.get("privacy", {})
    print(
        f"privacy mode: {'on' if privacy.get('privacy_mode') else 'OFF'}, "
        f"debug: {'on' if privacy.get('debug') else 'off'}"
    )
    print(f"tools registered: {report.get('tool_count', 0)}")
    print(f"servers ({report.get('server_count', 0)}):")
    for server in report.get("servers", []):
        line = (
            f"  - {server['name']} mode={server['mode']} "
            f"transport={server['transport']} auth={server['auth_method']} "
            f"credential_source={server['credential_source']} "
            f"tls_verify={server['tls_verify']} config={server['config_state']}"
        )
        if "reachable" in server:
            line += f" reachable={server['reachable']}"
        print(line)
        if server.get("detail"):
            print(f"      {server.get('code')}: {server['detail']}")
        if server.get("reachability_error"):
            print(f"      {server['reachability_error']}")
    problems = report.get("problems", [])
    if problems:
        print("problems:")
        for problem in problems:
            print(f"  - {problem}")
    else:
        print("problems: none")


def _cmd_doctor(config_path: Optional[str], *, as_json: bool, connect: bool) -> int:
    """Exit codes: 0 healthy, 1 config error, 2 degraded."""
    try:
        mcp = _build_dirsrv(config_path)
    except Exception as exc:
        report = {
            "type": "doctor_report",
            "status": "config_error",
            "error": f"{type(exc).__name__}: {exc}",
            "versions": _versions(),
        }
        _emit_doctor(report, as_json)
        return 1
    report = _doctor_report(mcp, connect=connect)
    _emit_doctor(report, as_json)
    return 0 if report["status"] == "healthy" else 2


def _forbidden_values(mcp: DirSrvMCP) -> List[Tuple[str, str]]:
    """Values that must NEVER appear in a support bundle."""
    values: List[Tuple[str, str]] = []
    for config in mcp.server_configs.values():
        if config.bind_password:
            values.append(("bind_password", config.bind_password))
        if config.bind_dn:
            values.append(("bind_dn", config.bind_dn))
        if config.base_dn:
            values.append(("base_dn", config.base_dn))
        if config.hostname and config.hostname not in _GENERIC_HOSTNAMES:
            values.append(("hostname", config.hostname))
    return values


def _cmd_support_bundle(config_path: Optional[str], output: str) -> int:
    """Exit codes: 0 written, 1 config error, 2 refused (leak/size/write)."""
    from datetime import datetime, timezone

    try:
        mcp = _build_dirsrv(config_path)
    except Exception as exc:
        print(
            f"support-bundle: config error: {type(exc).__name__}: {exc}",
            file=sys.stderr,
        )
        return 1

    doctor = _doctor_report(mcp, connect=False)
    bundle = {
        "type": "support_bundle",
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "versions": doctor["versions"],
        "privacy": doctor["privacy"],
        "doctor_status": doctor["status"],
        "problems": doctor["problems"],
        "tool_count": doctor["tool_count"],
        "config_fingerprint": {
            "server_count": doctor["server_count"],
            "servers": [
                {
                    "name": server["name"],
                    "mode": server["mode"],
                    "transport": server["transport"],
                }
                for server in doctor["servers"]
            ],
        },
        "doctor": doctor,
    }
    payload = json.dumps(bundle, indent=2, sort_keys=True)

    # Forbidden-content scan: fail closed BEFORE anything touches disk.
    hits = sorted(
        {label for label, value in _forbidden_values(mcp) if value and value in payload}
    )
    if hits:
        print(
            "support-bundle: refusing to write: bundle would contain "
            f"sensitive configuration values ({', '.join(hits)}). "
            "This is a bug guard — server names must not embed hostnames "
            "or DNs.",
            file=sys.stderr,
        )
        return 2

    encoded = payload.encode("utf-8")
    if len(encoded) > _MAX_BUNDLE_BYTES:
        print(
            f"support-bundle: refusing to write: bundle is {len(encoded)} "
            f"bytes (limit {_MAX_BUNDLE_BYTES}).",
            file=sys.stderr,
        )
        return 2

    try:
        fd = os.open(output, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
        try:
            with os.fdopen(fd, "w", encoding="utf-8") as fh:
                fh.write(payload)
        finally:
            # os.fdopen owns fd; nothing else to close here.
            pass
        # If the file pre-existed, O_CREAT mode was ignored — enforce 0600.
        os.chmod(output, 0o600)
    except OSError as exc:
        print(f"support-bundle: cannot write {output!r}: {exc}", file=sys.stderr)
        return 2

    print(f"support bundle written to {output} ({len(encoded)} bytes, mode 0600)")
    return 0


def _cmd_check_config(config_path: Optional[str]) -> int:
    """Exit codes: 0 valid, 1 invalid."""
    from ldap_assistant_mcp.config.loader import load_config

    try:
        config = load_config(config_file=config_path)
    except Exception as exc:
        print(
            f"Configuration INVALID: {type(exc).__name__}: {exc}", file=sys.stderr
        )
        return 1
    names = ", ".join(server.name for server in config.servers)
    print(f"Configuration OK: {len(config.servers)} server(s): {names}")
    return 0


def _cmd_list_tools(config_path: Optional[str]) -> int:
    """Exit codes: 0 listed, 1 config error."""
    from ldap_assistant_mcp.dirsrv_mcp.tools.capabilities import registered_tools

    try:
        mcp = _build_dirsrv(config_path)
    except Exception as exc:
        print(f"config error: {type(exc).__name__}: {exc}", file=sys.stderr)
        return 1
    tools = sorted(registered_tools(mcp), key=lambda tool: tool.name)
    for tool in tools:
        tags = ", ".join(sorted(tool.tags or ()))
        print(f"{tool.name}  [{tags}]")
    print(f"{len(tools)} tools registered")
    return 0


def _run_cli(args: List[str]) -> int:
    parser = argparse.ArgumentParser(
        prog="ldap-assistant-mcp",
        description=(
            "LDAP Assistant MCP server. With no arguments, runs the MCP "
            "server on stdio. Subcommands provide operability diagnostics."
        ),
    )
    parser.add_argument(
        "--config",
        metavar="PATH",
        default=None,
        help="Path to servers.json (default: LDAP_SERVERS_CONFIG env var)",
    )
    parser.add_argument(
        "--check-config",
        action="store_true",
        help="Validate the server configuration and exit (0 valid / 1 invalid)",
    )
    parser.add_argument(
        "--list-tools",
        action="store_true",
        help="List registered MCP tools with their tags and exit",
    )
    parser.add_argument(
        "--version", action="version", version=f"ldap-assistant-mcp {__version__}"
    )

    sub = parser.add_subparsers(dest="command", metavar="{doctor,support-bundle}")

    doctor_p = sub.add_parser(
        "doctor",
        help="Diagnose config, versions, privacy posture; optional reachability",
        description=(
            "Validates configuration loading, reports per-server mode/"
            "transport/auth posture (no secrets), privacy posture, and "
            "package versions. Exit codes: 0 healthy, 1 config error, "
            "2 degraded."
        ),
    )
    doctor_p.add_argument("--config", metavar="PATH", default=argparse.SUPPRESS)
    doctor_p.add_argument(
        "--json", action="store_true", dest="as_json", help="Emit JSON instead of text"
    )
    doctor_p.add_argument(
        "--connect",
        action="store_true",
        help="Also perform bounded reachability checks (opens connections)",
    )

    bundle_p = sub.add_parser(
        "support-bundle",
        help="Write a redacted JSON support bundle (never hostnames/DNs/secrets)",
        description=(
            "Writes an owner-only (0600) JSON artifact with versions, a "
            "redacted config fingerprint, and a doctor summary. Refuses to "
            "write if any sensitive configuration value would leak. Exit "
            "codes: 0 written, 1 config error, 2 refused."
        ),
    )
    bundle_p.add_argument("--config", metavar="PATH", default=argparse.SUPPRESS)
    bundle_p.add_argument(
        "--output", metavar="FILE", required=True, help="Bundle output path"
    )

    ns = parser.parse_args(args)

    if ns.command == "doctor":
        return _cmd_doctor(ns.config, as_json=ns.as_json, connect=ns.connect)
    if ns.command == "support-bundle":
        return _cmd_support_bundle(ns.config, ns.output)
    if ns.check_config:
        return _cmd_check_config(ns.config)
    if ns.list_tools:
        return _cmd_list_tools(ns.config)
    parser.print_help()
    return 2


def main(argv: Optional[List[str]] = None) -> None:
    """Entry point for the `ldap-assistant-mcp` console script.

    With no arguments this starts the MCP server on stdio using defaults
    and environment variables — the contract fastmcp.json and MCP clients
    depend on.  With arguments it dispatches to the operability CLI
    (doctor, support-bundle, --check-config, --list-tools).
    """

    args = list(sys.argv[1:]) if argv is None else list(argv)
    if not args:
        server = create_server()
        server.run()
        return
    raise SystemExit(_run_cli(args))


if __name__ == "__main__":
    main()

