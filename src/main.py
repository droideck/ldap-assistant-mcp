from __future__ import annotations

import argparse
import logging
import os
from typing import Dict, Type

from src.dirsrv_mcp.server import DirSrvMCP
from src.ldap_assistant_mcp.server import LDAPAssistantMCP, LDAPAuthMethod, LDAPServerConfig
from src.openldap_mcp.server import OpenLDAPMCP

SERVER_REGISTRY: Dict[str, Type[LDAPAssistantMCP]] = {
    "dirsrv": DirSrvMCP,
    "openldap": OpenLDAPMCP,
}


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="LDAP Assistant MCP entry point.")
    parser.add_argument(
        "server",
        choices=SERVER_REGISTRY.keys(),
        nargs="?",
        default="dirsrv",
        help="Which server implementation to run (default: dirsrv)",
    )
    parser.add_argument("--hostname", help="LDAP hostname or IP address")
    parser.add_argument("--port", type=int, help="LDAP port (defaults to 389/636)")
    parser.add_argument("--use-ssl", action="store_true", help="Use LDAPS/StartTLS")
    parser.add_argument("--bind-dn", help="Bind DN for authentication")
    parser.add_argument("--bind-password", help="Bind password")
    parser.add_argument("--base-dn", help="Base DN for directory operations")
    parser.add_argument(
        "--auth-method",
        choices=[method.value for method in LDAPAuthMethod],
        default=LDAPAuthMethod.SIMPLE.value,
        help="Authentication method to use",
    )
    parser.add_argument("--server-name", help="Identifier for the server entry", default="cli")
    parser.add_argument("--config", help="Path to multi-server JSON config (DirSrv only)")
    parser.add_argument(
        "--transport",
        choices=["stdio", "http"],
        default="stdio",
        help="Transport to use when running the server",
    )
    parser.add_argument("--listen-host", default="127.0.0.1", help="HTTP host when using http transport")
    parser.add_argument(
        "--listen-port", type=int, default=8000, help="HTTP port when using http transport"
    )
    parser.add_argument(
        "--log-level",
        default=os.environ.get("LOG_LEVEL", "INFO"),
        help="Logging level (DEBUG, INFO, WARNING, ERROR)",
    )
    return parser.parse_args()


def build_cli_server_config(args: argparse.Namespace) -> LDAPServerConfig | None:
    if not args.hostname:
        return None

    port = args.port
    if port is None:
        port = 636 if args.use_ssl else 389

    return LDAPServerConfig(
        name=args.server_name or "cli",
        hostname=args.hostname,
        port=port,
        use_ssl=args.use_ssl,
        bind_dn=args.bind_dn,
        bind_password=args.bind_password,
        base_dn=args.base_dn,
        auth_method=LDAPAuthMethod(args.auth_method),
        provider_type=args.server,
    )


def main() -> None:
    args = parse_args()
    logging.basicConfig(level=getattr(logging, args.log_level.upper(), logging.INFO))

    connection_override = build_cli_server_config(args)

    server_class = SERVER_REGISTRY[args.server]
    server_kwargs = {"config_path": args.config} if args.server == "dirsrv" else {}

    if connection_override:
        server_kwargs["servers"] = [connection_override]

    server = server_class(**server_kwargs)  # type: ignore[arg-type]

    if args.transport == "http":
        server.run(transport="http", host=args.listen_host, port=args.listen_port)
    else:
        server.run()


if __name__ == "__main__":
    main()

