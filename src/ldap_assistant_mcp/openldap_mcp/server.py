from __future__ import annotations

import logging
from typing import Any, Dict, Iterable, Optional

import ldap
from fastmcp.exceptions import ToolError
from mcp.types import ToolAnnotations

from ldap_assistant_mcp.core import LDAPAssistantMCP, LDAPAuthMethod, LDAPServerConfig

__all__ = ["OpenLDAPMCP"]

_RO = ToolAnnotations(readOnlyHint=True, idempotentHint=True, destructiveHint=False, openWorldHint=True)


class OpenLDAPMCP(LDAPAssistantMCP):
    """Lightweight MCP server for interacting with OpenLDAP directories."""

    def __init__(
        self,
        *,
        servers: Optional[Iterable[LDAPServerConfig]] = None,
        name: str = "OpenLDAP MCP",
        instructions: Optional[str] = None,
        **kwargs: Any,
    ) -> None:
        self.logger = logging.getLogger(
            f"ldap_assistant_mcp.{self.__class__.__name__}"
        )
        super().__init__(name=name, instructions=instructions, servers=servers or None, **kwargs)
        self.logger.warning(
            "The OpenLDAP provider is EXPERIMENTAL: it exposes only two tools "
            "and bypasses the privacy sanitizer and middleware used by the "
            "389 DS provider. Do not point it at directories with sensitive data."
        )
        self._register_tools()

    def _register_tools(self) -> None:
        """Register OpenLDAP-specific tools."""

        @self.tool(annotations=_RO, tags={"servers", "live"})
        def describe_connection(server_name: Optional[str] = None) -> Dict[str, Any]:
            """Show the stored connection settings (hostname, port, SSL, base DN, auth method) for a configured OpenLDAP server.

            Reads configuration only — does not contact the server. Uses the
            default server when ``server_name`` is omitted.

            Returns:
                Dict with name, hostname, port, use_ssl, base_dn,
                auth_method, and provider_type.
            """
            config = self.get_server_config(server_name)
            return {
                "name": config.name,
                "hostname": config.hostname,
                "port": config.port,
                "use_ssl": config.use_ssl,
                "base_dn": config.base_dn,
                "auth_method": config.auth_method.value,
                "provider_type": config.provider_type,
            }

        @self.tool(annotations=_RO, tags={"servers", "live"})
        def whoami(server_name: Optional[str] = None) -> Dict[str, Any]:
            """Verify credentials by binding to the OpenLDAP server and returning the authenticated identity (LDAP Who Am I).

            Performs a live bind; supports simple and SASL EXTERNAL auth only
            (other methods raise an error). Uses the default server when
            ``server_name`` is omitted.

            Returns:
                Dict with server, identity (e.g. ``dn:uid=...``), and base_dn.
            """
            config = self.get_server_config(server_name)
            conn = None
            try:
                conn = self._ldap_bind(config)
                identity = conn.whoami_s()
                return {
                    "server": config.name,
                    "identity": identity,
                    "base_dn": config.base_dn,
                }
            except ldap.LDAPError as exc:
                self.logger.error("whoami failed on %s: %s", config.name, exc)
                raise ToolError(f"OpenLDAP whoami failed: {exc}") from exc
            finally:
                if conn is not None:
                    try:
                        conn.unbind_s()
                    except Exception:
                        pass

    def _ldap_bind(self, config: LDAPServerConfig):
        """Create and return a bound LDAP connection for *config*."""
        if config.auth_method not in {LDAPAuthMethod.SIMPLE, LDAPAuthMethod.SASL_EXTERNAL}:
            raise ToolError(
                f"Auth method '{config.auth_method.value}' is not supported for OpenLDAP bindings yet"
            )

        conn = ldap.initialize(config.ldap_url)
        conn.set_option(ldap.OPT_NETWORK_TIMEOUT, 10.0)

        if config.use_ssl:
            conn.set_option(ldap.OPT_X_TLS_REQUIRE_CERT, ldap.OPT_X_TLS_ALLOW)
            conn.set_option(ldap.OPT_X_TLS_NEWCTX, 0)

        if config.auth_method == LDAPAuthMethod.SASL_EXTERNAL:
            conn.sasl_non_interactive_bind_s("EXTERNAL")
        else:
            conn.simple_bind_s(config.bind_dn or "", config.bind_password or "")

        return conn

