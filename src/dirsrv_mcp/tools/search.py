"""Generic LDAP search tools for 389 Directory Server."""

from __future__ import annotations

import base64
from typing import TYPE_CHECKING, Any, Dict, List, Optional

import ldap
from fastmcp.exceptions import ToolError

from src.dirsrv_mcp.connection import require_live_server
from src.lib.privacy import create_privacy_error

if TYPE_CHECKING:
    from src.dirsrv_mcp.server import DirSrvMCP


def register_search_tools(mcp: DirSrvMCP) -> None:
    """Register generic LDAP search tools with the MCP server."""

    @mcp.tool()
    def ldap_search(
        base_dn: str,
        scope: str = "SUBTREE",
        filter: str = "(objectClass=*)",
        attributes: Optional[str] = None,
        attrs_only: bool = False,
        limit: int = 100,
        server_name: Optional[str] = None,
    ) -> Dict[str, Any]:
        """Perform a generic LDAP search.

        Note: This tool is disabled in privacy mode (default) as it can
        retrieve arbitrary directory data. Set LDAP_MCP_EXPOSE_SENSITIVE_DATA=true
        to enable.
        """
        # Disabled in privacy mode - can retrieve any data
        if mcp.privacy_enabled:
            return create_privacy_error("ldap_search")
        target = str(server_name) if server_name is not None else mcp.default_server
        require_live_server(mcp.connection_manager, target, "ldap_search")
        with mcp._connection(target) as (srv, ds):
            try:
                base_dn_value = str(base_dn)
                filter_value = str(filter)
                original_scope = str(scope).upper()
                attributes_value = None if attributes is None else str(attributes)
                attrs_only_flag = bool(attrs_only)
                limit_value = int(limit)

                scope_map = {
                    "BASE": ldap.SCOPE_BASE,
                    "ONELEVEL": ldap.SCOPE_ONELEVEL,
                    "SUBTREE": ldap.SCOPE_SUBTREE,
                }
                if original_scope not in scope_map:
                    raise ToolError(
                        "Invalid scope. Must be one of: BASE, ONELEVEL, SUBTREE"
                    )

                capped_limit = max(1, min(limit_value, 1000))
                attrlist = None
                if attributes_value:
                    cleaned = attributes_value.strip()
                    if cleaned in {"*", "+", "*,+", "+,*"}:
                        attrlist = cleaned.split(",")
                    else:
                        attrlist = [
                            attr.strip() for attr in cleaned.split(",") if attr.strip()
                        ]

                try:
                    search_results = ds.search_s(
                        base_dn_value,
                        scope_map[original_scope],
                        filter_value,
                        attrlist=attrlist,
                        attrsonly=1 if attrs_only_flag else 0,
                    )
                except ldap.NO_SUCH_OBJECT:
                    raise ToolError(f"Base DN '{base_dn_value}' does not exist") from None
                except ldap.INVALID_SYNTAX as exc:
                    raise ToolError(f"Invalid LDAP filter syntax: {exc}") from exc
                except ldap.LDAPError as exc:
                    raise ToolError(f"LDAP search failed: {exc}") from exc

                results = []
                for item in search_results:
                    if len(results) >= capped_limit:
                        break
                    if isinstance(item, tuple) and len(item) == 2:
                        dn, attrs = item
                    else:
                        dn = getattr(item, "dn", None)
                        attrs = getattr(item, "data", None)
                    if not dn or attrs is None:
                        continue
                    attrs_out: Dict[str, List[str]] = {}
                    attr_items = attrs.items() if hasattr(attrs, "items") else []
                    for attr_name, attr_values in attr_items:
                        values_iter = (
                            attr_values
                            if isinstance(attr_values, (list, tuple))
                            else [attr_values]
                        )
                        converted_values = []
                        for val in values_iter:
                            if isinstance(val, bytes):
                                try:
                                    converted_values.append(val.decode("utf-8"))
                                except UnicodeDecodeError:
                                    converted_values.append(
                                        base64.b64encode(val).decode("ascii")
                                    )
                            else:
                                converted_values.append(str(val))
                        attrs_out[attr_name] = converted_values
                    results.append({"dn": dn, "attrs": attrs_out})

                return {
                    "type": "ldap_search",
                    "server": srv,
                    "base_dn": base_dn_value,
                    "scope": original_scope,
                    "filter": filter_value,
                    "attributes_requested": attributes_value or "all",
                    "attrs_only": attrs_only_flag,
                    "total_returned": len(results),
                    "limit_applied": capped_limit,
                    "items": results,
                }
            except AttributeError as exc:
                mcp.logger.exception(
                    "ldap_search AttributeError (base_dn=%r, scope=%r, filter=%r, "
                    "attributes=%r, attrs_only=%r, limit=%r)",
                    base_dn,
                    scope,
                    filter,
                    attributes,
                    attrs_only,
                    limit,
                )
                raise ToolError(
                    f"Unexpected internal attribute error in ldap_search: {exc}"
                ) from exc

