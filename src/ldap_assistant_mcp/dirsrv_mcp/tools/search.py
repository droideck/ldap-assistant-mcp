"""Generic LDAP search tools for 389 Directory Server."""

from __future__ import annotations

import base64
from typing import TYPE_CHECKING, Annotated, Any, Dict, List, Optional

from pydantic import Field

import ldap
from fastmcp.exceptions import ToolError

from mcp.types import ToolAnnotations


from ldap_assistant_mcp.lib.privacy import ALWAYS_REDACT_ATTRIBUTES, create_privacy_error

if TYPE_CHECKING:
    from ldap_assistant_mcp.dirsrv_mcp.server import DirSrvMCP

_RO = ToolAnnotations(readOnlyHint=True, idempotentHint=True, destructiveHint=False, openWorldHint=True)


def register_search_tools(mcp: DirSrvMCP) -> None:
    """Register generic LDAP search tools with the MCP server."""

    @mcp.tool(annotations=_RO, tags={"search", "live"})
    def ldap_search(
        base_dn: Annotated[str, Field(min_length=1, description="Base DN to search from, e.g. 'dc=example,dc=com'")],
        scope: Annotated[str, Field(description="Search scope: BASE (entry only), ONELEVEL (direct children), or SUBTREE (entire subtree)")] = "SUBTREE",
        filter: Annotated[str, Field(description="LDAP filter in RFC 4515 syntax, e.g. '(uid=jdoe)'")] = "(objectClass=*)",
        attributes: Annotated[Optional[str], Field(description="Comma-separated attribute list; '*' = all user attributes, '+' = operational attributes; omit for all")] = None,
        attrs_only: Annotated[bool, Field(description="Return attribute names only, without values")] = False,
        limit: Annotated[int, Field(ge=1, le=1000, description="Max entries to return (hard cap 1000)")] = 100,
        server_name: Annotated[Optional[str], Field(description="Target server name (default: the default server)")] = None,
    ) -> Dict[str, Any]:
        """Run an arbitrary LDAP search (any base DN, scope, and filter) when no specialized tool fits.

        Prefer the purpose-built tools (user/group/config/replication) first;
        use this as the escape hatch for advanced queries.

        Requires a LIVE server (fails with LiveServerRequired on offline/archive servers).
        Disabled in privacy mode (default) as it can retrieve arbitrary
        directory data; set LDAP_MCP_EXPOSE_SENSITIVE_DATA=true to enable.

        Returns:
            Dict with ``items`` (list of {dn, attrs}; non-UTF-8 values are
            base64-encoded), ``total_returned``, ``limit_applied``, and
            ``truncated`` (True when the server stopped at the limit and
            more entries exist).
        """
        # Disabled in privacy mode - can retrieve any data
        if mcp.privacy_enabled:
            return create_privacy_error("ldap_search")
        target = str(server_name) if server_name is not None else mcp.default_server
        mcp.require_live(target,"ldap_search")
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

                # Ask the server to stop at the cap (sizelimit) instead of
                # pulling the whole subtree and truncating client-side.
                # Entries are collected asynchronously so the partial result
                # set survives SIZELIMIT_EXCEEDED (which search_ext_s would
                # discard) — the response then carries truncated=True.
                truncated = False
                search_results = []
                try:
                    msgid = ds.search_ext(
                        base_dn_value,
                        scope_map[original_scope],
                        filter_value,
                        attrlist=attrlist,
                        attrsonly=1 if attrs_only_flag else 0,
                        sizelimit=capped_limit,
                    )
                    while True:
                        rtype, rdata = ds.result(msgid, all=0)
                        if rtype == ldap.RES_SEARCH_ENTRY:
                            search_results.extend(rdata)
                        else:
                            break
                except ldap.SIZELIMIT_EXCEEDED:
                    truncated = True
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
                        # Credential hashes are never diagnostically useful —
                        # strip them unconditionally, in both privacy modes.
                        if str(attr_name).lower() in ALWAYS_REDACT_ATTRIBUTES:
                            continue
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
                    "truncated": truncated,
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

