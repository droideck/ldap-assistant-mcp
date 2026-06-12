"""Group management tools for 389 Directory Server."""

from __future__ import annotations

import json
from typing import TYPE_CHECKING, Annotated, Any, Dict, Optional

from pydantic import Field

from lib389.idm.group import Groups

from mcp.types import ToolAnnotations


from ldap_assistant_mcp.lib.datetime_utils import convert_datetimes_to_strings
from ldap_assistant_mcp.lib.privacy import create_count_only_response, strip_credential_attributes

if TYPE_CHECKING:
    from ldap_assistant_mcp.dirsrv_mcp.server import DirSrvMCP

_RO = ToolAnnotations(readOnlyHint=True, idempotentHint=True, destructiveHint=False, openWorldHint=True)


def register_group_tools(mcp: DirSrvMCP) -> None:
    """Register group management tools with the MCP server."""

    @mcp.tool(annotations=_RO, tags={"groups", "live"})
    def list_all_groups(
        limit: Annotated[int, Field(ge=1, le=10000, description="Max entries to return")] = 50,
        server_name: Annotated[Optional[str], Field(description="Target server name (default: the default server)")] = None,
    ) -> Dict[str, Any]:
        """List directory groups with their full attributes, including membership (member/uniqueMember).

        Requires a LIVE server (fails with LiveServerRequired on offline/archive servers).
        In privacy mode (default), returns a count only; set
        LDAP_MCP_EXPOSE_SENSITIVE_DATA=true for full group details.

        Returns:
            Dict with ``items`` (group entries with DN and attrs),
            ``total_returned``, and ``limit_applied``.
        """
        target = server_name or mcp.default_server
        mcp.require_live(target,"list_all_groups")
        with mcp._connection(target) as (srv, ds):
            base_dn = mcp._get_base_dn(srv)
            groups = Groups(ds, base_dn)

            # In privacy mode, return count only
            if mcp.privacy_enabled:
                count = sum(1 for _ in groups.list())
                return create_count_only_response("group_list", srv, count, mcp.sanitizer)

            results = []
            count = 0
            for group in groups.list():
                if count >= limit:
                    break
                try:
                    group_data = json.loads(group.get_all_attrs_json())
                    if "attrs" in group_data:
                        # Credential hashes are never diagnostically useful —
                        # strip them unconditionally, in both privacy modes.
                        group_data["attrs"] = strip_credential_attributes(
                            convert_datetimes_to_strings(group_data["attrs"])
                        )
                    results.append(group_data)
                    count += 1
                except Exception as exc:
                    mcp.logger.error("Error processing group: %s", exc)
                    continue

            return {
                "type": "group_list",
                "server": srv,
                "total_returned": len(results),
                "limit_applied": limit,
                "items": results,
            }
