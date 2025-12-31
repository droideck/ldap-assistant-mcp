"""Group management tools for 389 Directory Server."""

from __future__ import annotations

import json
from typing import TYPE_CHECKING, Any, Dict, Optional

from lib389.idm.group import Groups

from src.lib.datetime_utils import convert_datetimes_to_strings
from src.lib.privacy import create_count_only_response

if TYPE_CHECKING:
    from src.dirsrv_mcp.server import DirSrvMCP


def register_group_tools(mcp: DirSrvMCP) -> None:
    """Register group management tools with the MCP server."""

    @mcp.tool()
    def list_all_groups(limit: int = 50, server_name: Optional[str] = None) -> Dict[str, Any]:
        """List directory groups.

        Note: In privacy mode (default), returns count only.
        Set LDAP_MCP_EXPOSE_SENSITIVE_DATA=true for full group details.
        """
        target = server_name or mcp.default_server
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
                        group_data["attrs"] = convert_datetimes_to_strings(group_data["attrs"])
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

