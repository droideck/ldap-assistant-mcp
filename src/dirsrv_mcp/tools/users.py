"""User management tools for 389 Directory Server."""

from __future__ import annotations

import json
import re
from typing import TYPE_CHECKING, Annotated, Any, Dict, Iterable, List, Optional

from pydantic import Field

from ldap.filter import escape_filter_chars
from lib389.idm.account import Accounts
from lib389.idm.user import nsUserAccounts

from fastmcp.exceptions import ToolError
from mcp.types import ToolAnnotations


from src.lib.datetime_utils import convert_datetimes_to_strings
from src.lib.privacy import create_count_only_response, create_privacy_error

if TYPE_CHECKING:
    from src.dirsrv_mcp.server import DirSrvMCP

_RO = ToolAnnotations(readOnlyHint=True, idempotentHint=True, destructiveHint=False, openWorldHint=True)


def register_user_tools(mcp: DirSrvMCP) -> None:
    """Register user management tools with the MCP server."""

    @mcp.tool(annotations=_RO, tags={"users", "live"})
    def list_all_users(limit: Annotated[int, Field(ge=1, le=10000, description="Max entries to return")] = 50, server_name: Optional[str] = None) -> Dict[str, Any]:
        """List users in the directory with computed status.

        Note: In privacy mode (default), returns count only.
        Set LDAP_MCP_EXPOSE_SENSITIVE_DATA=true for full user details.
        """
        target = server_name or mcp.default_server
        mcp.require_live(target,"list_all_users")
        with mcp._connection(target) as (name, ds):
            base_dn = mcp._get_base_dn(name)
            users = nsUserAccounts(ds, base_dn)

            # In privacy mode, return count only
            if mcp.privacy_enabled:
                count = sum(1 for _ in users.list())
                return create_count_only_response("user_list", name, count, mcp.sanitizer)

            results = _collect_entries(mcp, users.list(), ds, base_dn, limit)
            return {
                "type": "user_list",
                "server": name,
                "total_returned": len(results),
                "limit_applied": limit,
                "items": results,
            }

    @mcp.tool(annotations=_RO, tags={"users", "live"})
    def search_users_by_name(
        name: str, limit: Annotated[int, Field(ge=1, le=10000, description="Max entries to return")] = 50, server_name: Optional[str] = None
    ) -> Dict[str, Any]:
        """Search for users by name (uid, cn, givenName, sn, displayName, mail).

        Note: In privacy mode (default), returns count only.
        Set LDAP_MCP_EXPOSE_SENSITIVE_DATA=true for full user details.
        """
        target = server_name or mcp.default_server
        mcp.require_live(target,"search_users_by_name")
        with mcp._connection(target) as (srv, ds):
            base_dn = mcp._get_base_dn(srv)
            if "*" in name:
                # Escape segments between wildcards, preserve '*' for LDAP
                parts = name.split("*")
                safe_name = "*".join(escape_filter_chars(p) for p in parts)
                search_filter = (
                    f"(|(uid={safe_name})(cn={safe_name})(givenName={safe_name})(sn={safe_name})"
                    f"(displayName={safe_name})(mail={safe_name}))"
                )
            else:
                safe_name = escape_filter_chars(name)
                search_filter = (
                    f"(|(uid=*{safe_name}*)(cn=*{safe_name}*)(givenName=*{safe_name}*)(sn=*{safe_name}*)"
                    f"(displayName=*{safe_name}*)(mail=*{safe_name}*))"
                )
            users = nsUserAccounts(ds, base_dn)

            # In privacy mode, return count only
            if mcp.privacy_enabled:
                count = sum(1 for _ in users.filter(search_filter))
                return create_count_only_response("user_search", srv, count, mcp.sanitizer)

            results = _collect_entries(mcp, users.filter(search_filter), ds, base_dn, limit)
            return {
                "type": "user_search",
                "server": srv,
                "search_term": name,
                "filter_used": search_filter,
                "total_returned": len(results),
                "limit_applied": limit,
                "items": results,
            }

    @mcp.tool(annotations=_RO, tags={"users", "live"})
    def get_user_details(username: str, server_name: Optional[str] = None) -> Dict[str, Any]:
        """Get detailed information about a specific user.

        Note: This tool is disabled in privacy mode (default).
        Set LDAP_MCP_EXPOSE_SENSITIVE_DATA=true to enable.
        """
        # Disabled in privacy mode
        if mcp.privacy_enabled:
            return create_privacy_error("get_user_details")

        target = server_name or mcp.default_server
        mcp.require_live(target,"get_user_details")
        with mcp._connection(target) as (srv, ds):
            base_dn = mcp._get_base_dn(srv)
            users = nsUserAccounts(ds, base_dn)
            user = users.get(username)
            record = _build_user_record(mcp, user, ds, base_dn)
            return {"type": "user_details", "server": srv, "username": username, "user": record}

    @mcp.tool(annotations=_RO, tags={"users", "live"})
    def list_active_users(limit: Annotated[int, Field(ge=1, le=10000, description="Max entries to return")] = 50, server_name: Optional[str] = None) -> Dict[str, Any]:
        """List active (unlocked) users.

        Note: In privacy mode (default), returns count only.
        Set LDAP_MCP_EXPOSE_SENSITIVE_DATA=true for full user details.
        """
        target = server_name or mcp.default_server
        mcp.require_live(target,"list_active_users")
        with mcp._connection(target) as (srv, ds):
            base_dn = mcp._get_base_dn(srv)
            users = nsUserAccounts(ds, base_dn)

            # In privacy mode, count active users only
            if mcp.privacy_enabled:
                count = 0
                for entry in users.list():
                    try:
                        record = _build_user_record(mcp, entry, ds, base_dn)
                        if record["attrs"].get("computed_status", {}).get("simple_status") == "active":
                            count += 1
                    except Exception:
                        continue
                return create_count_only_response("active_users", srv, count, mcp.sanitizer)

            records = _collect_filtered_users(
                mcp, users.list(), ds, base_dn, limit, desired_status="active"
            )
            return {
                "type": "active_users",
                "server": srv,
                "active_users_found": len(records),
                "limit_applied": limit,
                "items": records,
            }

    @mcp.tool(annotations=_RO, tags={"users", "live"})
    def list_locked_users(limit: Annotated[int, Field(ge=1, le=10000, description="Max entries to return")] = 50, server_name: Optional[str] = None) -> Dict[str, Any]:
        """List locked users.

        Note: In privacy mode (default), returns count only.
        Set LDAP_MCP_EXPOSE_SENSITIVE_DATA=true for full user details.
        """
        target = server_name or mcp.default_server
        mcp.require_live(target,"list_locked_users")
        with mcp._connection(target) as (srv, ds):
            base_dn = mcp._get_base_dn(srv)
            users = nsUserAccounts(ds, base_dn)

            # In privacy mode, count locked users only
            if mcp.privacy_enabled:
                count = 0
                for entry in users.list():
                    try:
                        record = _build_user_record(mcp, entry, ds, base_dn)
                        if record["attrs"].get("computed_status", {}).get("simple_status") == "locked":
                            count += 1
                    except Exception:
                        continue
                return create_count_only_response("locked_users", srv, count, mcp.sanitizer)

            records = _collect_filtered_users(
                mcp, users.list(), ds, base_dn, limit, desired_status="locked"
            )
            return {
                "type": "locked_users",
                "server": srv,
                "locked_users_found": len(records),
                "limit_applied": limit,
                "items": records,
            }

    @mcp.tool(annotations=_RO, tags={"users", "live"})
    def search_users_by_attribute(
        attribute: str, value: str, limit: Annotated[int, Field(ge=1, le=10000, description="Max entries to return")] = 50, server_name: Optional[str] = None
    ) -> Dict[str, Any]:
        """Search for users by arbitrary attribute.

        Note: In privacy mode (default), returns count only.
        Set LDAP_MCP_EXPOSE_SENSITIVE_DATA=true for full user details.
        """
        target = server_name or mcp.default_server
        mcp.require_live(target,"search_users_by_attribute")
        with mcp._connection(target) as (srv, ds):
            base_dn = mcp._get_base_dn(srv)
            if not re.match(r'^[a-zA-Z][a-zA-Z0-9-]*$', attribute):
                raise ToolError(f"Invalid attribute name: {attribute!r}")
            if "*" in value:
                parts = value.split("*")
                safe_value = "*".join(escape_filter_chars(p) for p in parts)
                search_filter = f"({attribute}={safe_value})"
            else:
                safe_value = escape_filter_chars(value)
                search_filter = f"({attribute}=*{safe_value}*)"
            users = nsUserAccounts(ds, base_dn)

            # In privacy mode, return count only
            if mcp.privacy_enabled:
                count = sum(1 for _ in users.filter(search_filter))
                return create_count_only_response("attribute_search", srv, count, mcp.sanitizer)

            results = _collect_entries(mcp, users.filter(search_filter), ds, base_dn, limit)
            return {
                "type": "attribute_search",
                "server": srv,
                "attribute": attribute,
                "value": value,
                "filter_used": search_filter,
                "total_returned": len(results),
                "limit_applied": limit,
                "items": results,
            }


def _collect_entries(
    mcp: DirSrvMCP,
    entries: Iterable[Any],
    ds,
    base_dn: str,
    limit: int,
    include_all: bool = False,
) -> List[Dict[str, Any]]:
    """Collect and format user entries from the directory."""
    results: List[Dict[str, Any]] = []
    count = 0
    for entry in entries:
        if not include_all and count >= limit:
            break
        try:
            record = _build_user_record(mcp, entry, ds, base_dn)
            results.append(record)
            count += 1
        except Exception as exc:
            mcp.logger.error("Error processing entry: %s", exc)
            continue
    return results


def _build_user_record(mcp: DirSrvMCP, entry, ds, base_dn: str) -> Dict[str, Any]:
    """Build a user record with computed status."""
    data = json.loads(entry.get_all_attrs_json())
    if "attrs" in data and isinstance(data["attrs"], dict):
        data["attrs"] = convert_datetimes_to_strings(data["attrs"])
    else:
        data["attrs"] = {}

    user_dn = data.get("dn", "")
    data["attrs"]["computed_status"] = _get_user_status(mcp, ds, user_dn, base_dn)
    return data


def _collect_filtered_users(
    mcp: DirSrvMCP,
    entries: Iterable[Any],
    ds,
    base_dn: str,
    limit: int,
    *,
    desired_status: str,
) -> List[Dict[str, Any]]:
    """Collect users matching a specific status."""
    records: List[Dict[str, Any]] = []
    for entry in entries:
        if len(records) >= limit:
            break
        try:
            record = _build_user_record(mcp, entry, ds, base_dn)
        except Exception as exc:
            mcp.logger.error("Error processing entry: %s", exc)
            continue
        status = record["attrs"].get("computed_status", {}).get("simple_status")
        if status == desired_status:
            records.append(record)
    return records


def _get_user_status(mcp: DirSrvMCP, ds, user_dn: str, basedn: str) -> Dict[str, Any]:
    """Get computed status for a user account."""
    try:
        accounts = Accounts(ds, basedn)
        acct = accounts.get(dn=user_dn)
        status_data = acct.status()
        account_state = status_data.get("state", "unknown")
        params = convert_datetimes_to_strings(status_data.get("params", {}))
        calc_time = status_data.get("calc_time")
        calc_time_str = calc_time.isoformat() if hasattr(calc_time, "isoformat") else calc_time

        state_name = (
            account_state.name
            if hasattr(account_state, "name")
            else account_state.value
            if hasattr(account_state, "value")
            else str(account_state)
        )

        if state_name in {"DIRECTLY_LOCKED", "INDIRECTLY_LOCKED"}:
            simple_status = "locked"
        elif state_name == "INACTIVITY_LIMIT_EXCEEDED":
            simple_status = "inactive"
        elif state_name == "ACTIVATED":
            simple_status = "active"
        else:
            simple_status = "unknown"

        return {
            "simple_status": simple_status,
            "detailed_status": state_name,
            "status_params": params,
            "calc_time": calc_time_str,
        }
    except Exception as exc:
        mcp.logger.warning("Error getting status for %s: %s", user_dn, exc)
        return {
            "simple_status": "unknown",
            "detailed_status": f"error: {exc}",
            "status_params": {},
            "calc_time": None,
        }
