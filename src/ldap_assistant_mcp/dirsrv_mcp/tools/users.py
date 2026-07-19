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


from ldap_assistant_mcp.lib.datetime_utils import convert_datetimes_to_strings
from ldap_assistant_mcp.lib.pagination import decode_cursor, paginate
from ldap_assistant_mcp.lib.privacy import (
    bucket_count,
    create_count_only_response,
    create_privacy_error,
    strip_credential_attributes,
)

if TYPE_CHECKING:
    from ldap_assistant_mcp.dirsrv_mcp.server import DirSrvMCP

_RO = ToolAnnotations(readOnlyHint=True, idempotentHint=True, destructiveHint=False, openWorldHint=True)

# Hard cap on entries examined by the per-user status scans (each user costs
# an extra LDAP round-trip).  Results carry ``scan_capped`` when hit so a
# partial answer is never mistaken for a complete one.
_MAX_STATUS_SCAN = 1000


def _normalize_search_term(value: str, param: str) -> str:
    """Validate and normalize a user-supplied search term.

    Whitespace-only and wildcard-only terms would build filters like
    ``(uid=**)`` — invalid LDAP that surfaces as an opaque masked error.
    Reject them with a clear message and collapse repeated wildcards.
    """
    value = value.strip()
    if not value.strip("*"):
        raise ToolError(
            f"Parameter '{param}' must contain at least one "
            "non-wildcard, non-whitespace character."
        )
    return re.sub(r"\*{2,}", "*", value)


def register_user_tools(mcp: DirSrvMCP) -> None:
    """Register user management tools with the MCP server."""

    @mcp.tool(annotations=_RO, tags={"users", "live"})
    def list_all_users(
        limit: Annotated[int, Field(ge=1, le=10000, description="Max entries to return")] = 50,
        cursor: Annotated[Optional[str], Field(description="Opaque pagination cursor from a previous page's next_cursor")] = None,
        server_name: Annotated[Optional[str], Field(description="Target server name (default: the default server)")] = None,
    ) -> Dict[str, Any]:
        """List all user accounts regardless of status, with computed lock/active status per user.

        Use ``list_active_users`` / ``list_locked_users`` to filter by status instead.
        Results are paginated: when ``has_more`` is true, pass ``next_cursor``
        back as ``cursor`` to fetch the next page.

        Requires a LIVE server (fails with LiveServerRequired on offline/archive servers).
        In privacy mode (default), returns a count only; set
        LDAP_MCP_EXPOSE_SENSITIVE_DATA=true for full user details.

        Returns:
            Dict with ``items`` (user records with attrs + computed_status),
            ``total_returned``, ``limit_applied``, ``has_more``, ``next_cursor``.
        """
        target = server_name or mcp.default_server
        mcp.require_live(target,"list_all_users")
        offset = decode_cursor(cursor)
        with mcp._connection(target) as (name, ds):
            base_dn = mcp._get_base_dn(name)
            users = nsUserAccounts(ds, base_dn)

            # In privacy mode, return count only
            if mcp.privacy_enabled:
                count = sum(1 for _ in users.list())
                return create_count_only_response("user_list", name, count, mcp.sanitizer)

            page, has_more, next_cursor = paginate(users.list(), offset, limit)
            results = _collect_entries(mcp, page, ds, base_dn, limit, include_all=True)
            return {
                "type": "user_list",
                "server": name,
                "total_returned": len(results),
                "limit_applied": limit,
                "has_more": has_more,
                "next_cursor": next_cursor,
                "items": results,
            }

    @mcp.tool(annotations=_RO, tags={"users", "live"})
    def search_users_by_name(
        name: Annotated[str, Field(min_length=1, description="Name to search for; matched as substring unless it contains '*', which is honored as an LDAP wildcard")],
        limit: Annotated[int, Field(ge=1, le=10000, description="Max entries to return")] = 50,
        server_name: Annotated[Optional[str], Field(description="Target server name (default: the default server)")] = None,
    ) -> Dict[str, Any]:
        """Search users by name substring or '*' wildcard across uid, cn, givenName, sn, displayName, and mail.

        Requires a LIVE server (fails with LiveServerRequired on offline/archive servers).
        In privacy mode (default), returns a count only; set
        LDAP_MCP_EXPOSE_SENSITIVE_DATA=true for full user details.

        Returns:
            Dict with ``items``, ``filter_used``, ``total_returned``, ``limit_applied``.
        """
        target = server_name or mcp.default_server
        mcp.require_live(target,"search_users_by_name")
        name = _normalize_search_term(name, "name")
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

            # In privacy mode, return a coarse count bucket only: exact
            # counts for attacker-controlled substring/wildcard filters are
            # a count oracle that can extract values character by character.
            if mcp.privacy_enabled:
                count = sum(1 for _ in users.filter(search_filter))
                response = create_count_only_response("user_search", srv, count, mcp.sanitizer)
                bucket = bucket_count(count)
                response["count"] = bucket
                response["message"] = (
                    f"Found {bucket} entries. Enable expose_sensitive_data for details."
                )
                return response

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
    def get_user_details(
        username: Annotated[str, Field(min_length=1, description="The user's uid (RDN value), e.g. 'jdoe' — not a full DN")],
        server_name: Annotated[Optional[str], Field(description="Target server name (default: the default server)")] = None,
    ) -> Dict[str, Any]:
        """Get full attributes plus computed lock/expiry status for one user, looked up by uid.

        Requires a LIVE server. This tool is disabled entirely in privacy
        mode (default); set LDAP_MCP_EXPOSE_SENSITIVE_DATA=true to enable.

        Returns:
            Dict with ``user`` (all attributes plus computed_status with
            lock state, policy params, and calculation time).
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
    def list_active_users(
        limit: Annotated[int, Field(ge=1, le=10000, description="Max entries to return")] = 50,
        server_name: Annotated[Optional[str], Field(description="Target server name (default: the default server)")] = None,
    ) -> Dict[str, Any]:
        """List only users whose computed account status is active (not locked or inactivity-expired).

        Requires a LIVE server (fails with LiveServerRequired on offline/archive servers).
        In privacy mode (default), returns a count only; set
        LDAP_MCP_EXPOSE_SENSITIVE_DATA=true for full user details.

        Returns:
            Dict with ``items``, ``active_users_found``, ``limit_applied``.
        """
        target = server_name or mcp.default_server
        mcp.require_live(target,"list_active_users")
        with mcp._connection(target) as (srv, ds):
            base_dn = mcp._get_base_dn(srv)
            users = nsUserAccounts(ds, base_dn)

            # In privacy mode, count active users only
            if mcp.privacy_enabled:
                count, scanned, capped = _count_users_with_status(
                    mcp, users.list(), ds, base_dn, desired_status="active"
                )
                result = create_count_only_response("active_users", srv, count, mcp.sanitizer)
                result["users_scanned"] = scanned
                result["scan_capped"] = capped
                return result

            records, scanned, capped = _collect_filtered_users(
                mcp, users.list(), ds, base_dn, limit, desired_status="active"
            )
            return {
                "type": "active_users",
                "server": srv,
                "active_users_found": len(records),
                "limit_applied": limit,
                "users_scanned": scanned,
                "scan_capped": capped,
                "items": records,
            }

    @mcp.tool(annotations=_RO, tags={"users", "live"})
    def list_locked_users(
        limit: Annotated[int, Field(ge=1, le=10000, description="Max entries to return")] = 50,
        server_name: Annotated[Optional[str], Field(description="Target server name (default: the default server)")] = None,
    ) -> Dict[str, Any]:
        """List users whose accounts are locked, whether directly or indirectly (account policy / inactivity).

        Requires a LIVE server (fails with LiveServerRequired on offline/archive servers).
        In privacy mode (default), returns a count only; set
        LDAP_MCP_EXPOSE_SENSITIVE_DATA=true for full user details.

        Returns:
            Dict with ``items`` (including lock reason in computed_status),
            ``locked_users_found``, ``limit_applied``.
        """
        target = server_name or mcp.default_server
        mcp.require_live(target,"list_locked_users")
        with mcp._connection(target) as (srv, ds):
            base_dn = mcp._get_base_dn(srv)
            users = nsUserAccounts(ds, base_dn)

            # In privacy mode, count locked users only
            if mcp.privacy_enabled:
                count, scanned, capped = _count_users_with_status(
                    mcp, users.list(), ds, base_dn, desired_status="locked"
                )
                result = create_count_only_response("locked_users", srv, count, mcp.sanitizer)
                result["users_scanned"] = scanned
                result["scan_capped"] = capped
                return result

            records, scanned, capped = _collect_filtered_users(
                mcp, users.list(), ds, base_dn, limit, desired_status="locked"
            )
            return {
                "type": "locked_users",
                "server": srv,
                "locked_users_found": len(records),
                "limit_applied": limit,
                "users_scanned": scanned,
                "scan_capped": capped,
                "items": records,
            }

    @mcp.tool(annotations=_RO, tags={"users", "live"})
    def search_users_by_attribute(
        attribute: Annotated[str, Field(pattern=r"^[a-zA-Z][a-zA-Z0-9-]*$", description="LDAP attribute name (letters, digits, hyphens; must start with a letter), e.g. 'departmentNumber' or 'mail'")],
        value: Annotated[str, Field(min_length=1, description="Value to match; matched as substring unless it contains '*', which is honored as an LDAP wildcard")],
        limit: Annotated[int, Field(ge=1, le=10000, description="Max entries to return")] = 50,
        server_name: Annotated[Optional[str], Field(description="Target server name (default: the default server)")] = None,
    ) -> Dict[str, Any]:
        """Search users by any single attribute=value match (e.g. departmentNumber, title, mail domain).

        Requires a LIVE server (fails with LiveServerRequired on offline/archive servers).
        Disabled in privacy mode (default) as arbitrary substring filters
        with exact match counts can be used to extract attribute values
        character-by-character; set LDAP_MCP_EXPOSE_SENSITIVE_DATA=true to enable.

        Returns:
            Dict with ``items``, ``filter_used``, ``total_returned``, ``limit_applied``.
        """
        # Disabled in privacy mode - substring filters + exact counts form
        # a count-oracle that lets attribute values be extracted
        if mcp.privacy_enabled:
            return create_privacy_error("search_users_by_attribute")

        target = server_name or mcp.default_server
        mcp.require_live(target,"search_users_by_attribute")
        value = _normalize_search_term(value, "value")
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
        # Credential hashes are never diagnostically useful — strip them
        # unconditionally, in both privacy and sensitive-data modes.
        data["attrs"] = strip_credential_attributes(
            convert_datetimes_to_strings(data["attrs"])
        )
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
) -> tuple:
    """Collect users matching a specific status.

    Computing a user's status costs an extra LDAP round-trip per entry, so
    the scan is capped at ``_MAX_STATUS_SCAN`` entries.  Returns
    ``(records, scanned, capped)`` — when *capped* is True the result
    covers only the first ``scanned`` users, not the whole directory.
    """
    records: List[Dict[str, Any]] = []
    scanned = 0
    capped = False
    for entry in entries:
        if len(records) >= limit:
            break
        if scanned >= _MAX_STATUS_SCAN:
            capped = True
            break
        scanned += 1
        try:
            record = _build_user_record(mcp, entry, ds, base_dn)
        except Exception as exc:
            mcp.logger.error("Error processing entry: %s", exc)
            continue
        status = record["attrs"].get("computed_status", {}).get("simple_status")
        if status == desired_status:
            records.append(record)
    return records, scanned, capped


def _count_users_with_status(
    mcp: DirSrvMCP,
    entries: Iterable[Any],
    ds,
    base_dn: str,
    *,
    desired_status: str,
) -> tuple:
    """Count users matching a status, capped at ``_MAX_STATUS_SCAN`` scans.

    Returns ``(count, scanned, capped)``.
    """
    count = 0
    scanned = 0
    capped = False
    for entry in entries:
        if scanned >= _MAX_STATUS_SCAN:
            capped = True
            break
        scanned += 1
        try:
            record = _build_user_record(mcp, entry, ds, base_dn)
        except Exception:
            continue
        if record["attrs"].get("computed_status", {}).get("simple_status") == desired_status:
            count += 1
    return count, scanned, capped


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
