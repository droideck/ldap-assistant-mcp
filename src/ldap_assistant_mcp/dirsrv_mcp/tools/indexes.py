"""Index analysis tools for 389 Directory Server.

This module provides index configuration analysis including:
- Listing all configured indexes across backends
- Analyzing index configuration against best practices
- Identifying unindexed searches from access logs (local server only)

Note on local vs remote servers:
- list_indexes and analyze_index_configuration work via LDAP for all servers
- find_unindexed_searches requires local server access (is_local=True with serverid)
  to parse access log files
"""

from __future__ import annotations

import re
from datetime import datetime, timedelta, timezone
from typing import TYPE_CHECKING, Annotated, Any, Dict, List, Optional, Set

from pydantic import Field

from fastmcp.exceptions import ToolError

from lib389.backend import Backends
from lib389.index import VLVSearches
from lib389.plugins import MemberOfPlugin

from mcp.types import ToolAnnotations

from ldap_assistant_mcp.dirsrv_mcp.connection import is_archive_server, is_local_server, is_offline_or_archive
from ldap_assistant_mcp.dirsrv_mcp.tools.dse_utils import find_child_dns, get_dse_ldif_path
from ldap_assistant_mcp.dirsrv_mcp.tools.error_utils import format_error_message, format_tool_error
from ldap_assistant_mcp.lib.result_formatter import Severity, format_finding

if TYPE_CHECKING:
    from ldap_assistant_mcp.dirsrv_mcp.server import DirSrvMCP

_RO = ToolAnnotations(readOnlyHint=True, idempotentHint=True, destructiveHint=False, openWorldHint=True)
_RO_LOCAL = ToolAnnotations(readOnlyHint=True, idempotentHint=True, destructiveHint=False, openWorldHint=False)


def _sanitize_index_result(mcp: "DirSrvMCP", result: Dict[str, Any]) -> Dict[str, Any]:
    """Sanitize index result for privacy mode."""
    if not mcp.privacy_enabled:
        return result

    sanitizer = mcp.sanitizer
    sanitized = dict(result)

    # Server names are never sanitized (user-chosen config labels).
    if "error" in sanitized and isinstance(sanitized["error"], str):
        sanitized["error"] = sanitizer.sanitize_text(sanitized["error"])

    if "backends" in sanitized and isinstance(sanitized["backends"], list):
        sanitized["backends"] = [
            _sanitize_backend(sanitizer, b) for b in sanitized["backends"]
        ]

    if "findings" in sanitized and isinstance(sanitized["findings"], list):
        sanitized["findings"] = sanitizer.sanitize_findings(sanitized["findings"])

    if "patterns" in sanitized and isinstance(sanitized["patterns"], list):
        sanitized["patterns"] = [
            _sanitize_pattern(sanitizer, p) for p in sanitized["patterns"]
        ]

    if "backends_scanned" in sanitized and isinstance(sanitized["backends_scanned"], list):
        sanitized["backends_scanned"] = ["[backend]" for _ in sanitized["backends_scanned"]]

    if "backends_failed" in sanitized and isinstance(sanitized["backends_failed"], list):
        sanitized["backends_failed"] = [
            {
                **b,
                "backend": "[backend]",
                "error": sanitizer.sanitize_text(b.get("error", "")),
            }
            if isinstance(b, dict)
            else b
            for b in sanitized["backends_failed"]
        ]

    if "requested_backend" in sanitized and isinstance(sanitized["requested_backend"], str):
        sanitized["requested_backend"] = "[backend]"

    return sanitized


def _sanitize_backend(sanitizer, backend: Dict[str, Any]) -> Dict[str, Any]:
    """Sanitize a backend entry in index results."""
    result = {}
    for key, value in backend.items():
        if key == "name":
            result[key] = "[backend]"
        elif key == "suffix":
            result[key] = sanitizer.sanitize_suffix(value)
        elif key == "vlv_indexes" and isinstance(value, list):
            result[key] = [
                {
                    **vlv,
                    "name": "[vlv]",
                    "base": sanitizer.sanitize_dn(vlv.get("base")),
                    "filter": "[filter]",
                }
                for vlv in value
            ]
        elif key in ("indexes", "missing_recommended", "incomplete_indexes") and isinstance(value, list):
            # Attribute names, index types, and dsconf command templates are
            # schema-level data, not directory content
            result[key] = value
        elif key == "indexes_error" and isinstance(value, str):
            result[key] = sanitizer.sanitize_text(value)
        elif value is None or isinstance(value, (bool, int, float)):
            # Numbers/bools cannot carry identifiers (diagnostic counts)
            result[key] = value
        else:
            # Deny-by-default: a key this allowlist doesn't know about must
            # not pass through raw — redact it until it is explicitly vetted.
            result[key] = "[REDACTED]"
    return result


def _sanitize_pattern(sanitizer, pattern: Dict[str, Any]) -> Dict[str, Any]:
    """Sanitize an unindexed search pattern entry."""
    result = dict(pattern)
    if "base_dn" in result:
        result["base_dn"] = sanitizer.sanitize_dn(result["base_dn"])
    if "example_filter" in result:
        result["example_filter"] = "[filter]"
    return result


RECOMMENDED_INDEXES: Dict[str, List[str]] = {
    "uid": ["eq", "pres", "sub"],
    "cn": ["eq", "pres", "sub"],
    "sn": ["eq", "pres", "sub"],
    "givenName": ["eq", "pres", "sub"],
    "mail": ["eq", "pres", "sub"],
    "displayName": ["eq", "sub"],
    "member": ["eq"],
    "uniqueMember": ["eq"],
    "memberOf": ["eq"],
    "memberUid": ["eq"],
    "objectClass": ["eq", "pres"],
    "entryUUID": ["eq"],
    "nsUniqueId": ["eq"],
    "modifyTimestamp": ["eq"],
    "createTimestamp": ["eq"],
    "telephoneNumber": ["eq", "sub"],
    "employeeNumber": ["eq"],
    "employeeType": ["eq"],
    "uidNumber": ["eq"],
    "gidNumber": ["eq"],
}

# Attributes 389 DS genuinely expects indexed for core operation (part of
# the server's default index set).  Missing one of these is a real deviation
# from the shipped configuration.  Everything else in RECOMMENDED_INDEXES is
# workload-dependent: only worth indexing when the deployment actually
# searches on it.
CORE_INDEX_ATTRIBUTES: Set[str] = {
    "objectclass",
    "uid",
    "cn",
    "sn",
    "givenname",
    "mail",
    "telephonenumber",
    "member",
    "uniquemember",
    "nsuniqueid",
    "entryuuid",
}

# Plugin-maintained attributes: recommending an index only makes sense when
# the maintaining plugin is enabled.
PLUGIN_DEPENDENT_INDEX_ATTRIBUTES: Dict[str, str] = {
    "memberof": "MemberOf Plugin",
}

_WORKLOAD_DEPENDENT_NOTE = (
    "consider only if this attribute is searched in your workload"
)


def _recommendation_risk(requires_reindex: bool = True) -> Dict[str, Any]:
    """Risk metadata attached to every index recommendation.

    Index changes are configuration changes: they add write-path cost and
    (for new indexes/types) require a reindex, so they must be reviewed and
    approved rather than applied verbatim.
    """
    return {
        "risk": "change",
        "requires_reindex": requires_reindex,
        "write_cost": "adds index maintenance on writes",
        "approval_required": True,
    }


def _memberof_plugin_enabled(mcp: "DirSrvMCP", ds, dse) -> Optional[bool]:
    """Best-effort detection of the MemberOf plugin state.

    Returns True/False when the state could be read, None when unknown
    (detection failure must never masquerade as a definitive answer).
    """
    try:
        if dse is not None:
            val = dse.get(
                "cn=MemberOf Plugin,cn=plugins,cn=config",
                "nsslapd-pluginEnabled",
                single=True,
            )
            if isinstance(val, str):
                return val.lower() == "on"
            return None
        status = MemberOfPlugin(ds).status()
        if isinstance(status, bool):
            return status
        return None
    except Exception as e:
        mcp.logger.debug("MemberOf plugin state unknown: %s", e)
        return None

INDEX_TYPE_DESCRIPTIONS: Dict[str, str] = {
    "eq": "equality - supports = searches",
    "pres": "presence - supports =* searches",
    "sub": "substring - supports *value* searches",
    "approx": "approximate - supports ~= searches",
}

# notes=U/A may appear combined with other flags, e.g. notes=P,U
UNINDEXED_SEARCH_PATTERN = re.compile(r"notes=[A-Z,]*[UA]")
SEARCH_FILTER_PATTERN = re.compile(r'filter="([^"]*)"')
SEARCH_BASE_PATTERN = re.compile(r'base="([^"]*)"')
CONN_OP_PATTERN = re.compile(r"conn=(\S+)\s+op=(\d+)")
# Traditional access-log timestamp: [28/Jan/2024:11:01:31.392560011 -0500]
ACCESS_LOG_TIMESTAMP_PATTERN = re.compile(
    r"^\[(?P<day>\d{1,2})/(?P<month>\w{3})/(?P<year>\d{4})"
    r":(?P<hour>\d{2}):(?P<minute>\d{2}):(?P<second>\d{2})"
    r"(?:\.\d+)?\s(?P<tz>[+-]\d{4})\]"
)


def _parse_index_entry(idx) -> Dict[str, Any]:
    """Parse a single index entry into a dictionary."""
    attr_name = idx.get_attr_val_utf8("cn")
    index_types = idx.get_attr_vals_utf8("nsIndexType") or []
    is_system = idx.get_attr_val_utf8("nsSystemIndex")
    matching_rule = idx.get_attr_val_utf8("nsMatchingRule")

    return {
        "attribute": attr_name,
        "types": index_types,
        "types_description": [
            INDEX_TYPE_DESCRIPTIONS.get(t.lower(), t) for t in index_types
        ],
        "is_system": is_system.lower() == "true" if is_system else False,
        "matching_rule": matching_rule,
    }


def _parse_vlv_entry(vlv) -> Dict[str, Any]:
    """Parse a VLV search entry into a dictionary."""
    return {
        "name": vlv.get_attr_val_utf8("cn"),
        "base": vlv.get_attr_val_utf8("vlvBase"),
        "scope": vlv.get_attr_val_utf8("vlvScope"),
        "filter": vlv.get_attr_val_utf8("vlvFilter"),
        "sort": vlv.get_attr_val_utf8("vlvSort"),
    }


def _generate_add_index_command(backend: str, attr: str, types: List[str]) -> str:
    """Generate dsconf command suggestion to add a new index."""
    types_args = " ".join(f"--index-type {t}" for t in types)
    return (
        f"Review whether indexing '{attr}' would benefit your specific workload. "
        f"If confirmed needed, a reindex will be required after adding. "
        f"Example command: dsconf <instance> backend index add --attr {attr} {types_args} {backend}"
    )


def _generate_add_index_type_command(backend: str, attr: str, types: List[str]) -> str:
    """Generate dsconf command suggestion to add index types to existing index."""
    types_args = " ".join(f"--add-type {t}" for t in types)
    return (
        f"Review whether additional index types for '{attr}' would benefit your workload. "
        f"A reindex may be required after modification. "
        f"Example command: dsconf <instance> backend index set --attr {attr} {types_args} {backend}"
    )


def _generate_index_recommendations(analysis_data: Dict[str, Any]) -> List[str]:
    """Generate prioritized list of recommendations.

    Core-attribute gaps are actionable deviations from the 389 DS default
    index set; workload-dependent suggestions are explicitly conditional on
    the deployment's search patterns.  Every change requires review, a
    reindex, and admin approval - none of these are ready-to-run.
    """
    recommendations = []

    all_missing = [
        m
        for be in analysis_data.get("backends", [])
        for m in be.get("missing_recommended", [])
    ]
    core_missing = [m for m in all_missing if m.get("category") != "workload_dependent"]
    workload_missing = [m for m in all_missing if m.get("category") == "workload_dependent"]

    if core_missing:
        recommendations.append(
            f"Review {len(core_missing)} missing core index(es) - these are part "
            f"of the 389 DS default index set (adding one requires a reindex "
            f"and admin approval)"
        )
    if workload_missing:
        recommendations.append(
            f"{len(workload_missing)} workload-dependent index suggestion(s) - "
            f"{_WORKLOAD_DEPENDENT_NOTE}"
        )

    # Check for common high-impact missing indexes
    for missing in all_missing:
        attr = missing["attribute"]
        if attr in ["uid", "mail", "cn"]:
            recommendations.append(
                f"PRIORITY: Add index for '{attr}' - frequently used in authentication and lookups"
            )
            break

    if not recommendations:
        # A no-issues result only means "follows best practices" when the
        # analysis actually observed complete evidence.
        if analysis_data.get("status") == "unknown" or analysis_data.get("evidence_status") == "partial":
            recommendations.append(
                "Analysis incomplete - index configuration could not be verified; "
                "resolve the discovery/scan failures and re-run"
            )
        else:
            recommendations.append("Index configuration follows best practices")

    return recommendations


def _parse_time_range(time_range: str) -> Optional[datetime]:
    """Parse a time range string ("1h", "24h", "7d") into a cutoff datetime.

    Returns a timezone-aware cutoff datetime, or None if the value is invalid.
    """
    now = datetime.now(timezone.utc)

    match = re.match(r"^(\d+)([hd])$", time_range.strip().lower())
    if not match:
        return None

    value = int(match.group(1))
    unit = match.group(2)

    if unit == "h":
        delta = timedelta(hours=value)
    else:
        delta = timedelta(days=value)

    return now - delta


def _parse_access_log_timestamp(line: str) -> Optional[datetime]:
    """Parse the leading timestamp of a traditional access-log line.

    Returns a timezone-aware datetime, or None if the line does not start
    with a parseable ``[DD/Mon/YYYY:HH:MM:SS.ns +ZZZZ]`` timestamp.

    Note: lib389's ``DirsrvLog.parse_timestamp()`` rebuilds the time with
    dashes ("11-01-31"), which current dateutil versions misparse (dropping
    minutes/seconds), and ``get_time_in_secs()`` only returns seconds since
    midnight — so we parse the timestamp ourselves with strptime.
    """
    m = ACCESS_LOG_TIMESTAMP_PATTERN.match(line)
    if not m:
        return None
    try:
        return datetime.strptime(
            "{day}/{month}/{year}:{hour}:{minute}:{second} {tz}".format(
                **m.groupdict()
            ),
            "%d/%b/%Y:%H:%M:%S %z",
        )
    except ValueError:
        return None


# One filter component: (attr OP value).  Operator order matters so ">=",
# "<=", and "~=" are recognized before plain "=".
_FILTER_COMPONENT_PATTERN = re.compile(
    r"\(\s*([a-zA-Z][a-zA-Z0-9;.-]*)\s*(>=|<=|~=|=)([^)]*)\)"
)


def _normalize_filter_pattern(filter_str: str) -> str:
    """Normalize an LDAP filter for grouping, preserving operator evidence.

    Equality values become ``*`` (legacy placeholder), presence stays
    ``=*``, substring filters keep their wildcard structure with literal
    runs collapsed to ``VAL``, and range/approximate operators are kept so
    the operator that made the search unindexed stays visible.
    """

    def _repl(m: "re.Match[str]") -> str:
        attr, op, value = m.groups()
        if op == "=":
            if value == "*":
                return f"({attr}=*)"  # presence
            if "*" in value:
                # substring: keep wildcard positions, drop literal values
                return f"({attr}={re.sub(r'[^*]+', 'VAL', value)})"
            return f"({attr}=*)"  # equality (legacy placeholder)
        return f"({attr}{op}VAL)"  # >=, <=, ~=

    normalized = _FILTER_COMPONENT_PATTERN.sub(_repl, filter_str)
    # Safety net: any component the pattern didn't recognize still gets its
    # value stripped (legacy behavior) so no directory data survives grouping.
    return re.sub(r"=(?!\*)(?!VAL[*)])([^)]+)", "=*", normalized)


def _classify_filter_operators(filter_str: str) -> Dict[str, Dict[str, str]]:
    """Map each attribute in an LDAP filter to its operator evidence.

    Returns ``{attr: {"operator": ..., "index_type": ...}}`` where operator
    is equality/presence/substring/approximate/range and index_type is the
    389 DS index type serving that operator (eq/pres/sub/approx).  Range
    filters map to "eq" only as a placeholder - an eq index does not serve
    range scans, which the caller must annotate.
    """
    evidence: Dict[str, Dict[str, str]] = {}
    for attr, op, value in _FILTER_COMPONENT_PATTERN.findall(filter_str or ""):
        if op == "~=":
            operator, index_type = "approximate", "approx"
        elif op in (">=", "<="):
            operator, index_type = "range", "eq"
        elif value == "*":
            operator, index_type = "presence", "pres"
        elif "*" in value:
            operator, index_type = "substring", "sub"
        else:
            operator, index_type = "equality", "eq"
        evidence.setdefault(attr, {"operator": operator, "index_type": index_type})
    return evidence


def _extract_filter_attributes(filter_str: str) -> List[str]:
    """Extract attribute names from an LDAP filter."""
    # Match attribute names before = or ~= or >= or <=
    attrs = re.findall(r"\(([a-zA-Z][a-zA-Z0-9-]*)(?:=|~=|>=|<=)", filter_str)
    return list(set(attrs))


_get_dse_ldif_path = get_dse_ldif_path
_find_child_dns = find_child_dns


def _discover_backends_offline(dse) -> List[tuple]:
    """Discover backends from DSEldif dse.ldif data.

    Returns list of (backend_name, suffix) tuples.
    """
    ldbm_dn = "cn=ldbm database,cn=plugins,cn=config"
    backend_dns = _find_child_dns(dse, ldbm_dn)

    backends = []
    for be_dn in backend_dns:
        be_suffix = dse.get(be_dn, "nsslapd-suffix", single=True)
        if be_suffix is None:
            continue
        be_name = dse.get(be_dn, "cn", single=True)
        if be_name:
            backends.append((be_name, be_suffix))

    return backends


def _parse_index_entry_offline(dse, index_dn: str) -> Dict[str, Any]:
    """Parse an index entry from DSEldif."""
    attr_name = dse.get(index_dn, "cn", single=True)
    index_types = dse.get(index_dn, "nsIndexType") or []
    is_system = dse.get(index_dn, "nsSystemIndex", single=True)
    matching_rule = dse.get(index_dn, "nsMatchingRule", single=True)

    return {
        "attribute": attr_name,
        "types": index_types,
        "types_description": [
            INDEX_TYPE_DESCRIPTIONS.get(t.lower(), t) for t in index_types
        ],
        "is_system": is_system.lower() == "true" if is_system else False,
        "matching_rule": matching_rule,
    }


def _parse_vlv_entry_offline(dse, vlv_dn: str) -> Dict[str, Any]:
    """Parse a VLV search entry from DSEldif."""
    return {
        "name": dse.get(vlv_dn, "cn", single=True),
        "base": dse.get(vlv_dn, "vlvBase", single=True),
        "scope": dse.get(vlv_dn, "vlvScope", single=True),
        "filter": dse.get(vlv_dn, "vlvFilter", single=True),
        "sort": dse.get(vlv_dn, "vlvSort", single=True),
    }


def register_index_tools(mcp: DirSrvMCP) -> None:
    """Register index analysis tools with the MCP server."""

    @mcp.tool(annotations=_RO, tags={"indexes", "live", "offline", "archive"})
    def list_indexes(
        backend: Optional[str] = None,
        server_name: Optional[str] = None,
    ) -> Dict[str, Any]:
        """List all configured indexes (attribute + VLV) per backend.

        Use this to audit which attributes are indexed and with which types
        (eq, pres, sub, approx). For best-practice analysis, use
        ``analyze_index_configuration``. For unindexed search detection,
        use ``find_unindexed_searches``.

        Works in all modes: LIVE, OFFLINE, ARCHIVE.

        Args:
            backend: Specific backend (e.g., 'userroot').
                    If not specified, lists indexes for all backends.
            server_name: Target server name. Uses default if not specified.

        Returns:
            Per-backend index list with types, system/user flags, and
            VLV index definitions.
        """
        target = server_name or mcp.default_server
        if not target:
            return {
                "type": "index_list",
                "error": "No server configured",
            }

        ds = None
        try:
            offline_archive = is_offline_or_archive(mcp.connection_manager, target)
            ds = mcp.connection_manager.connect(target)

            index_data: Dict[str, Any] = {
                "type": "index_list",
                "server": target,
                "backends": [],
            }

            total_indexes = 0
            total_vlv = 0

            if offline_archive:
                from lib389.dseldif import DSEldif

                dse_path = _get_dse_ldif_path(ds)
                dse = DSEldif(ds, path=dse_path)
                backends = _discover_backends_offline(dse)

                for be_name, be_suffix in backends:
                    if backend and be_name.lower() != backend.lower():
                        continue

                    backend_info: Dict[str, Any] = {
                        "name": be_name,
                        "suffix": be_suffix,
                        "indexes": [],
                        "vlv_indexes": [],
                    }

                    # Get indexes via DSEldif
                    try:
                        index_names = dse.get_indexes(be_name)
                        for idx_name in index_names:
                            idx_dn = f"cn={idx_name},cn=index,cn={be_name},cn=ldbm database,cn=plugins,cn=config"
                            index_info = _parse_index_entry_offline(dse, idx_dn)
                            if index_info.get("attribute"):
                                backend_info["indexes"].append(index_info)
                                total_indexes += 1
                    except Exception as e:
                        mcp.logger.warning("Error getting indexes for %s: %s", be_name, e)
                        backend_info["indexes_error"] = str(e)

                    # VLV indexes from DSEldif
                    try:
                        be_dn_lower = f"cn={be_name},cn=ldbm database,cn=plugins,cn=config".lower()
                        for line in dse._contents:
                            if not line.startswith("dn: "):
                                continue
                            dn = line[4:].rstrip("\n")
                            if dn.endswith(be_dn_lower) and dse.get(dn, "vlvBase") is not None:
                                vlv_entry = _parse_vlv_entry_offline(dse, dn)
                                backend_info["vlv_indexes"].append(vlv_entry)
                                total_vlv += 1
                    except Exception as e:
                        mcp.logger.debug("Error getting VLV indexes for %s: %s", be_name, e)

                    index_data["backends"].append(backend_info)
            else:
                backends_obj = Backends(ds)

                for be in backends_obj.list():
                    be_name = be.get_attr_val_utf8("cn")

                    if backend and be_name.lower() != backend.lower():
                        continue

                    be_suffix = be.get_attr_val_utf8("nsslapd-suffix")

                    backend_info = {
                        "name": be_name,
                        "suffix": be_suffix,
                        "indexes": [],
                        "vlv_indexes": [],
                    }

                    try:
                        indexes = be.get_indexes()
                        for idx in indexes.list():
                            index_entry = _parse_index_entry(idx)
                            backend_info["indexes"].append(index_entry)
                            total_indexes += 1
                    except Exception as e:
                        mcp.logger.warning("Error getting indexes for %s: %s", be_name, e)
                        backend_info["indexes_error"] = str(e)

                    try:
                        vlv_searches = VLVSearches(ds, basedn=be.dn)
                        for vlv in vlv_searches.list():
                            vlv_entry = _parse_vlv_entry(vlv)
                            backend_info["vlv_indexes"].append(vlv_entry)
                            total_vlv += 1
                    except Exception as e:
                        mcp.logger.debug("Error getting VLV indexes for %s: %s", be_name, e)

                    index_data["backends"].append(backend_info)

            # Summary
            user_indexes = sum(
                1
                for be in index_data["backends"]
                for idx in be.get("indexes", [])
                if not idx.get("is_system", False)
            )
            system_indexes = total_indexes - user_indexes

            index_data["summary"] = {
                "total_indexes": total_indexes,
                "user_indexes": user_indexes,
                "system_indexes": system_indexes,
                "vlv_indexes": total_vlv,
                "backends_checked": len(index_data["backends"]),
            }

            if offline_archive:
                index_data["mode"] = "offline" if mcp.connection_manager.get_config(target).is_offline else "archive"

            return _sanitize_index_result(mcp, index_data)

        except Exception as e:
            mcp.logger.error("Error listing indexes: %s", e)
            return _sanitize_index_result(
                mcp, format_tool_error(e, mcp, "index_list", server=target),
            )
        finally:
            if ds:
                try:
                    ds.close()
                except Exception:
                    pass

    @mcp.tool(annotations=_RO, tags={"indexes", "live", "offline", "archive"})
    def analyze_index_configuration(
        backend: Optional[str] = None,
        server_name: Optional[str] = None,
    ) -> Dict[str, Any]:
        """Audit index configuration against best practices with remediation commands.

        Checks for missing recommended indexes, incomplete index types, and
        provides example ``dsconf`` commands. Recommendations are static
        best-practice checks, not workload analysis: core attributes 389 DS
        expects indexed are separated from workload-dependent suggestions,
        and every change is marked as requiring review, approval, and a
        reindex. For a raw index listing, use ``list_indexes``.

        Works in all modes: LIVE, OFFLINE, ARCHIVE.

        Args:
            backend: Specific backend to analyze (e.g., 'userroot').
                    If not specified, analyzes all backends.
            server_name: Target server name. Uses default if not specified.

        Returns:
            Missing/incomplete indexes with basis and risk metadata,
            best-practice findings, and example dsconf remediation commands.
        """
        target = server_name or mcp.default_server
        if not target:
            return {
                "type": "index_analysis",
                "error": "No server configured",
            }

        ds = None
        try:
            offline_archive = is_offline_or_archive(mcp.connection_manager, target)
            ds = mcp.connection_manager.connect(target)

            analysis_data: Dict[str, Any] = {
                "type": "index_analysis",
                "server": target,
                "backends": [],
                "findings": [],
            }

            if offline_archive:
                from lib389.dseldif import DSEldif

                dse_path = _get_dse_ldif_path(ds)
                dse = DSEldif(ds, path=dse_path)
                all_backends = _discover_backends_offline(dse)
            else:
                all_backends = None
                dse = None

            _backend_objects: Dict[str, Any] = {}
            if offline_archive:
                backend_iter = all_backends
            else:
                backends_obj = Backends(ds)
                backend_iter = []
                for be in backends_obj.list():
                    name = be.get_attr_val_utf8("cn")
                    suffix = be.get_attr_val_utf8("nsslapd-suffix")
                    _backend_objects[name] = be
                    backend_iter.append((name, suffix))

            backends_scanned: List[str] = []
            backends_failed: List[Dict[str, str]] = []
            backend_matched = False

            # Plugin-dependent recommendations (memberOf) only apply when the
            # maintaining plugin is enabled; None means "state unknown".
            memberof_enabled = _memberof_plugin_enabled(mcp, ds, dse)

            for be_name, be_suffix in backend_iter:
                if backend and be_name.lower() != backend.lower():
                    continue
                backend_matched = True

                # Build current index map: attr -> set of types
                current_indexes: Dict[str, Set[str]] = {}
                user_indexes: List[str] = []

                try:
                    if offline_archive:
                        index_names = dse.get_indexes(be_name)
                        for idx_name in index_names:
                            idx_dn = f"cn={idx_name},cn=index,cn={be_name},cn=ldbm database,cn=plugins,cn=config"
                            attr_name = dse.get(idx_dn, "cn", single=True)
                            if attr_name:
                                index_types_list = dse.get(idx_dn, "nsIndexType") or []
                                is_system = dse.get(idx_dn, "nsSystemIndex", single=True)

                                current_indexes[attr_name.lower()] = set(
                                    t.lower() for t in index_types_list
                                )
                                # Absent nsSystemIndex ⇒ user index (matches
                                # list_indexes' counting)
                                if not is_system or is_system.lower() != "true":
                                    user_indexes.append(attr_name)
                    else:
                        be_obj = _backend_objects[be_name]
                        indexes = be_obj.get_indexes()
                        for idx in indexes.list():
                            attr_name = idx.get_attr_val_utf8("cn")
                            index_types = idx.get_attr_vals_utf8("nsIndexType") or []
                            is_system = idx.get_attr_val_utf8("nsSystemIndex")

                            current_indexes[attr_name.lower()] = set(
                                t.lower() for t in index_types
                            )

                            # Absent nsSystemIndex ⇒ user index (matches
                            # list_indexes' counting)
                            if not is_system or is_system.lower() != "true":
                                user_indexes.append(attr_name)
                except Exception as e:
                    mcp.logger.warning(
                        "Error analyzing indexes for %s: %s", be_name, e
                    )
                    backends_failed.append({
                        "backend": be_name,
                        "error": format_error_message(e),
                    })
                    continue

                backends_scanned.append(be_name)

                backend_analysis: Dict[str, Any] = {
                    "name": be_name,
                    "suffix": be_suffix,
                    "current_index_count": len(current_indexes),
                    "user_index_count": len(user_indexes),
                    "missing_recommended": [],
                    "incomplete_indexes": [],
                }

                # Check for missing recommended indexes
                for attr, rec_types in RECOMMENDED_INDEXES.items():
                    attr_lower = attr.lower()

                    # Categorize the recommendation: static best practice is
                    # not a workload analysis, and only core attributes are
                    # ones 389 DS genuinely expects indexed.
                    if attr_lower in PLUGIN_DEPENDENT_INDEX_ATTRIBUTES:
                        if memberof_enabled is False:
                            # Plugin disabled: indexing its attribute has no
                            # benefit - do not recommend it at all.
                            continue
                        category = (
                            "plugin_dependent"
                            if memberof_enabled
                            else "workload_dependent"
                        )
                    elif attr_lower in CORE_INDEX_ATTRIBUTES:
                        category = "core"
                    else:
                        category = "workload_dependent"

                    if attr_lower not in current_indexes:
                        # Completely missing
                        backend_analysis["missing_recommended"].append(
                            {
                                "attribute": attr,
                                "recommended_types": rec_types,
                                "basis": "static_best_practice",
                                "category": category,
                                "risk": _recommendation_risk(requires_reindex=True),
                                "dsconf_command": _generate_add_index_command(
                                    be_name, attr, rec_types
                                ),
                            }
                        )

                        if category == "workload_dependent":
                            severity = Severity.LOW
                            impact = (
                                f"Searches on '{attr}' would be unindexed - "
                                f"{_WORKLOAD_DEPENDENT_NOTE}"
                            )
                            details = (
                                f"The '{attr}' attribute has no index in backend "
                                f"'{be_name}'. This is a workload-dependent "
                                f"suggestion, not a core requirement: "
                                f"{_WORKLOAD_DEPENDENT_NOTE}."
                            )
                        else:
                            severity = Severity.MEDIUM
                            impact = f"Searches on '{attr}' attribute may be slow or cause full scans"
                            details = f"The '{attr}' attribute is commonly searched but has no index in backend '{be_name}'"

                        analysis_data["findings"].append(
                            format_finding(
                                title=f"Missing Recommended Index: {attr}",
                                severity=severity,
                                impact=impact,
                                details=details,
                                remediation=_generate_add_index_command(
                                    be_name, attr, rec_types
                                ),
                                server=target,
                                metadata={
                                    "attribute": attr,
                                    "backend": be_name,
                                    "recommended_types": rec_types,
                                    "basis": "static_best_practice",
                                    "category": category,
                                },
                            )
                        )
                    else:
                        # Check if all recommended types are present
                        current_types = current_indexes[attr_lower]
                        missing_types = [
                            t for t in rec_types if t.lower() not in current_types
                        ]

                        if missing_types:
                            backend_analysis["incomplete_indexes"].append(
                                {
                                    "attribute": attr,
                                    "current_types": list(current_types),
                                    "missing_types": missing_types,
                                    "basis": "static_best_practice",
                                    "category": category,
                                    "risk": _recommendation_risk(requires_reindex=True),
                                    "dsconf_command": _generate_add_index_type_command(
                                        be_name, attr, missing_types
                                    ),
                                }
                            )

                            analysis_data["findings"].append(
                                format_finding(
                                    title=f"Incomplete Index Configuration: {attr}",
                                    severity=Severity.LOW,
                                    impact=f"Some search types on '{attr}' may not use the index",
                                    details=f"Index for '{attr}' exists with types {list(current_types)} but missing {missing_types}",
                                    remediation=_generate_add_index_type_command(
                                        be_name, attr, missing_types
                                    ),
                                    server=target,
                                    metadata={
                                        "attribute": attr,
                                        "backend": be_name,
                                        "current_types": list(current_types),
                                        "missing_types": missing_types,
                                        "basis": "static_best_practice",
                                        "category": category,
                                    },
                                )
                            )

                analysis_data["backends"].append(backend_analysis)

            # Generate summary. A "healthy" conclusion requires that at least
            # one backend was actually scanned and that no selected backend
            # failed or was missing from discovery.
            total_missing = sum(
                len(be.get("missing_recommended", []))
                for be in analysis_data["backends"]
            )
            core_missing = sum(
                1
                for be in analysis_data["backends"]
                for m in be.get("missing_recommended", [])
                if m.get("category") != "workload_dependent"
            )
            workload_missing = total_missing - core_missing
            total_incomplete = sum(
                len(be.get("incomplete_indexes", []))
                for be in analysis_data["backends"]
            )

            requested_absent = bool(backend) and not backend_matched
            empty_discovery = not backend_iter
            incomplete = bool(backends_failed) or requested_absent or empty_discovery

            if core_missing > 0:
                summary = (
                    f"ATTENTION: {core_missing} missing core index(es), "
                    f"{workload_missing} workload-dependent suggestion(s), "
                    f"{total_incomplete} incomplete"
                )
                status = "warning"
            elif workload_missing > 0:
                summary = (
                    f"FAIR: core indexes present; {workload_missing} "
                    f"workload-dependent index suggestion(s) - "
                    f"{_WORKLOAD_DEPENDENT_NOTE}"
                )
                status = "fair"
            elif total_incomplete > 0:
                summary = f"FAIR: All recommended indexes present but {total_incomplete} could be enhanced"
                status = "fair"
            elif incomplete:
                status = "unknown"
                if empty_discovery:
                    summary = "UNKNOWN: no eligible backends were discovered - index health cannot be assessed"
                elif requested_absent:
                    summary = (
                        f"UNKNOWN: requested backend not found among "
                        f"{len(backend_iter)} discovered backend(s)"
                    )
                else:
                    summary = (
                        f"INCOMPLETE: {len(backends_failed)} backend scan(s) failed "
                        f"({len(backends_scanned)} scanned successfully) - index health cannot be confirmed"
                    )
            else:
                summary = "HEALTHY: All recommended indexes are properly configured"
                status = "healthy"

            if incomplete:
                # Issues found in scanned backends do not erase the gap:
                # keep the partial-coverage evidence visible either way.
                analysis_data["evidence_status"] = "partial"
            else:
                analysis_data["evidence_status"] = "complete"

            analysis_data["backends_scanned"] = backends_scanned
            analysis_data["backends_failed"] = backends_failed
            if requested_absent:
                analysis_data["requested_backend"] = backend

            analysis_data["summary"] = summary
            analysis_data["status"] = status
            analysis_data["recommendations"] = _generate_index_recommendations(
                analysis_data
            )

            if offline_archive:
                analysis_data["mode"] = "offline" if mcp.connection_manager.get_config(target).is_offline else "archive"

            return _sanitize_index_result(mcp, analysis_data)

        except Exception as e:
            mcp.logger.error("Error analyzing index configuration: %s", e)
            return _sanitize_index_result(
                mcp, format_tool_error(e, mcp, "index_analysis", server=target),
            )
        finally:
            if ds:
                try:
                    ds.close()
                except Exception:
                    pass

    @mcp.tool(annotations=_RO_LOCAL, tags={"indexes", "logs", "live", "offline", "archive"})
    def find_unindexed_searches(
        time_range: str = "1h",
        limit: Annotated[int, Field(ge=1, le=10000, description="Max entries to return")] = 50,
        server_name: Optional[str] = None,
    ) -> Dict[str, Any]:
        """Find unindexed searches (notes=U/A) in access logs with fix suggestions.

        Parses access log for operations flagged as unindexed or all-IDs-scan,
        groups them by search pattern, and provides ``dsconf`` commands to
        add the missing indexes.

        Requires LOCAL or ARCHIVE server access (reads log files directly).

        Args:
            time_range: How far back to analyze: "1h", "6h", "24h", "7d".
                       Default "1h".
            limit: Maximum unique patterns to return. Default 50.
            server_name: Target server name. Uses default if not specified.

        Returns:
            Unindexed search patterns with frequency, recommended indexes,
            estimated impact, and dsconf remediation commands.
        """
        target = server_name or mcp.default_server
        if not target:
            return {
                "type": "unindexed_searches",
                "error": "No server configured",
            }

        # Check if this server has local file access (local, offline, or archive)
        has_file_access = (
            is_local_server(mcp.connection_manager, target)
            or is_archive_server(mcp.connection_manager, target)
        )
        if not has_file_access:
            return _sanitize_index_result(mcp, {
                "type": "unindexed_searches",
                "server": target,
                "error": "Log analysis requires local server access",
                "details": (
                    f"Server '{target}' is configured as remote. "
                    "To enable log analysis, configure the server with "
                    "is_local=True and serverid=<instance>, or use archive mode."
                ),
                "findings": [
                    format_finding(
                        title="Local Server Access Required",
                        severity=Severity.INFO,
                        impact="Cannot analyze access logs for unindexed searches",
                        details="Access log parsing requires local file system access",
                        remediation="Configure the server with is_local=True and serverid to enable this feature",
                        server=target,
                    )
                ],
            })

        # Validate the time range up front — an invalid value must be an
        # explicit error, not a filter that silently matches nothing.
        cutoff_time = _parse_time_range(time_range)
        if cutoff_time is None:
            raise ToolError(
                f"Invalid time_range '{time_range}': use <number><unit> with "
                "unit 'h' (hours) or 'd' (days), e.g. '1h', '24h', '7d'"
            )

        ds = None
        try:
            ds = mcp.connection_manager.connect(target)

            # Stream the access-log FAMILY (current + rotated + gz, per-file
            # format detection) via the shared readers instead of loading
            # the whole current traditional file into memory.
            from ldap_assistant_mcp.dirsrv_mcp.tools.logs import (
                _detect_json_log,
                _json_entry_has_unindexed_note,
                _log_family_paths,
                _log_time_span,
                _parse_log_timestamp,
                _read_json_lines_single,
                _read_lines_single,
            )

            log_path = getattr(ds.ds_paths, "access_log", None)
            family = _log_family_paths(log_path, include_archived=True)
            if not family:
                return _sanitize_index_result(mcp, {
                    "type": "unindexed_searches",
                    "server": target,
                    "error": f"Access log not found at {log_path}",
                })

            # Archive evidence: anchor the relative range to the dataset end
            # instead of the wall clock (an old SOS would match nothing).
            # Scan the WHOLE family, newest file first: an empty or
            # header-only current file must not silently revert the anchor
            # to the wall clock while rotations still hold evidence.
            time_anchor = "wall_clock"
            if is_archive_server(mcp.connection_manager, target):
                dataset_end = None
                for candidate in reversed(family):
                    _first, dataset_end = _log_time_span(
                        candidate, "access", include_archived=False,
                    )
                    if dataset_end is not None:
                        break
                if dataset_end is not None:
                    window = datetime.now(timezone.utc) - cutoff_time
                    cutoff_time = dataset_end.replace(tzinfo=timezone.utc) - window
                    time_anchor = "dataset_end"
                else:
                    time_anchor = "dataset_end_unavailable"

            # Track unindexed search patterns
            # Key: (filter_pattern, base_dn), Value: count
            pattern_counts: Dict[tuple, int] = {}
            pattern_examples: Dict[tuple, str] = {}  # Store one example for each
            read_counters: Dict[str, int] = {}

            def _record_hit(search_filter, search_base):
                if search_filter is None:
                    # Still count it — an unindexed operation without a
                    # recoverable filter must not vanish from the report.
                    search_filter = "unknown"
                    normalized_filter = "unknown"
                else:
                    # Normalize filter for grouping (replace specific values)
                    normalized_filter = _normalize_filter_pattern(search_filter)
                key = (normalized_filter, search_base)
                pattern_counts[key] = pattern_counts.get(key, 0) + 1
                if key not in pattern_examples:
                    pattern_examples[key] = search_filter

            # Search for unindexed operations
            try:
                # Stream each file with its own format's parser.
                for path in family:
                    if _detect_json_log(path):
                        for jentry in _read_json_lines_single(path, read_counters):
                            if not _json_entry_has_unindexed_note(jentry):
                                continue
                            ts = jentry.get("local_time", jentry.get("date", ""))
                            jdt = _parse_log_timestamp(ts) if ts else None
                            if jdt is not None and jdt.replace(tzinfo=timezone.utc) < cutoff_time:
                                continue
                            # 389 DS RESULT records carry base/filter inside
                            # the notes[] objects, not at the top level.
                            search_filter = jentry.get("filter")
                            search_base = jentry.get("base_dn", jentry.get("base"))
                            if search_filter is None or search_base is None:
                                for note in jentry.get("notes") or []:
                                    if isinstance(note, dict) and note.get("note") in ("U", "A"):
                                        if search_filter is None:
                                            search_filter = note.get("filter")
                                        if search_base is None:
                                            search_base = note.get(
                                                "base_dn", note.get("base")
                                            )
                                        break
                            _record_hit(
                                search_filter,
                                search_base if search_base is not None else "unknown",
                            )
                        continue

                    # notes=U/A is logged on RESULT lines while base/filter
                    # are on the corresponding SRCH line — correlate via
                    # conn/op PER FILE: server restarts reset conn numbering,
                    # so (conn, op) keys collide across rotations.
                    # The correlation pass gets throwaway counters: both passes
                    # hit the same file, and a shared dict would double-count
                    # unreadable/truncated incidents in the tool result.
                    search_ops: Dict[Any, tuple] = {}
                    for line in _read_lines_single(path, {}):
                        filter_match = SEARCH_FILTER_PATTERN.search(line)
                        if not filter_match:
                            continue
                        op_match = CONN_OP_PATTERN.search(line)
                        if not op_match:
                            continue
                        base_match = SEARCH_BASE_PATTERN.search(line)
                        search_ops[op_match.groups()] = (
                            filter_match.group(1),
                            base_match.group(1) if base_match else "unknown",
                        )

                    for line in _read_lines_single(path, read_counters):
                        if not UNINDEXED_SEARCH_PATTERN.search(line):
                            continue

                        # Filter on the line's real timestamp.  Lines whose
                        # timestamp cannot be parsed are included rather than
                        # silently dropped.
                        line_time = _parse_access_log_timestamp(line)
                        if line_time is not None and line_time < cutoff_time:
                            continue

                        # Prefer base/filter from the line itself; fall back to
                        # the correlated SRCH line for RESULT lines.
                        filter_match = SEARCH_FILTER_PATTERN.search(line)
                        if filter_match:
                            search_filter = filter_match.group(1)
                            base_match = SEARCH_BASE_PATTERN.search(line)
                            search_base = base_match.group(1) if base_match else "unknown"
                        else:
                            op_match = CONN_OP_PATTERN.search(line)
                            search_filter, search_base = search_ops.get(
                                op_match.groups() if op_match else None,
                                (None, "unknown"),
                            )

                        _record_hit(search_filter, search_base)

            except Exception as e:
                mcp.logger.warning("Error parsing access log: %s", e)
                return _sanitize_index_result(mcp, {
                    "type": "unindexed_searches",
                    "server": target,
                    "error": f"Failed to parse access log: {e}",
                })

            # Sort by frequency and limit
            sorted_patterns = sorted(
                pattern_counts.items(), key=lambda x: x[1], reverse=True
            )[:limit]

            # Build results
            findings: List[Dict[str, Any]] = []
            patterns = []

            for (normalized_filter, base_dn), count in sorted_patterns:
                example_filter = pattern_examples.get(
                    (normalized_filter, base_dn), normalized_filter
                )
                # Classify operators from the example filter (which retains
                # the original operators) so the recommended index type
                # matches what the search actually needed.
                operator_evidence = _classify_filter_operators(example_filter)
                attrs = list(operator_evidence.keys()) or _extract_filter_attributes(
                    normalized_filter
                )

                pattern_entry: Dict[str, Any] = {
                    "filter_pattern": normalized_filter,
                    "example_filter": example_filter,
                    "base_dn": base_dn,
                    "count": count,
                    "recommended_indexes": [],
                }

                # Generate index recommendations
                for attr in attrs:
                    if attr.lower() in ["objectclass"]:  # objectClass usually indexed
                        continue
                    evidence = operator_evidence.get(
                        attr, {"operator": "equality", "index_type": "eq"}
                    )
                    index_type = evidence["index_type"]
                    rec = {
                        "attribute": attr,
                        "operator": evidence["operator"],
                        "index_type_suggested": index_type,
                        "recommended_type": index_type,
                        "dsconf_command": f"dsconf <instance> backend index add --attr {attr} --index-type {index_type} <backend>",
                    }
                    if evidence["operator"] == "range":
                        rec["note"] = (
                            "range filter (>=/<=): an eq index does not serve "
                            "range scans; consider ordering/matching-rule "
                            "support for this attribute"
                        )
                    pattern_entry["recommended_indexes"].append(rec)

                patterns.append(pattern_entry)

                # Add finding for high-frequency patterns. Filter values and
                # base DNs are directory data: in privacy mode use the same
                # placeholders the patterns list gets, or the finding details
                # would leak what the pattern sanitizer redacts.
                if count >= 10:
                    severity = Severity.HIGH if count >= 100 else Severity.MEDIUM
                    if mcp.privacy_enabled:
                        finding_title = "Frequent Unindexed Search: [filter]"
                        finding_details = "Filter: [filter]\nBase: [dn]"
                        finding_meta = {
                            "filter": "[filter]",
                            "base": "[dn]",
                            "count": count,
                            "attributes": attrs,
                        }
                    else:
                        finding_title = f"Frequent Unindexed Search: {normalized_filter[:50]}{'...' if len(normalized_filter) > 50 else ''}"
                        finding_details = f"Filter: {pattern_examples.get((normalized_filter, base_dn), normalized_filter)}\nBase: {base_dn}"
                        finding_meta = {
                            "filter": normalized_filter,
                            "base": base_dn,
                            "count": count,
                            "attributes": attrs,
                        }
                    findings.append(
                        format_finding(
                            title=finding_title,
                            severity=severity,
                            impact=f"Search pattern executed {count} times without index",
                            details=finding_details,
                            remediation=f"Investigate whether indexing '{', '.join(attrs)}' would benefit performance. Verify this pattern represents legitimate search traffic before adding indexes. A reindex is required after adding new indexes.",
                            server=target,
                            metadata=finding_meta,
                        )
                    )

            # Summary. "No unindexed searches" is a claim about evidence
            # actually read: if reader incidents (unreadable files, budget-
            # truncated gz rotations, malformed lines) left gaps in coverage
            # and nothing was found, the truthful answer is unknown, not
            # healthy.
            total_unindexed = sum(pattern_counts.values())
            unreadable = read_counters.get("unreadable_files", 0)
            truncated = read_counters.get("decompression_truncated", 0)
            malformed = read_counters.get("malformed_lines", 0)
            if total_unindexed == 0 and (unreadable or truncated or malformed):
                incidents = ", ".join(
                    f"{count} {label}"
                    for label, count in (
                        ("unreadable file(s)", unreadable),
                        ("truncated decompression(s)", truncated),
                        ("malformed line(s)", malformed),
                    )
                    if count
                )
                summary = (
                    f"INCOMPLETE: reader incidents ({incidents}) - no unindexed "
                    f"searches found in readable evidence"
                )
                status = "unknown"
            elif total_unindexed == 0:
                summary = f"HEALTHY: No unindexed searches found in the last {time_range}"
                status = "healthy"
            elif len(findings) > 0:
                summary = f"ATTENTION: {len(patterns)} unique unindexed search pattern(s) found ({total_unindexed} total occurrences)"
                status = "warning"
            else:
                summary = f"FAIR: {len(patterns)} low-frequency unindexed search pattern(s) found"
                status = "fair"

            result = {
                "type": "unindexed_searches",
                "server": target,
                "time_range": time_range,
                # Deprecated alias of effective_window["anchor"].
                "time_anchor": time_anchor,
                "effective_window": {
                    "requested": time_range,
                    "start": cutoff_time.replace(tzinfo=None).isoformat(),
                    "end": None,
                    "anchor": time_anchor,
                },
                "summary": summary,
                "status": status,
                "total_unindexed_count": total_unindexed,
                # True distinct-pattern count; "patterns" holds the top
                # `limit` by frequency.
                "unique_patterns": len(pattern_counts),
                "patterns": patterns,
                "patterns_truncated": max(0, len(pattern_counts) - len(patterns)),
                "findings": findings,
            }
            for counter_key in ("unreadable_files", "decompression_truncated", "malformed_lines"):
                if read_counters.get(counter_key):
                    result[counter_key] = read_counters[counter_key]
            return _sanitize_index_result(mcp, result)

        except Exception as e:
            mcp.logger.error("Error finding unindexed searches: %s", e)
            return _sanitize_index_result(
                mcp, format_tool_error(e, mcp, "unindexed_searches", server=target),
            )
        finally:
            if ds:
                try:
                    ds.close()
                except Exception:
                    pass
