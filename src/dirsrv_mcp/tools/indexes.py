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
from typing import TYPE_CHECKING, Any, Dict, List, Optional, Set

from lib389.backend import Backends
from lib389.dirsrv_log import DirsrvAccessLog
from lib389.index import VLVSearches

from src.dirsrv_mcp.connection import is_archive_server, is_local_server, is_offline_or_archive
from src.dirsrv_mcp.tools.dse_utils import find_child_dns, get_dse_ldif_path
from src.dirsrv_mcp.tools.error_utils import format_tool_error
from src.lib.result_formatter import Severity, format_finding

if TYPE_CHECKING:
    from src.dirsrv_mcp.server import DirSrvMCP


def _sanitize_index_result(mcp: "DirSrvMCP", result: Dict[str, Any]) -> Dict[str, Any]:
    """Sanitize index result for privacy mode."""
    if not mcp.privacy_enabled:
        return result

    sanitizer = mcp.sanitizer
    sanitized = dict(result)

    if "server" in sanitized:
        sanitized["server"] = sanitizer.sanitize_server_name(sanitized["server"])

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

    return sanitized


def _sanitize_backend(sanitizer, backend: Dict[str, Any]) -> Dict[str, Any]:
    """Sanitize a backend entry in index results."""
    result = dict(backend)
    if "name" in result:
        result["name"] = "[backend]"
    if "suffix" in result:
        result["suffix"] = sanitizer.sanitize_suffix(result["suffix"])
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

INDEX_TYPE_DESCRIPTIONS: Dict[str, str] = {
    "eq": "equality - supports = searches",
    "pres": "presence - supports =* searches",
    "sub": "substring - supports *value* searches",
    "approx": "approximate - supports ~= searches",
}

UNINDEXED_SEARCH_PATTERN = re.compile(r"notes=(U|A)")
SEARCH_FILTER_PATTERN = re.compile(r'filter="([^"]*)"')
SEARCH_BASE_PATTERN = re.compile(r'base="([^"]*)"')


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
    """Generate prioritized list of recommendations."""
    recommendations = []

    total_missing = sum(
        len(be.get("missing_recommended", []))
        for be in analysis_data.get("backends", [])
    )

    if total_missing > 0:
        recommendations.append(
            f"Add {total_missing} missing recommended index(es) to improve search performance"
        )

    # Check for common high-impact missing indexes
    for be in analysis_data.get("backends", []):
        for missing in be.get("missing_recommended", []):
            attr = missing["attribute"]
            if attr in ["uid", "mail", "cn"]:
                recommendations.append(
                    f"PRIORITY: Add index for '{attr}' - frequently used in authentication and lookups"
                )
                break

    if not recommendations:
        recommendations.append("Index configuration follows best practices")

    return recommendations


def _parse_time_range(time_range: str) -> Optional[float]:
    """Parse time range string to cutoff timestamp in seconds."""
    now = datetime.now(timezone.utc)

    match = re.match(r"^(\d+)([hd])$", time_range.lower())
    if not match:
        return None

    value = int(match.group(1))
    unit = match.group(2)

    if unit == "h":
        delta = timedelta(hours=value)
    elif unit == "d":
        delta = timedelta(days=value)
    else:
        return None

    cutoff = now - delta
    return cutoff.timestamp()


def _normalize_filter_pattern(filter_str: str) -> str:
    """Normalize an LDAP filter by replacing specific values with placeholders."""
    # Replace specific values in equality filters with placeholder
    # (uid=john) -> (uid=*)
    normalized = re.sub(r"=([^)]+)", "=*", filter_str)
    return normalized


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

    @mcp.tool()
    def list_indexes(
        backend: Optional[str] = None,
        server_name: Optional[str] = None,
    ) -> Dict[str, Any]:
        """List all configured indexes for the directory server.

        Returns comprehensive information about all indexes including:
        - Regular attribute indexes (eq, pres, sub, approx types)
        - System vs user-defined indexes
        - VLV (Virtual List View) indexes

        Args:
            backend: Specific backend to query (e.g., 'userroot').
                    If not specified, lists indexes for all backends.
            server_name: Target server name. Uses default if not specified.

        Returns:
            Index listing including:
            - Per-backend index configuration
            - Index types for each attribute
            - System index indicators
            - VLV index definitions
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

    @mcp.tool()
    def analyze_index_configuration(
        backend: Optional[str] = None,
        server_name: Optional[str] = None,
    ) -> Dict[str, Any]:
        """Analyze index configuration for common issues and best practices.

        Compares current index configuration against recommended indexes
        and identifies potential optimization opportunities.

        Args:
            backend: Specific backend to analyze (e.g., 'userroot').
                    If not specified, analyzes all backends.
            server_name: Target server name. Uses default if not specified.

        Returns:
            Analysis including:
            - Missing recommended indexes
            - Index type recommendations
            - Potentially incomplete indexes
            - Best practice recommendations
            - dsconf commands for remediation
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

            for be_name, be_suffix in backend_iter:
                if backend and be_name.lower() != backend.lower():
                    continue

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
                                if is_system and is_system.lower() != "true":
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

                            if is_system and is_system.lower() != "true":
                                user_indexes.append(attr_name)
                except Exception as e:
                    mcp.logger.warning(
                        "Error analyzing indexes for %s: %s", be_name, e
                    )
                    continue

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
                    if attr_lower not in current_indexes:
                        # Completely missing
                        backend_analysis["missing_recommended"].append(
                            {
                                "attribute": attr,
                                "recommended_types": rec_types,
                                "dsconf_command": _generate_add_index_command(
                                    be_name, attr, rec_types
                                ),
                            }
                        )

                        analysis_data["findings"].append(
                            format_finding(
                                title=f"Missing Recommended Index: {attr}",
                                severity=Severity.MEDIUM,
                                impact=f"Searches on '{attr}' attribute may be slow or cause full scans",
                                details=f"The '{attr}' attribute is commonly searched but has no index in backend '{be_name}'",
                                remediation=_generate_add_index_command(
                                    be_name, attr, rec_types
                                ),
                                server=target,
                                metadata={
                                    "attribute": attr,
                                    "backend": be_name,
                                    "recommended_types": rec_types,
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
                                    },
                                )
                            )

                analysis_data["backends"].append(backend_analysis)

            # Generate summary
            total_missing = sum(
                len(be.get("missing_recommended", []))
                for be in analysis_data["backends"]
            )
            total_incomplete = sum(
                len(be.get("incomplete_indexes", []))
                for be in analysis_data["backends"]
            )

            if total_missing > 0:
                summary = f"ATTENTION: {total_missing} missing recommended index(es), {total_incomplete} incomplete"
                status = "warning"
            elif total_incomplete > 0:
                summary = f"FAIR: All recommended indexes present but {total_incomplete} could be enhanced"
                status = "fair"
            else:
                summary = "HEALTHY: All recommended indexes are properly configured"
                status = "healthy"

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

    @mcp.tool()
    def find_unindexed_searches(
        time_range: str = "1h",
        limit: int = 50,
        server_name: Optional[str] = None,
    ) -> Dict[str, Any]:
        """Identify searches that aren't using indexes by analyzing access logs.

        Parses the access log for operations with notes=U (unindexed) or
        notes=A (all IDs scan) to identify search patterns that would
        benefit from indexing.

        **Requires local server access** - This tool needs to read the
        access log files directly and only works when the server is
        configured with is_local=True and serverid set.

        Args:
            time_range: How far back to analyze. Supports:
                       "1h" (1 hour), "6h" (6 hours), "24h" (24 hours),
                       "7d" (7 days). Default is "1h".
            limit: Maximum number of unique patterns to return. Default 50.
            server_name: Target server name. Uses default if not specified.

        Returns:
            Unindexed search analysis including:
            - Search patterns causing unindexed searches
            - Frequency of each pattern
            - Recommended indexes to create
            - Estimated impact
            - dsconf commands for remediation
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

        ds = None
        try:
            ds = mcp.connection_manager.connect(target)

            # Parse time range
            cutoff_time = _parse_time_range(time_range)

            # Get access log
            access_log = DirsrvAccessLog(ds)

            # Track unindexed search patterns
            # Key: (filter_pattern, base_dn), Value: count
            pattern_counts: Dict[tuple, int] = {}
            pattern_examples: Dict[tuple, str] = {}  # Store one example for each

            # Search for unindexed operations
            try:
                # Match lines with notes=U or notes=A
                matches = access_log.match(r"notes=(U|A)")

                for line in matches:
                    # Parse timestamp and check if within range
                    try:
                        line_time = access_log.get_time_in_secs(line)
                        if cutoff_time and line_time < cutoff_time:
                            continue
                    except Exception:
                        # If we can't parse time, include it anyway
                        pass

                    # Extract filter and base
                    filter_match = SEARCH_FILTER_PATTERN.search(line)
                    base_match = SEARCH_BASE_PATTERN.search(line)

                    if filter_match:
                        search_filter = filter_match.group(1)
                        search_base = base_match.group(1) if base_match else "unknown"

                        # Normalize filter for grouping (replace specific values)
                        normalized_filter = _normalize_filter_pattern(search_filter)

                        key = (normalized_filter, search_base)
                        pattern_counts[key] = pattern_counts.get(key, 0) + 1

                        if key not in pattern_examples:
                            pattern_examples[key] = search_filter

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
                # Extract attributes from filter for index recommendations
                attrs = _extract_filter_attributes(normalized_filter)

                pattern_entry: Dict[str, Any] = {
                    "filter_pattern": normalized_filter,
                    "example_filter": pattern_examples.get(
                        (normalized_filter, base_dn), normalized_filter
                    ),
                    "base_dn": base_dn,
                    "count": count,
                    "recommended_indexes": [],
                }

                # Generate index recommendations
                for attr in attrs:
                    if attr.lower() not in ["objectclass"]:  # objectClass usually indexed
                        rec = {
                            "attribute": attr,
                            "recommended_type": "eq",  # Most unindexed are equality
                            "dsconf_command": f"dsconf <instance> backend index add --attr {attr} --index-type eq <backend>",
                        }
                        pattern_entry["recommended_indexes"].append(rec)

                patterns.append(pattern_entry)

                # Add finding for high-frequency patterns
                if count >= 10:
                    severity = Severity.HIGH if count >= 100 else Severity.MEDIUM
                    findings.append(
                        format_finding(
                            title=f"Frequent Unindexed Search: {normalized_filter[:50]}{'...' if len(normalized_filter) > 50 else ''}",
                            severity=severity,
                            impact=f"Search pattern executed {count} times without index",
                            details=f"Filter: {pattern_examples.get((normalized_filter, base_dn), normalized_filter)}\nBase: {base_dn}",
                            remediation=f"Investigate whether indexing '{', '.join(attrs)}' would benefit performance. Verify this pattern represents legitimate search traffic before adding indexes. A reindex is required after adding new indexes.",
                            server=target,
                            metadata={
                                "filter": normalized_filter,
                                "base": base_dn,
                                "count": count,
                                "attributes": attrs,
                            },
                        )
                    )

            # Summary
            total_unindexed = sum(pattern_counts.values())
            if total_unindexed == 0:
                summary = f"HEALTHY: No unindexed searches found in the last {time_range}"
                status = "healthy"
            elif len(findings) > 0:
                summary = f"ATTENTION: {len(patterns)} unique unindexed search pattern(s) found ({total_unindexed} total occurrences)"
                status = "warning"
            else:
                summary = f"FAIR: {len(patterns)} low-frequency unindexed search pattern(s) found"
                status = "fair"

            return _sanitize_index_result(mcp, {
                "type": "unindexed_searches",
                "server": target,
                "time_range": time_range,
                "summary": summary,
                "status": status,
                "total_unindexed_count": total_unindexed,
                "unique_patterns": len(patterns),
                "patterns": patterns,
                "findings": findings,
            })

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
