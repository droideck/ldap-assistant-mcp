"""Replication diagnostic tools for 389 Directory Server.

This module provides comprehensive replication monitoring and diagnostic capabilities
including status checks, topology mapping, lag analysis, and conflict detection.
"""

from __future__ import annotations

import json
from typing import TYPE_CHECKING, Any, Dict, List, Optional

from lib389._constants import ReplicaRole
from lib389.conflicts import ConflictEntries, GlueEntries
from lib389.replica import Replicas, RUV

from src.dirsrv_mcp.connection import is_offline_or_archive, require_live_server
from src.dirsrv_mcp.tools.error_utils import format_error_message, format_tool_error
from src.lib.result_formatter import Severity, format_finding

if TYPE_CHECKING:
    from src.dirsrv_mcp.server import DirSrvMCP

def _sanitize_replication_result(mcp: "DirSrvMCP", result: Dict[str, Any]) -> Dict[str, Any]:
    """Sanitize replication result for privacy mode."""
    if not mcp.privacy_enabled:
        return result

    sanitizer = mcp.sanitizer
    sanitized = dict(result)

    original_server = sanitized.get("server")
    if "server" in sanitized:
        sanitized["server"] = sanitizer.sanitize_server_name(sanitized["server"])
    if "error" in sanitized and isinstance(sanitized["error"], str):
        err = sanitized["error"]
        if original_server and original_server in err:
            err = err.replace(original_server, sanitized.get("server", "[server]"))
        sanitized["error"] = sanitizer._sanitize_text_field(err)

    if "replicas" in sanitized and isinstance(sanitized["replicas"], list):
        sanitized["replicas"] = [sanitizer.sanitize_replica(r) for r in sanitized["replicas"]]

    if "servers" in sanitized and isinstance(sanitized["servers"], list):
        sanitized["servers"] = [sanitizer.sanitize_server_info(s) for s in sanitized["servers"]]

    if "agreements" in sanitized and isinstance(sanitized["agreements"], list):
        sanitized["agreements"] = [sanitizer.sanitize_agreement(a) for a in sanitized["agreements"]]

    if "lag_data" in sanitized and isinstance(sanitized["lag_data"], list):
        sanitized["lag_data"] = [sanitizer.sanitize_agreement(a) for a in sanitized["lag_data"]]

    if "findings" in sanitized and isinstance(sanitized["findings"], list):
        sanitized["findings"] = sanitizer.sanitize_findings(sanitized["findings"])

    if "suffixes" in sanitized and isinstance(sanitized["suffixes"], dict):
        new_suffixes = {}
        for suffix, data in sanitized["suffixes"].items():
            anon_suffix = sanitizer.sanitize_suffix(suffix)
            new_data = {}
            for key, servers in data.items():
                if isinstance(servers, list):
                    new_data[key] = [sanitizer.sanitize_server_name(s) for s in servers]
                else:
                    new_data[key] = servers
            new_suffixes[anon_suffix] = new_data
        sanitized["suffixes"] = new_suffixes

    if "suffix_filter" in sanitized and sanitized["suffix_filter"]:
        sanitized["suffix_filter"] = sanitizer.sanitize_suffix(sanitized["suffix_filter"])

    if "suffixes_checked" in sanitized and isinstance(sanitized["suffixes_checked"], list):
        sanitized["suffixes_checked"] = [
            sanitizer.sanitize_suffix(s) for s in sanitized["suffixes_checked"]
        ]

    if "servers_checked" in sanitized and isinstance(sanitized["servers_checked"], list):
        sanitized["servers_checked"] = [
            sanitizer.sanitize_server_name(s) for s in sanitized["servers_checked"]
        ]
    if "servers_failed" in sanitized and isinstance(sanitized["servers_failed"], list):
        sanitized["servers_failed"] = [
            sanitizer.sanitize_server_name(s) for s in sanitized["servers_failed"]
        ]

    if "conflicts" in sanitized and isinstance(sanitized["conflicts"], list):
        sanitized["conflicts"] = [
            {
                **c,
                "dn": sanitizer.sanitize_dn(c.get("dn")),
                "suffix": sanitizer.sanitize_suffix(c.get("suffix")),
                "valid_entry_dn": sanitizer.sanitize_dn(c.get("valid_entry_dn")) if c.get("valid_entry_dn") else None,
                "conflict_attribute": sanitizer._sanitize_text_field(c.get("conflict_attribute", "")) if c.get("conflict_attribute") else None,
            }
            for c in sanitized["conflicts"]
        ]
    if "glue_entries" in sanitized and isinstance(sanitized["glue_entries"], list):
        sanitized["glue_entries"] = [
            {
                **g,
                "dn": sanitizer.sanitize_dn(g.get("dn")),
                "suffix": sanitizer.sanitize_suffix(g.get("suffix")),
            }
            for g in sanitized["glue_entries"]
        ]

    if "filter" in sanitized and isinstance(sanitized["filter"], dict):
        new_filter = {}
        for key, value in sanitized["filter"].items():
            if key == "suffix" and value:
                new_filter[key] = sanitizer.sanitize_suffix(value)
            elif key == "agreement_name" and value:
                new_filter[key] = "[agreement]"
            else:
                new_filter[key] = value
        sanitized["filter"] = new_filter

    return sanitized

def _role_to_string(role: ReplicaRole) -> str:
    """Convert ReplicaRole enum to readable string."""
    role_map = {
        ReplicaRole.SUPPLIER: "supplier",
        ReplicaRole.HUB: "hub",
        ReplicaRole.CONSUMER: "consumer",
    }
    return role_map.get(role, "unknown")

def _parse_ruv_for_display(ruv: RUV) -> Dict[str, Any]:
    """Parse RUV object into displayable format with interpretation."""
    try:
        ruv_data = ruv.format_ruv()
        return {
            "data_generation": ruv_data.get("data_generation"),
            "replicas": ruv_data.get("ruvs", []),
            "replica_count": len(ruv_data.get("ruvs", [])),
        }
    except Exception as e:
        return {"error": format_error_message(e), "replicas": [], "replica_count": 0}

def _get_agreement_details(agmt, mcp: DirSrvMCP) -> Dict[str, Any]:
    """Extract detailed information from a replication agreement."""
    try:
        agmt_data = {
            "name": agmt.get_attr_val_utf8("cn"),
            "consumer_host": agmt.get_attr_val_utf8("nsDS5ReplicaHost"),
            "consumer_port": agmt.get_attr_val_utf8("nsDS5ReplicaPort"),
            "suffix": agmt.get_attr_val_utf8("nsDS5ReplicaRoot"),
            "transport": agmt.get_attr_val_utf8("nsDS5ReplicaTransportInfo"),
            "bind_method": agmt.get_attr_val_utf8("nsDS5ReplicaBindMethod"),
            "enabled": agmt.get_attr_val_utf8("nsds5ReplicaEnabled"),
        }

        try:
            status_json = agmt.get_agmt_status(return_json=True)
            status = json.loads(status_json)
            agmt_data["status"] = status
        except Exception as e:
            agmt_data["status"] = {"error": format_error_message(e), "state": "unknown"}

        agmt_data["last_update_start"] = agmt.get_attr_val_utf8("nsds5replicaLastUpdateStart")
        agmt_data["last_update_end"] = agmt.get_attr_val_utf8("nsds5replicaLastUpdateEnd")
        agmt_data["last_update_status"] = agmt.get_attr_val_utf8("nsds5replicaLastUpdateStatus")
        agmt_data["changes_sent"] = agmt.get_attr_val_utf8("nsds5replicaChangesSentSinceStartup")

        return agmt_data
    except Exception as e:
        mcp.logger.warning("Error getting agreement details: %s", e)
        return {"error": format_error_message(e)}

def register_replication_tools(mcp: DirSrvMCP) -> None:
    """Register replication diagnostic tools with the MCP server."""

    @mcp.tool()
    def get_replication_status(server_name: Optional[str] = None) -> Dict[str, Any]:
        """Get replication configuration, RUV, and agreement status for one server. LIVE only.

        Start here when investigating a specific server's replication.
        For a cross-server topology map, use ``get_replication_topology``.
        For lag analysis, use ``check_replication_lag``.

        Args:
            server_name: Target server name. Uses default if not specified.

        Returns:
            Per-suffix replica role, ID, RUV with CSN analysis, all
            agreements with status, and findings for detected issues.
        """
        target = server_name or mcp.default_server
        if not target:
            return {
                "type": "replication_status",
                "error": "No server configured",
                "replicas": [],
            }
        require_live_server(mcp.connection_manager, target, "get_replication_status")

        ds = None
        try:
            ds = mcp.connection_manager.connect(target)
            replicas_obj = Replicas(ds)
            replicas_list = replicas_obj.list()

            if not replicas_list:
                return _sanitize_replication_result(mcp, {
                    "type": "replication_status",
                    "server": target,
                    "summary": "No replication configured",
                    "replicas": [],
                    "findings": [
                        format_finding(
                            title="No Replication Configured",
                            severity=Severity.INFO,
                            impact="This server is not participating in replication",
                            details="No replica entries found in cn=mapping tree,cn=config",
                            remediation="If replication is needed, configure it using dsconf or lib389",
                            server=target,
                        )
                    ],
                })

            findings: List[Dict[str, Any]] = []
            replicas_data = []

            for replica in replicas_list:
                try:
                    suffix = replica.get_suffix()
                    role = replica.get_role()
                    rid = replica.get_rid()
                    ruv = replica.get_ruv()

                    replica_info = {
                        "suffix": suffix,
                        "role": _role_to_string(role),
                        "replica_id": rid,
                        "ruv": _parse_ruv_for_display(ruv),
                        "agreements": [],
                    }

                    # Check for empty RUV (uninitialized replica)
                    ruv_data = ruv.format_ruv()
                    if not ruv_data.get("ruvs"):
                        findings.append(
                            format_finding(
                                title=f"Uninitialized Replica: {suffix}",
                                severity=Severity.HIGH,
                                impact="Replica has no RUV - replication is not working",
                                details=f"The replica for suffix {suffix} has an empty RUV, indicating it has never been initialized",
                                remediation="Investigate why the replica is uninitialized. This could indicate a new replica that needs initialization, or a configuration issue. Consult documentation before performing replica initialization as it involves data transfer.",
                                server=target,
                                metadata={"suffix": suffix},
                            )
                        )

                    try:
                        agmts = replica.get_agreements()
                        for agmt in agmts.list():
                            agmt_details = _get_agreement_details(agmt, mcp)
                            replica_info["agreements"].append(agmt_details)

                            # Check agreement status
                            status = agmt_details.get("status", {})
                            if status.get("state") == "red":
                                findings.append(
                                    format_finding(
                                        title=f"Agreement Error: {agmt_details.get('name')}",
                                        severity=Severity.CRITICAL,
                                        impact=f"Replication to {agmt_details.get('consumer_host')}:{agmt_details.get('consumer_port')} is failing",
                                        details=status.get("reason", "Unknown error"),
                                        remediation="Check consumer connectivity, credentials, and server logs",
                                        server=target,
                                        metadata={"agreement": agmt_details.get("name"), "suffix": suffix},
                                    )
                                )
                            elif status.get("state") == "amber":
                                findings.append(
                                    format_finding(
                                        title=f"Agreement Warning: {agmt_details.get('name')}",
                                        severity=Severity.MEDIUM,
                                        impact=f"Replication to {agmt_details.get('consumer_host')} has warnings",
                                        details=status.get("reason", "Unknown warning"),
                                        remediation="Monitor the agreement and check server logs if issues persist",
                                        server=target,
                                        metadata={"agreement": agmt_details.get("name"), "suffix": suffix},
                                    )
                                )
                            elif status.get("msg") == "Not in Synchronization":
                                if "Replication still in progress" not in status.get("reason", ""):
                                    findings.append(
                                        format_finding(
                                            title=f"Replication Lag: {agmt_details.get('name')}",
                                            severity=Severity.MEDIUM,
                                            impact=f"Consumer {agmt_details.get('consumer_host')} is behind",
                                            details=f"Supplier CSN: {status.get('agmt_maxcsn')}, Consumer CSN: {status.get('con_maxcsn')}",
                                            remediation="Check for network issues or heavy load on supplier/consumer",
                                            server=target,
                                            metadata={"agreement": agmt_details.get("name"), "suffix": suffix},
                                        )
                                    )

                            if agmt_details.get("enabled", "on").lower() == "off":
                                findings.append(
                                    format_finding(
                                        title=f"Disabled Agreement: {agmt_details.get('name')}",
                                        severity=Severity.MEDIUM,
                                        impact=f"Replication to {agmt_details.get('consumer_host')} is disabled",
                                        details="The replication agreement is configured but disabled",
                                        remediation="Verify whether this agreement was intentionally disabled. If replication to this consumer is required, investigate why it was disabled before re-enabling.",
                                        server=target,
                                        metadata={"agreement": agmt_details.get("name"), "suffix": suffix},
                                    )
                                )

                    except Exception as e:
                        mcp.logger.warning("Error getting agreements for %s: %s", suffix, e)
                        replica_info["agreements_error"] = format_error_message(e)

                    try:
                        tombstone_count = replica.get_tombstone_count()
                        replica_info["tombstone_count"] = tombstone_count
                        if tombstone_count > 10000:
                            findings.append(
                                format_finding(
                                    title=f"High Tombstone Count: {suffix}",
                                    severity=Severity.MEDIUM,
                                    impact="Large number of tombstones may affect performance",
                                    details=f"Found {tombstone_count} tombstones in {suffix}",
                                    remediation="Consider running tombstone purge or reviewing purge settings",
                                    server=target,
                                    metadata={"suffix": suffix, "count": tombstone_count},
                                )
                            )
                    except Exception:
                        pass

                    replicas_data.append(replica_info)

                except Exception as e:
                    mcp.logger.error("Error processing replica: %s", e)
                    replicas_data.append({"error": format_error_message(e)})

            total_agreements = sum(len(r.get("agreements", [])) for r in replicas_data)
            error_count = sum(1 for f in findings if f.get("severity") in ["critical", "high"])

            if error_count > 0:
                summary = f"ISSUES DETECTED: {error_count} critical/high issues found"
            elif findings:
                summary = f"WARNINGS: {len(findings)} issue(s) found across {len(replicas_data)} replica(s)"
            else:
                summary = f"HEALTHY: {len(replicas_data)} replica(s) with {total_agreements} agreement(s) operating normally"

            return _sanitize_replication_result(mcp, {
                "type": "replication_status",
                "server": target,
                "summary": summary,
                "replica_count": len(replicas_data),
                "total_agreements": total_agreements,
                "replicas": replicas_data,
                "findings": findings,
            })

        except Exception as e:
            mcp.logger.error("Error getting replication status: %s", e)
            err_msg = format_error_message(e)
            result = format_tool_error(e, mcp, "replication_status", server=target)
            result["summary"] = f"FAILED: {err_msg}"
            result["replicas"] = []
            result["findings"] = [
                format_finding(
                    title="Replication Status Check Failed",
                    severity=Severity.HIGH,
                    impact="Unable to retrieve replication information",
                    details=err_msg,
                    remediation="Check server connectivity and permissions",
                    server=target,
                )
            ]
            return _sanitize_replication_result(mcp, result)
        finally:
            if ds:
                try:
                    ds.close()
                except Exception:
                    pass

    @mcp.tool()
    def get_replication_topology() -> Dict[str, Any]:
        """Map the complete replication topology across all configured servers. LIVE only.

        Queries every configured live server to build a cross-server view.
        Offline/archive servers are included as nodes but cannot report
        live agreement status. For single-server details, use
        ``get_replication_status`` instead.

        Returns:
            All servers with roles, inter-server agreements, topology
            graph, and findings (single points of failure, orphaned replicas).
        """
        server_names = mcp.connection_manager.get_server_names()

        if not server_names:
            return {
                "type": "replication_topology",
                "error": "No servers configured",
                "servers": [],
            }

        topology = {
            "type": "replication_topology",
            "servers": [],
            "agreements": [],
            "findings": [],
            "suffixes": {},
        }

        servers_checked = []
        servers_failed = []

        for server_name in server_names:
            # Skip offline/archive servers - they can't provide live replication status
            if is_offline_or_archive(mcp.connection_manager, server_name):
                config = mcp.connection_manager.get_config(server_name)
                mode = "archive" if config.is_archive else "offline"
                servers_failed.append(server_name)
                topology["findings"].append(
                    format_finding(
                        title=f"Skipped {mode.title()} Server: {server_name}",
                        severity=Severity.INFO,
                        impact=f"{mode.title()} servers cannot provide live replication topology data",
                        details=f"Server '{server_name}' is in {mode} mode",
                        remediation="Use a live server for replication topology analysis",
                        server=server_name,
                    )
                )
                continue

            ds = None
            try:
                ds = mcp.connection_manager.connect(server_name)
                servers_checked.append(server_name)

                live_config = mcp.connection_manager.get_config(server_name)
                server_info = {
                    "name": server_name,
                    "url": live_config.ldap_url,
                    "replicas": [],
                }

                replicas_obj = Replicas(ds)
                replicas_list = replicas_obj.list()

                for replica in replicas_list:
                    try:
                        suffix = replica.get_suffix()
                        role = replica.get_role()
                        rid = replica.get_rid()

                        replica_data = {
                            "suffix": suffix,
                            "role": _role_to_string(role),
                            "replica_id": rid,
                        }
                        server_info["replicas"].append(replica_data)

                        # Track suffixes across topology
                        if suffix not in topology["suffixes"]:
                            topology["suffixes"][suffix] = {
                                "suppliers": [],
                                "hubs": [],
                                "consumers": [],
                            }

                        role_str = _role_to_string(role)
                        if role_str == "supplier":
                            topology["suffixes"][suffix]["suppliers"].append(server_name)
                        elif role_str == "hub":
                            topology["suffixes"][suffix]["hubs"].append(server_name)
                        elif role_str == "consumer":
                            topology["suffixes"][suffix]["consumers"].append(server_name)

                        try:
                            agmts = replica.get_agreements()
                            for agmt in agmts.list():
                                agreement_info = {
                                    "source": server_name,
                                    "target_host": agmt.get_attr_val_utf8("nsDS5ReplicaHost"),
                                    "target_port": agmt.get_attr_val_utf8("nsDS5ReplicaPort"),
                                    "suffix": suffix,
                                    "name": agmt.get_attr_val_utf8("cn"),
                                    "enabled": agmt.get_attr_val_utf8("nsds5ReplicaEnabled") or "on",
                                }
                                topology["agreements"].append(agreement_info)
                        except Exception as e:
                            mcp.logger.warning("Error getting agreements from %s: %s", server_name, e)

                    except Exception as e:
                        mcp.logger.warning("Error processing replica on %s: %s", server_name, e)

                topology["servers"].append(server_info)

            except Exception as e:
                servers_failed.append(server_name)
                topology["findings"].append(
                    format_finding(
                        title=f"Failed to Query Server: {server_name}",
                        severity=Severity.HIGH,
                        impact="Cannot include this server in topology analysis",
                        details=str(e),
                        remediation="Check server connectivity and credentials",
                        server=server_name,
                    )
                )
            finally:
                if ds:
                    try:
                        ds.close()
                    except Exception:
                        pass

        for suffix, roles in topology["suffixes"].items():
            # Check for single supplier (no redundancy)
            if len(roles["suppliers"]) == 1 and (roles["hubs"] or roles["consumers"]):
                topology["findings"].append(
                    format_finding(
                        title=f"Single Supplier for {suffix}",
                        severity=Severity.MEDIUM,
                        impact="No supplier redundancy - single point of failure for writes",
                        details=f"Only {roles['suppliers'][0]} is a supplier for {suffix}",
                        remediation="Consider adding another supplier for high availability",
                        metadata={"suffix": suffix, "supplier": roles["suppliers"][0]},
                    )
                )

            # Check for consumers with no suppliers
            if roles["consumers"] and not roles["suppliers"]:
                topology["findings"].append(
                    format_finding(
                        title=f"Orphaned Consumers for {suffix}",
                        severity=Severity.HIGH,
                        impact="Consumer replicas exist but no suppliers are configured",
                        details=f"Consumers {roles['consumers']} have no supplier for {suffix}",
                        remediation="Investigate the replication topology configuration. Consumers exist without corresponding suppliers in the configured servers, which may indicate misconfiguration or incomplete topology setup.",
                        metadata={"suffix": suffix, "consumers": roles["consumers"]},
                    )
                )

        total_replicas = sum(len(s.get("replicas", [])) for s in topology["servers"])
        if topology["findings"]:
            summary = f"ISSUES DETECTED: Topology has {len(topology['findings'])} potential issues"
        else:
            summary = f"HEALTHY: {len(servers_checked)} servers, {total_replicas} replicas, {len(topology['agreements'])} agreements"

        topology["summary"] = summary
        topology["servers_checked"] = servers_checked
        topology["servers_failed"] = servers_failed

        return _sanitize_replication_result(mcp, topology)

    @mcp.tool()
    def check_replication_lag(
        suffix: Optional[str] = None,
        server_name: Optional[str] = None,
    ) -> Dict[str, Any]:
        """Measure replication lag by comparing supplier and consumer CSNs. LIVE only.

        Use this when ``first_look`` or ``get_replication_status`` indicates
        stale agreements. Returns per-agreement lag severity and timestamps.

        Args:
            suffix: Specific suffix to check. If not specified, checks all.
            server_name: Target server name. Uses default if not specified.

        Returns:
            Per-agreement lag status with CSN comparisons, severity
            assessment, and recommendations.
        """
        target = server_name or mcp.default_server
        if not target:
            return {
                "type": "replication_lag",
                "error": "No server configured",
            }
        require_live_server(mcp.connection_manager, target, "check_replication_lag")

        ds = None
        try:
            ds = mcp.connection_manager.connect(target)
            replicas_obj = Replicas(ds)
            replicas_list = replicas_obj.list()

            if not replicas_list:
                return _sanitize_replication_result(mcp, {
                    "type": "replication_lag",
                    "server": target,
                    "summary": "No replication configured",
                    "lag_data": [],
                })

            lag_data = []
            findings = []
            in_sync_count = 0
            lagging_count = 0
            error_count = 0

            for replica in replicas_list:
                try:
                    rep_suffix = replica.get_suffix()
                    if suffix and rep_suffix.lower() != suffix.lower():
                        continue

                    role = replica.get_role()
                    if role == ReplicaRole.CONSUMER:
                        # Consumers don't have outbound agreements
                        continue

                    agmts = replica.get_agreements()
                    for agmt in agmts.list():
                        agmt_name = agmt.get_attr_val_utf8("cn")
                        consumer_host = agmt.get_attr_val_utf8("nsDS5ReplicaHost")
                        consumer_port = agmt.get_attr_val_utf8("nsDS5ReplicaPort")

                        lag_entry = {
                            "suffix": rep_suffix,
                            "agreement": agmt_name,
                            "consumer": f"{consumer_host}:{consumer_port}",
                        }

                        try:
                            status_json = agmt.get_agmt_status(return_json=True)
                            status = json.loads(status_json)

                            lag_entry["status"] = status.get("msg", "Unknown")
                            lag_entry["supplier_csn"] = status.get("agmt_maxcsn", "Unknown")
                            lag_entry["consumer_csn"] = status.get("con_maxcsn", "Unknown")
                            lag_entry["state"] = status.get("state", "unknown")
                            lag_entry["reason"] = status.get("reason", "")

                            if status.get("msg") == "In Synchronization":
                                lag_entry["lag_status"] = "in_sync"
                                in_sync_count += 1
                            elif "Replication still in progress" in status.get("reason", ""):
                                lag_entry["lag_status"] = "syncing"
                                in_sync_count += 1
                            elif status.get("state") == "red":
                                lag_entry["lag_status"] = "error"
                                error_count += 1
                                findings.append(
                                    format_finding(
                                        title=f"Replication Error: {agmt_name}",
                                        severity=Severity.CRITICAL,
                                        impact=f"Replication to {consumer_host} is failing",
                                        details=status.get("reason", "Unknown error"),
                                        remediation="Check consumer connectivity and server logs",
                                        server=target,
                                        metadata={"agreement": agmt_name, "suffix": rep_suffix},
                                    )
                                )
                            else:
                                lag_entry["lag_status"] = "lagging"
                                lagging_count += 1

                                # Try to determine lag severity
                                supplier_csn = status.get("agmt_maxcsn", "")
                                consumer_csn = status.get("con_maxcsn", "")
                                if supplier_csn and consumer_csn and supplier_csn != "Unknown" and consumer_csn != "Unknown":
                                    findings.append(
                                        format_finding(
                                            title=f"Replication Lag Detected: {agmt_name}",
                                            severity=Severity.MEDIUM,
                                            impact=f"Consumer {consumer_host} is behind supplier",
                                            details=f"Supplier CSN: {supplier_csn}, Consumer CSN: {consumer_csn}",
                                            remediation="Check network connectivity, consumer load, and changelog",
                                            server=target,
                                            metadata={"agreement": agmt_name, "suffix": rep_suffix},
                                        )
                                    )

                        except Exception as e:
                            lag_entry["status"] = "error"
                            lag_entry["error"] = format_error_message(e)
                            lag_entry["lag_status"] = "unknown"
                            error_count += 1

                        lag_data.append(lag_entry)

                except Exception as e:
                    mcp.logger.warning("Error checking lag for replica: %s", e)

            total = in_sync_count + lagging_count + error_count
            if error_count > 0:
                summary = f"CRITICAL: {error_count} agreement(s) in error state"
            elif lagging_count > 0:
                summary = f"WARNING: {lagging_count} of {total} agreement(s) showing lag"
            elif total > 0:
                summary = f"HEALTHY: All {in_sync_count} agreement(s) in sync"
            else:
                summary = "No outbound replication agreements found"

            return _sanitize_replication_result(mcp, {
                "type": "replication_lag",
                "server": target,
                "suffix_filter": suffix,
                "summary": summary,
                "in_sync_count": in_sync_count,
                "lagging_count": lagging_count,
                "error_count": error_count,
                "lag_data": lag_data,
                "findings": findings,
            })

        except Exception as e:
            mcp.logger.error("Error checking replication lag: %s", e)
            result = format_tool_error(e, mcp, "replication_lag", server=target)
            result["lag_data"] = []
            return _sanitize_replication_result(mcp, result)
        finally:
            if ds:
                try:
                    ds.close()
                except Exception:
                    pass

    @mcp.tool()
    def list_replication_conflicts(
        base_dn: Optional[str] = None,
        server_name: Optional[str] = None,
    ) -> Dict[str, Any]:
        """Find replication conflict and glue entries that need resolution. LIVE only.

        Searches for nsds5ReplConflict attributes and glue objectclasses
        that arise from concurrent updates on multiple suppliers.

        Args:
            base_dn: Base DN to search. If not specified, searches all
                     replicated suffixes.
            server_name: Target server name. Uses default if not specified.

        Returns:
            Conflict entries with details, glue entries, counts, and
            resolution recommendations.
        """
        target = server_name or mcp.default_server
        if not target:
            return {
                "type": "replication_conflicts",
                "error": "No server configured",
            }
        require_live_server(mcp.connection_manager, target, "list_replication_conflicts")

        ds = None
        try:
            ds = mcp.connection_manager.connect(target)

            # Determine which suffixes to check
            suffixes_to_check = []
            if base_dn:
                suffixes_to_check.append(base_dn)
            else:
                # Get all replicated suffixes
                replicas_obj = Replicas(ds)
                for replica in replicas_obj.list():
                    try:
                        suffixes_to_check.append(replica.get_suffix())
                    except Exception:
                        pass

            if not suffixes_to_check:
                return _sanitize_replication_result(mcp, {
                    "type": "replication_conflicts",
                    "server": target,
                    "summary": "No replicated suffixes found",
                    "conflicts": [],
                    "glue_entries": [],
                })

            all_conflicts = []
            all_glue = []
            findings = []

            for suffix in suffixes_to_check:
                # Find conflict entries
                try:
                    conflicts = ConflictEntries(ds, suffix)
                    for conflict in conflicts.list():
                        try:
                            conflict_data = {
                                "dn": conflict.dn,
                                "suffix": suffix,
                                "conflict_attribute": conflict.get_attr_val_utf8("nsds5ReplConflict"),
                                "objectclasses": conflict.get_attr_vals_utf8("objectClass"),
                            }

                            # Try to get the valid entry it conflicts with
                            try:
                                valid_entry = conflict.get_valid_entry()
                                conflict_data["valid_entry_dn"] = valid_entry.dn
                            except Exception:
                                conflict_data["valid_entry_dn"] = "Unable to determine"

                            all_conflicts.append(conflict_data)
                        except Exception as e:
                            all_conflicts.append({"dn": str(conflict.dn), "error": str(e)})

                except Exception as e:
                    mcp.logger.warning("Error searching conflicts in %s: %s", suffix, e)

                # Find glue entries
                try:
                    glue_entries = GlueEntries(ds, suffix)
                    for glue in glue_entries.list():
                        try:
                            glue_data = {
                                "dn": glue.dn,
                                "suffix": suffix,
                                "objectclasses": glue.get_attr_vals_utf8("objectClass"),
                            }
                            all_glue.append(glue_data)
                        except Exception as e:
                            all_glue.append({"dn": str(glue.dn), "error": str(e)})

                except Exception as e:
                    mcp.logger.warning("Error searching glue entries in %s: %s", suffix, e)

            # Generate findings
            total_issues = len(all_conflicts) + len(all_glue)
            if all_conflicts:
                # Generate dsconf command examples for the first conflict
                first_conflict_dn = all_conflicts[0].get("dn", "<conflict_dn>") if all_conflicts else "<conflict_dn>"
                first_suffix = all_conflicts[0].get("suffix", suffixes_to_check[0]) if all_conflicts else suffixes_to_check[0]

                remediation_text = (
                    f"Review each conflict before resolution. Use dsconf repl-conflict commands:\n"
                    f"  1. Compare conflict with valid entry:\n"
                    f"     dsconf <instance> repl-conflict compare \"{first_conflict_dn}\"\n"
                    f"  2. Resolution options (choose based on comparison):\n"
                    f"     - Delete conflict (keep valid): dsconf <instance> repl-conflict delete \"<dn>\"\n"
                    f"     - Swap (replace valid with conflict): dsconf <instance> repl-conflict swap \"<dn>\"\n"
                    f"     - Convert (rename conflict): dsconf <instance> repl-conflict convert \"<dn>\" --new-rdn=cn=newname\n"
                    f"  3. List all conflicts: dsconf <instance> repl-conflict list {first_suffix}"
                )

                findings.append(
                    format_finding(
                        title=f"Replication Conflicts Found: {len(all_conflicts)}",
                        severity=Severity.HIGH,
                        impact="Conflict entries indicate replication issues that may cause data inconsistency",
                        details=f"Found {len(all_conflicts)} conflict entries across {len(suffixes_to_check)} suffix(es)",
                        remediation=remediation_text,
                        server=target,
                        metadata={"count": len(all_conflicts)},
                    )
                )

            if all_glue:
                first_glue_dn = all_glue[0].get("dn", "<glue_dn>") if all_glue else "<glue_dn>"

                glue_remediation = (
                    f"Glue entries are placeholders that may indicate orphaned entries. Review each glue entry:\n"
                    f"  - To delete if orphaned: ldapdelete -D \"cn=Directory Manager\" -W \"{first_glue_dn}\"\n"
                    f"  - To convert to real entry: Remove 'glue' objectclass and add appropriate attributes"
                )

                findings.append(
                    format_finding(
                        title=f"Glue Entries Found: {len(all_glue)}",
                        severity=Severity.MEDIUM,
                        impact="Glue entries are placeholders created during replication that may need attention",
                        details=f"Found {len(all_glue)} glue entries across {len(suffixes_to_check)} suffix(es)",
                        remediation=glue_remediation,
                        server=target,
                        metadata={"count": len(all_glue)},
                    )
                )

            if total_issues == 0:
                summary = f"HEALTHY: No conflicts found in {len(suffixes_to_check)} suffix(es)"
            else:
                summary = f"ISSUES FOUND: {len(all_conflicts)} conflicts, {len(all_glue)} glue entries"

            return _sanitize_replication_result(mcp, {
                "type": "replication_conflicts",
                "server": target,
                "summary": summary,
                "suffixes_checked": suffixes_to_check,
                "conflict_count": len(all_conflicts),
                "glue_count": len(all_glue),
                "conflicts": all_conflicts,
                "glue_entries": all_glue,
                "findings": findings,
            })

        except Exception as e:
            mcp.logger.error("Error searching for conflicts: %s", e)
            result = format_tool_error(e, mcp, "replication_conflicts", server=target)
            result["conflicts"] = []
            result["glue_entries"] = []
            return _sanitize_replication_result(mcp, result)
        finally:
            if ds:
                try:
                    ds.close()
                except Exception:
                    pass

    @mcp.tool()
    def get_agreement_status(
        agreement_name: Optional[str] = None,
        suffix: Optional[str] = None,
        server_name: Optional[str] = None,
    ) -> Dict[str, Any]:
        """Get detailed status for one or all replication agreements. LIVE only.

        Use this to inspect schedule, flow control, and error details for
        a specific agreement. For a broader view, use ``get_replication_status``.

        Args:
            agreement_name: Specific agreement name. If not specified,
                           returns all agreements.
            suffix: Filter agreements by suffix.
            server_name: Target server name. Uses default if not specified.

        Returns:
            Per-agreement configuration, sync status, last update
            timestamps, and error conditions.
        """
        target = server_name or mcp.default_server
        if not target:
            return {
                "type": "agreement_status",
                "error": "No server configured",
            }
        require_live_server(mcp.connection_manager, target, "get_agreement_status")

        ds = None
        try:
            ds = mcp.connection_manager.connect(target)
            replicas_obj = Replicas(ds)
            replicas_list = replicas_obj.list()

            if not replicas_list:
                return _sanitize_replication_result(mcp, {
                    "type": "agreement_status",
                    "server": target,
                    "summary": "No replication configured",
                    "agreements": [],
                })

            agreements_data = []
            findings = []

            for replica in replicas_list:
                try:
                    rep_suffix = replica.get_suffix()

                    # Filter by suffix if specified
                    if suffix and rep_suffix.lower() != suffix.lower():
                        continue

                    agmts = replica.get_agreements()
                    for agmt in agmts.list():
                        try:
                            agmt_name = agmt.get_attr_val_utf8("cn")

                            # Filter by agreement name if specified
                            if agreement_name and agmt_name.lower() != agreement_name.lower():
                                continue

                            # Get comprehensive agreement data
                            agmt_data = _get_agreement_details(agmt, mcp)
                            agmt_data["suffix"] = rep_suffix

                            # Add schedule info
                            agmt_data["schedule"] = agmt.get_attr_val_utf8("nsds5replicaupdateschedule")

                            # Add init status
                            agmt_data["last_init_status"] = agmt.get_attr_val_utf8("nsds5ReplicaLastInitStatus")
                            agmt_data["last_init_start"] = agmt.get_attr_val_utf8("nsds5ReplicaLastInitStart")
                            agmt_data["last_init_end"] = agmt.get_attr_val_utf8("nsds5ReplicaLastInitEnd")

                            # Add flow control info
                            agmt_data["flow_control_window"] = agmt.get_attr_val_utf8("nsds5ReplicaFlowControlWindow")
                            agmt_data["flow_control_pause"] = agmt.get_attr_val_utf8("nsds5ReplicaFlowControlPause")

                            # Analyze for issues
                            status = agmt_data.get("status", {})
                            if status.get("state") == "red":
                                findings.append(
                                    format_finding(
                                        title=f"Critical Agreement Error: {agmt_name}",
                                        severity=Severity.CRITICAL,
                                        impact="Agreement is in error state - replication is not working",
                                        details=status.get("reason", "Unknown error"),
                                        remediation="Check connectivity, credentials, and both server logs",
                                        server=target,
                                        metadata={"agreement": agmt_name, "suffix": rep_suffix},
                                    )
                                )

                            agreements_data.append(agmt_data)

                        except Exception as e:
                            mcp.logger.warning("Error getting agreement details: %s", e)
                            if agreement_name:
                                # If looking for specific agreement and error, report it
                                agreements_data.append({"name": agreement_name, "error": format_error_message(e)})

                except Exception as e:
                    mcp.logger.warning("Error processing replica: %s", e)

            error_count = sum(1 for a in agreements_data if a.get("status", {}).get("state") == "red")
            warning_count = sum(1 for a in agreements_data if a.get("status", {}).get("state") == "amber")

            if error_count > 0:
                summary = f"CRITICAL: {error_count} agreement(s) in error state"
            elif warning_count > 0:
                summary = f"WARNING: {warning_count} agreement(s) with warnings"
            elif agreements_data:
                summary = f"HEALTHY: {len(agreements_data)} agreement(s) operating normally"
            else:
                summary = "No agreements found matching criteria"

            return _sanitize_replication_result(mcp, {
                "type": "agreement_status",
                "server": target,
                "summary": summary,
                "filter": {
                    "agreement_name": agreement_name,
                    "suffix": suffix,
                },
                "agreement_count": len(agreements_data),
                "error_count": error_count,
                "warning_count": warning_count,
                "agreements": agreements_data,
                "findings": findings,
            })

        except Exception as e:
            mcp.logger.error("Error getting agreement status: %s", e)
            result = format_tool_error(e, mcp, "agreement_status", server=target)
            result["agreements"] = []
            return _sanitize_replication_result(mcp, result)
        finally:
            if ds:
                try:
                    ds.close()
                except Exception:
                    pass
