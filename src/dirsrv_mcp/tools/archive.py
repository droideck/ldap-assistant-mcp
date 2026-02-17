"""Archive-specific analysis tools for 389 Directory Server.

Two tools: ``analyze_archive`` (inventory + summary) and
``validate_configuration`` (static config lint).  Both require offline
or archive mode.
"""

from __future__ import annotations

import glob
import os
from typing import TYPE_CHECKING, Any, Dict, List, Optional

from lib389._ldifconn import LDIFConn
from lib389.dseldif import DSEldif

from src.dirsrv_mcp.connection import is_offline_or_archive
from src.dirsrv_mcp.tools.error_utils import format_error_message, format_tool_error
from src.dirsrv_mcp.tools.dse_utils import (
    dn_equals,
    find_child_dns,
    get_dse_ldif_path,
    get_rdn_value,
    is_under_dn,
)
from src.lib.result_formatter import Severity, format_finding

if TYPE_CHECKING:
    from src.dirsrv_mcp.server import DirSrvMCP


def _sanitize_server_list(mcp: "DirSrvMCP", names: List[str]) -> List[str]:
    """Sanitize a list of server names for privacy mode."""
    if not mcp.privacy_enabled:
        return list(names)
    return [mcp.sanitizer.sanitize_server_name(n) for n in names]


def _sanitize_archive_result(mcp: "DirSrvMCP", result: Dict[str, Any]) -> Dict[str, Any]:
    """Sanitize archive tool results for privacy mode.

    Dispatches to type-specific helpers based on ``result["type"]``.
    """
    if not mcp.privacy_enabled:
        return result

    sanitizer = mcp.sanitizer
    sanitized = dict(result)

    # Common keys across all archive result types — capture originals for text replacement
    original_names = {}
    for server_key in ("server", "server1", "server2"):
        if server_key in sanitized:
            original_names[server_key] = sanitized[server_key]
            sanitized[server_key] = sanitizer.sanitize_server_name(sanitized[server_key])
    if "instance_name" in sanitized:
        sanitized["instance_name"] = "[instance]"
    if "error" in sanitized and isinstance(sanitized["error"], str):
        err = sanitized["error"]
        for key, orig in original_names.items():
            if orig and orig in err:
                err = err.replace(orig, sanitized[key])
        sanitized["error"] = sanitizer._sanitize_text_field(err)
    if "findings" in sanitized and isinstance(sanitized["findings"], list):
        sanitized["findings"] = sanitizer.sanitize_findings(sanitized["findings"])

    # Type-specific sanitization
    result_type = sanitized.get("type", "")
    if result_type in ("archive_analysis", "configuration_validation"):
        _sanitize_analysis(sanitizer, sanitized)
    elif result_type == "dse_comparison":
        _sanitize_dse_comparison(sanitizer, sanitized)

    return sanitized


def _sanitize_analysis(sanitizer, sanitized: Dict[str, Any]) -> None:
    """Sanitize archive_analysis / configuration_validation results in place."""
    # Config summary
    if "config_summary" in sanitized and isinstance(sanitized["config_summary"], dict):
        cs = dict(sanitized["config_summary"])
        for k in ("suffixes",):
            if k in cs and isinstance(cs[k], list):
                cs[k] = [sanitizer.sanitize_suffix(s) for s in cs[k]]
        if "port" in cs:
            cs["port"] = "[port]"
        if "secure_port" in cs:
            cs["secure_port"] = "[port]"
        if "backends" in cs and isinstance(cs["backends"], list):
            cs["backends"] = [
                {**b, "name": "[backend]", "suffix": sanitizer.sanitize_suffix(b.get("suffix"))}
                for b in cs["backends"]
            ]
        if "replication" in cs and isinstance(cs["replication"], list):
            cs["replication"] = [
                {**r, "suffix": sanitizer.sanitize_suffix(r.get("suffix"))}
                for r in cs["replication"]
            ]
        sanitized["config_summary"] = cs

    # Available data paths
    if "available_data" in sanitized and isinstance(sanitized["available_data"], dict):
        ad = dict(sanitized["available_data"])
        for k in list(ad.keys()):
            if isinstance(ad[k], str) and ad[k].startswith("/"):
                ad[k] = "[path]"
        sanitized["available_data"] = ad

    # SOS healthcheck output
    if "sos_healthcheck" in sanitized and isinstance(sanitized["sos_healthcheck"], dict):
        hc = sanitized["sos_healthcheck"]
        safe_hc: Dict[str, Any] = {}
        if "raw_output" in hc:
            safe_hc["raw_output"] = "[redacted-healthcheck-output]"
        if "findings" in hc and isinstance(hc["findings"], list):
            safe_hc["findings"] = [
                {
                    "code": f.get("code"),
                    "severity": f.get("severity"),
                    "description": sanitizer._sanitize_text_field(f.get("description", "")),
                    "details": sanitizer._sanitize_text_field(f.get("details", "")),
                }
                for f in hc["findings"]
            ]
        # Preserve safe scalar keys (counts, booleans)
        for k in ("total_findings", "error"):
            if k in hc:
                safe_hc[k] = hc[k]
        sanitized["sos_healthcheck"] = safe_hc


def _sanitize_dse_comparison(sanitizer, sanitized: Dict[str, Any]) -> None:
    """Sanitize dse_comparison results in place."""
    for list_key in ("only_in_server1", "only_in_server2"):
        if list_key in sanitized and isinstance(sanitized[list_key], list):
            sanitized[list_key] = [sanitizer.sanitize_dn(dn) for dn in sanitized[list_key]]

    if "differences" in sanitized and isinstance(sanitized["differences"], list):
        sanitized_diffs = []
        for diff in sanitized["differences"]:
            sd = dict(diff)
            if "dn" in sd:
                sd["dn"] = sanitizer.sanitize_dn(sd["dn"])
            if "different_values" in sd and isinstance(sd["different_values"], list):
                sd["different_values"] = [
                    {
                        "attribute": dv.get("attribute"),
                        "server1": [sanitizer.sanitize_attribute_value(dv.get("attribute", ""), v) for v in dv.get("server1", [])],
                        "server2": [sanitizer.sanitize_attribute_value(dv.get("attribute", ""), v) for v in dv.get("server2", [])],
                    }
                    for dv in sd["different_values"]
                ]
            sanitized_diffs.append(sd)
        sanitized["differences"] = sanitized_diffs


def _build_archive_analysis(
    mcp: "DirSrvMCP", ds, server_name: str
) -> Dict[str, Any]:
    """Build a comprehensive analysis of an archive/offline source."""
    dse_path = get_dse_ldif_path(ds)
    dse = DSEldif(ds, path=dse_path)

    version = dse.get("cn=config", "nsslapd-versionstring", single=True)
    port = dse.get("cn=config", "nsslapd-port", single=True)
    secure_port = dse.get("cn=config", "nsslapd-secureport", single=True)
    security = dse.get("cn=config", "nsslapd-security", single=True)

    ldbm_dn = "cn=ldbm database,cn=plugins,cn=config"
    backend_dns = find_child_dns(dse, ldbm_dn)
    backends: List[Dict[str, str]] = []
    suffixes: List[str] = []
    for be_dn in backend_dns:
        suffix = dse.get(be_dn, "nsslapd-suffix", single=True)
        name = dse.get(be_dn, "cn", single=True)
        if suffix:
            backends.append({"name": name or "unknown", "suffix": suffix})
            suffixes.append(suffix)

    plugins_dn = "cn=plugins,cn=config"
    plugin_dns = find_child_dns(dse, plugins_dn)
    enabled_plugins = 0
    for p_dn in plugin_dns:
        enabled = dse.get(p_dn, "nsslapd-pluginEnabled", single=True)
        if enabled and enabled.lower() == "on":
            enabled_plugins += 1

    repl_suffixes: List[Dict[str, Any]] = []
    for line in dse._contents:
        if not line.startswith("dn: "):
            continue
        replica_dn = line[4:].rstrip("\n")
        # Only match replica entries (RDN cn=replica under mapping tree)
        rdn_attr, rdn_val = get_rdn_value(replica_dn)
        if rdn_attr != "cn" or rdn_val != "replica":
            continue
        if not is_under_dn(replica_dn, "cn=mapping tree,cn=config"):
            continue
        repl_root = dse.get(replica_dn, "nsds5replicaroot", single=True)
        repl_type = dse.get(replica_dn, "nsds5replicatype", single=True)
        repl_id = dse.get(replica_dn, "nsds5replicaid", single=True)
        role_map = {"3": "supplier", "2": "hub", "1": "consumer"}
        if repl_root:
            repl_suffixes.append({
                "suffix": repl_root,
                "role": role_map.get(repl_type, "unknown"),
                "replica_id": repl_id,
            })

    available_data: Dict[str, Any] = {
        "dse_ldif": os.path.isfile(dse_path),
    }

    paths = ds.ds_paths
    if paths.log_dir and os.path.isdir(paths.log_dir):
        available_data["logs_dir"] = True
        if paths.access_log:
            available_data["access_log"] = os.path.isfile(paths.access_log)
        if paths.error_log:
            available_data["error_log"] = os.path.isfile(paths.error_log)
        if hasattr(paths, "audit_log") and paths.audit_log:
            available_data["audit_log"] = os.path.isfile(paths.audit_log)
    else:
        available_data["logs_dir"] = False

    if hasattr(paths, "schema_dir") and paths.schema_dir:
        available_data["schema_dir"] = os.path.isdir(paths.schema_dir)
    if hasattr(paths, "cert_dir") and paths.cert_dir:
        available_data["cert_dir"] = os.path.isdir(paths.cert_dir)

    sos_healthcheck = None
    layout = getattr(ds, "_layout", None)
    sos_commands_dir = getattr(layout, "sos_commands_dir", None) if layout else None
    if sos_commands_dir and os.path.isdir(sos_commands_dir):
        available_data["sos_commands_dir"] = True
        # Look for dsctl_*_healthcheck files
        hc_files = sorted(glob.glob(os.path.join(sos_commands_dir, "dsctl_*_healthcheck")))
        if hc_files:
            from src.dirsrv_mcp.archive.healthcheck_parser import parse_healthcheck_output
            try:
                with open(hc_files[0], "r", errors="ignore") as fh:
                    content = fh.read()
                sos_healthcheck = parse_healthcheck_output(content)
            except Exception as e:
                sos_healthcheck = {"error": format_error_message(e)}

    config = mcp.connection_manager.get_config(server_name)
    if config.is_archive:
        source_type = getattr(layout, "archive_type", "archive") if layout else "archive"
    else:
        source_type = "offline_instance"

    result: Dict[str, Any] = {
        "type": "archive_analysis",
        "server": server_name,
        "source_type": source_type,
        "instance_name": ds.serverid,
        "config_summary": {
            "version": version,
            "port": port,
            "secure_port": secure_port,
            "security_enabled": security == "on" if security else False,
            "backends": backends,
            "backend_count": len(backends),
            "suffixes": suffixes,
            "total_plugins": len(plugin_dns),
            "enabled_plugins": enabled_plugins,
            "replication": repl_suffixes,
        },
        "available_data": available_data,
    }

    if sos_healthcheck is not None:
        result["sos_healthcheck"] = sos_healthcheck

    return result


_GOOD_PW_SCHEMES = {"pbkdf2_sha256", "pbkdf2-sha256", "pbkdf2_sha512", "pbkdf2-sha512",
                     "ssha512", "ssha256", "ssha"}
_GOOD_TLS_VERSIONS = {"tls1.2", "tls1.3"}


def _run_config_validation(
    mcp: "DirSrvMCP", ds, server_name: str
) -> Dict[str, Any]:
    """Run static configuration checks on dse.ldif."""
    dse_path = get_dse_ldif_path(ds)
    dse = DSEldif(ds, path=dse_path)

    findings: List[Dict[str, Any]] = []
    checks_run: List[str] = []

    checks_run.append("dseldif:nsstate")
    try:
        for result in dse._lint_nsstate() or []:
            if isinstance(result, dict):
                from src.dirsrv_mcp.tools.health import _convert_lib389_result_to_finding
                findings.append(_convert_lib389_result_to_finding(result, server_name))
    except Exception as e:
        mcp.logger.debug("DSEldif nsstate lint failed: %s", e)

    checks_run.append("config:password_scheme")
    pw_scheme = dse.get("cn=config", "nsslapd-rootpwstoragescheme", single=True)
    if pw_scheme:
        if pw_scheme.lower().replace("_", "-").replace("{", "").replace("}", "") not in _GOOD_PW_SCHEMES:
            findings.append(format_finding(
                title="Weak Password Storage Scheme",
                severity=Severity.HIGH,
                impact="Root password uses a weak hashing algorithm",
                details=f"Current scheme: {pw_scheme}. Recommended: PBKDF2_SHA256 or stronger.",
                remediation="Set nsslapd-rootpwstoragescheme to PBKDF2_SHA256",
                server=server_name,
                metadata={"attribute": "nsslapd-rootpwstoragescheme", "current": pw_scheme},
            ))

    checks_run.append("config:tls_version")
    tls_min = dse.get("cn=encryption,cn=config", "sslVersionMin", single=True)
    if tls_min:
        if tls_min.lower().replace(" ", "") not in _GOOD_TLS_VERSIONS:
            findings.append(format_finding(
                title="Weak TLS Minimum Version",
                severity=Severity.HIGH,
                impact="Server allows connections with outdated TLS protocol",
                details=f"Current minimum: {tls_min}. Recommended: TLS1.2 or higher.",
                remediation="Set sslVersionMin to TLS1.2 under cn=encryption,cn=config",
                server=server_name,
                metadata={"attribute": "sslVersionMin", "current": tls_min},
            ))

    checks_run.append("config:log_buffering")
    log_buffering = dse.get("cn=config", "nsslapd-accesslog-logbuffering", single=True)
    if log_buffering and log_buffering.lower() == "off":
        findings.append(format_finding(
            title="Access Log Buffering Disabled",
            severity=Severity.LOW,
            impact="Unbuffered logging may impact write performance",
            details="nsslapd-accesslog-logbuffering is set to off.",
            remediation="Enable access log buffering for better performance unless real-time logging is required",
            server=server_name,
            metadata={"attribute": "nsslapd-accesslog-logbuffering", "current": "off"},
        ))

    checks_run.append("config:audit_logging")
    audit_enabled = dse.get("cn=config", "nsslapd-auditlog-logging-enabled", single=True)
    if not audit_enabled or audit_enabled.lower() != "on":
        findings.append(format_finding(
            title="Audit Logging Disabled",
            severity=Severity.MEDIUM,
            impact="Directory changes are not being audited",
            details="nsslapd-auditlog-logging-enabled is not 'on'. Audit logs are essential for change tracking and compliance.",
            remediation="Enable audit logging: set nsslapd-auditlog-logging-enabled to on",
            server=server_name,
            metadata={"attribute": "nsslapd-auditlog-logging-enabled", "current": audit_enabled or "not set"},
        ))

    checks_run.append("config:security")
    security = dse.get("cn=config", "nsslapd-security", single=True)
    if not security or security.lower() != "on":
        findings.append(format_finding(
            title="TLS/SSL Security Disabled",
            severity=Severity.HIGH,
            impact="Server does not encrypt LDAP connections",
            details="nsslapd-security is not enabled. All LDAP traffic is unencrypted.",
            remediation="Enable TLS: set nsslapd-security to on and configure certificates",
            server=server_name,
            metadata={"attribute": "nsslapd-security", "current": security or "not set"},
        ))

    checks_run.append("config:anonymous_access")
    anon_access = dse.get("cn=config", "nsslapd-allow-anonymous-access", single=True)
    if anon_access and anon_access.lower() == "on":
        findings.append(format_finding(
            title="Anonymous Access Fully Enabled",
            severity=Severity.MEDIUM,
            impact="Unauthenticated users can read directory data",
            details="nsslapd-allow-anonymous-access is set to 'on'. Consider restricting to 'rootdse' or 'off'.",
            remediation="Set nsslapd-allow-anonymous-access to 'rootdse' to limit anonymous access to root DSE only",
            server=server_name,
            metadata={"attribute": "nsslapd-allow-anonymous-access", "current": anon_access},
        ))

    # Count by severity
    severity_counts = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}
    for f in findings:
        sev = f.get("severity", "info").lower()
        if sev in severity_counts:
            severity_counts[sev] += 1

    total_issues = sum(severity_counts.values())
    if severity_counts["critical"] > 0:
        summary = f"CRITICAL: {severity_counts['critical']} critical issue(s) found"
    elif severity_counts["high"] > 0:
        summary = f"WARNING: {severity_counts['high']} high-priority issue(s) found"
    elif total_issues > 0:
        summary = f"OK: {total_issues} finding(s), no critical or high severity"
    else:
        summary = f"HEALTHY: No issues found ({len(checks_run)} checks passed)"

    return {
        "type": "configuration_validation",
        "server": server_name,
        "summary": summary,
        "critical_count": severity_counts["critical"],
        "high_count": severity_counts["high"],
        "medium_count": severity_counts["medium"],
        "low_count": severity_counts["low"],
        "info_count": severity_counts["info"],
        "total_issues": total_issues,
        "findings": findings,
        "checks_run": checks_run,
    }


def _dn_matches_section(dn: str, section: Optional[str]) -> bool:
    """Check if a DN belongs to the requested section filter.

    Uses proper DN parsing via ``ldap.dn`` instead of substring matching
    to avoid false positives.
    """
    if not section or section.lower() == "all":
        return True

    sect = section.lower()

    if sect == "plugins":
        return is_under_dn(dn, "cn=plugins,cn=config")
    elif sect == "indexes":
        # Index entries live at cn=<attr>,cn=index,cn=<backend>,...
        # We accept anything that is under an "cn=index" container
        return is_under_dn(dn, "cn=plugins,cn=config") and _has_index_ancestor(dn)
    elif sect == "replication":
        return (is_under_dn(dn, "cn=mapping tree,cn=config")
                or dn_equals(dn, "cn=mapping tree,cn=config"))
    elif sect == "security":
        return (dn_equals(dn, "cn=encryption,cn=config")
                or is_under_dn(dn, "cn=encryption,cn=config"))
    elif sect == "backends":
        return (is_under_dn(dn, "cn=ldbm database,cn=plugins,cn=config")
                and not _has_index_ancestor(dn))
    elif sect == "config":
        return dn_equals(dn, "cn=config")
    return True


def _has_index_ancestor(dn: str) -> bool:
    """Return True if any RDN component (other than the leaf) is ``cn=index``."""
    try:
        import ldap.dn as _ldn
        parsed = _ldn.str2dn(dn)
        # Check RDN components beyond the leaf (index 1+)
        for rdn in parsed[1:]:
            attr, val, _ = rdn[0]
            if attr.lower() == "cn" and val.lower() == "index":
                return True
        # Also check the leaf itself for "cn=index" container entries
        if parsed:
            attr, val, _ = parsed[0][0]
            if attr.lower() == "cn" and val.lower() == "index":
                return True
    except Exception:
        pass
    return False


def _compare_ldif_entries(
    ldif1: LDIFConn,
    ldif2: LDIFConn,
    server1_name: str,
    server2_name: str,
    section: Optional[str] = None,
) -> Dict[str, Any]:
    """Compare two LDIFConn objects entry-by-entry."""
    # Get DN sets, filtered by section
    dns1 = {e.dn for e in ldif1.dnlist if _dn_matches_section(e.dn, section)}
    dns2 = {e.dn for e in ldif2.dnlist if _dn_matches_section(e.dn, section)}

    only_in_server1 = sorted(dns1 - dns2)
    only_in_server2 = sorted(dns2 - dns1)
    shared_dns = sorted(dns1 & dns2)

    differences: List[Dict[str, Any]] = []
    matching_count = 0

    for dn in shared_dns:
        entry1 = ldif1.get(dn)
        entry2 = ldif2.get(dn)

        if not entry1 or not entry2:
            continue

        attrs1 = set(entry1.getAttrs())
        attrs2 = set(entry2.getAttrs())

        attrs_only_in_1 = sorted(attrs1 - attrs2)
        attrs_only_in_2 = sorted(attrs2 - attrs1)
        different_values: List[Dict[str, Any]] = []

        for attr in sorted(attrs1 & attrs2):
            vals1 = sorted(v.decode("utf-8", errors="replace") if isinstance(v, bytes) else str(v)
                               for v in entry1.getValues(attr))
            vals2 = sorted(v.decode("utf-8", errors="replace") if isinstance(v, bytes) else str(v)
                               for v in entry2.getValues(attr))
            if vals1 != vals2:
                different_values.append({
                    "attribute": attr,
                    "server1": vals1,
                    "server2": vals2,
                })

        if attrs_only_in_1 or attrs_only_in_2 or different_values:
            differences.append({
                "dn": dn,
                "attrs_only_in_server1": attrs_only_in_1,
                "attrs_only_in_server2": attrs_only_in_2,
                "different_values": different_values,
            })
        else:
            matching_count += 1

    return {
        "type": "dse_comparison",
        "server1": server1_name,
        "server2": server2_name,
        "section": section or "all",
        "only_in_server1": only_in_server1,
        "only_in_server2": only_in_server2,
        "differences": differences,
        "matching_count": matching_count,
        "total_entries": len(dns1 | dns2),
    }


def register_archive_tools(mcp: "DirSrvMCP") -> None:
    """Register archive analysis tools with the MCP server."""

    @mcp.tool()
    def analyze_archive(
        server_name: Optional[str] = None,
    ) -> Dict[str, Any]:
        """Inventory available data in an offline or archive source.

        Reads dse.ldif to extract server version, ports, backends, suffixes,
        plugins, and replication configuration.  Checks for available log files,
        schema, and certificates.  For SOS reports, also parses any
        ``dsctl healthcheck`` output found in ``sos_commands/``.

        Use this as the first step when working with a new archive or
        offline instance. OFFLINE and ARCHIVE only.

        Args:
            server_name: Target server name. Uses default if not specified.

        Returns:
            Source type, instance name, DS version, available data inventory,
            configuration summary, and SOS healthcheck results (if present).
        """
        target = server_name or mcp.default_server
        if not target:
            return {"type": "archive_analysis", "error": "No server configured"}

        if not is_offline_or_archive(mcp.connection_manager, target):
            return _sanitize_archive_result(mcp, {
                "type": "archive_analysis",
                "server": target,
                "error": (
                    "analyze_archive requires an offline or archive server. "
                    f"Server '{target}' is a live connection."
                ),
            })

        ds = None
        try:
            ds = mcp.connection_manager.connect(target)
            result = _build_archive_analysis(mcp, ds, target)
            return _sanitize_archive_result(mcp, result)
        except Exception as e:
            mcp.logger.error("Error analyzing archive: %s", e)
            return _sanitize_archive_result(
                mcp, format_tool_error(e, mcp, "archive_analysis", server=target),
            )
        finally:
            if ds:
                try:
                    ds.close()
                except Exception:
                    pass

    @mcp.tool()
    def validate_configuration(
        server_name: Optional[str] = None,
    ) -> Dict[str, Any]:
        """Run static configuration lint on dse.ldif (like ``run_healthcheck`` but offline).

        Performs DSEldif nsstate lint plus custom checks: password storage
        scheme, TLS minimum version, access log buffering, audit logging,
        TLS/SSL enabled, and anonymous access settings.

        Use this instead of ``run_healthcheck`` for archive sources that
        cannot run full lib389 lint. OFFLINE and ARCHIVE only.

        Args:
            server_name: Target server name. Uses default if not specified.

        Returns:
            Findings in the same format as run_healthcheck, with severity,
            descriptions, and remediation steps.
        """
        target = server_name or mcp.default_server
        if not target:
            return {"type": "configuration_validation", "error": "No server configured"}

        if not is_offline_or_archive(mcp.connection_manager, target):
            return _sanitize_archive_result(mcp, {
                "type": "configuration_validation",
                "server": target,
                "error": (
                    "validate_configuration requires an offline or archive server. "
                    f"Server '{target}' is a live connection."
                ),
            })

        ds = None
        try:
            ds = mcp.connection_manager.connect(target)
            result = _run_config_validation(mcp, ds, target)
            return _sanitize_archive_result(mcp, result)
        except Exception as e:
            mcp.logger.error("Error validating configuration: %s", e)
            return _sanitize_archive_result(
                mcp, format_tool_error(e, mcp, "configuration_validation", server=target),
            )
        finally:
            if ds:
                try:
                    ds.close()
                except Exception:
                    pass

    @mcp.tool()
    def compare_dse_configs(
        server1: str,
        server2: str,
        section: Optional[str] = None,
    ) -> Dict[str, Any]:
        """Compare entire dse.ldif between two offline/archive servers entry-by-entry.

        Unlike ``compare_server_configurations`` (which only compares ``cn=config``
        attributes), this tool compares **every entry** in dse.ldif — plugins,
        backends, indexes, replication agreements, encryption, etc.

        Requires both servers to be offline or archive mode.

        Args:
            server1: First server name to compare.
            server2: Second server name to compare.
            section: Optional section filter. One of: ``all`` (default),
                ``plugins``, ``indexes``, ``replication``, ``security``,
                ``backends``, ``config``.

        Returns:
            Entries only in one server, per-entry attribute differences,
            matching count, and total entry count.
        """
        server_names = mcp.connection_manager.get_server_names()
        if server1 not in server_names:
            available = _sanitize_server_list(mcp, server_names)
            return {
                "type": "dse_comparison",
                "error": f"Server not found. Available: {', '.join(available)}",
            }
        if server2 not in server_names:
            available = _sanitize_server_list(mcp, server_names)
            return {
                "type": "dse_comparison",
                "error": f"Server not found. Available: {', '.join(available)}",
            }

        if not is_offline_or_archive(mcp.connection_manager, server1):
            return _sanitize_archive_result(mcp, {
                "type": "dse_comparison",
                "server1": server1,
                "error": (
                    "compare_dse_configs requires offline or archive servers. "
                    f"Server '{server1}' is a live connection."
                ),
            })
        if not is_offline_or_archive(mcp.connection_manager, server2):
            return _sanitize_archive_result(mcp, {
                "type": "dse_comparison",
                "server2": server2,
                "error": (
                    "compare_dse_configs requires offline or archive servers. "
                    f"Server '{server2}' is a live connection."
                ),
            })

        ds1 = None
        ds2 = None
        try:
            ds1 = mcp.connection_manager.connect(server1)
            ds2 = mcp.connection_manager.connect(server2)

            path1 = get_dse_ldif_path(ds1)
            path2 = get_dse_ldif_path(ds2)

            ldif1 = LDIFConn(path1)
            ldif2 = LDIFConn(path2)

            result = _compare_ldif_entries(ldif1, ldif2, server1, server2, section)
            return _sanitize_archive_result(mcp, result)
        except Exception as e:
            mcp.logger.error("Error comparing DSE configs: %s", e)
            return _sanitize_archive_result(
                mcp, format_tool_error(e, mcp, "dse_comparison", server1=server1, server2=server2),
            )
        finally:
            if ds1:
                try:
                    ds1.close()
                except Exception:
                    pass
            if ds2:
                try:
                    ds2.close()
                except Exception:
                    pass
