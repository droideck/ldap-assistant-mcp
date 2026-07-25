"""Case-oriented support workflow tools (0.6.0 case MVP).

Deterministic, bounded collectors that turn a live server, stopped
instance, or SOS archive into evidence a support case can be built on:

- ``inspect_log_coverage`` — what log evidence exists and what time span
  it covers (no raw identifiers).
- ``collect_case_snapshot`` — a bounded multi-server evidence snapshot
  with per-probe status and stable evidence IDs.
- ``correlate_incident_window`` — temporal co-occurrence of log signals
  in time buckets; reports change points, never causality.
- ``render_case_packet`` — pure rendering of a snapshot into an
  audience-appropriate Markdown packet with resolvable evidence refs.

Tools observe; workflows (prompts/Skills) own hypotheses and judgment.
"""

from __future__ import annotations

import hashlib
import json
import os
from typing import TYPE_CHECKING, Annotated, Any, Dict, List, Optional

from pydantic import Field

from fastmcp.exceptions import ToolError
from mcp.types import ToolAnnotations

from ldap_assistant_mcp.dirsrv_mcp.connection import (
    is_archive_server,
    is_local_server,
)
from ldap_assistant_mcp.dirsrv_mcp.tools.error_utils import format_error_message
from ldap_assistant_mcp.dirsrv_mcp.tools.logs import (
    _detect_json_log,
    _is_relative_range,
    _log_family_paths,
    _log_time_span,
    _parse_log_timestamp,
    _parse_time_range,
    _read_json_lines_single,
    _read_lines_single,
)

if TYPE_CHECKING:
    from ldap_assistant_mcp.dirsrv_mcp.server import DirSrvMCP

_RO = ToolAnnotations(readOnlyHint=True, idempotentHint=True, destructiveHint=False, openWorldHint=True)

# Bounded fan-out: a case snapshot never contacts more servers than this.
_MAX_SNAPSHOT_SERVERS = 25
# Correlation bucket bounds
_MIN_BUCKET_SECONDS = 60
_MAX_BUCKETS = 500

_LOG_KINDS = (("access", "access_log"), ("error", "error_log"), ("audit", "audit_log"))


def _evidence_id(payload: Any) -> str:
    """Stable, content-derived evidence ID (deterministic across runs)."""
    digest = hashlib.sha256(
        json.dumps(payload, sort_keys=True, default=str).encode()
    ).hexdigest()
    return f"ev-{digest[:12]}"


def _can_access_logs(mcp: "DirSrvMCP", server_name: str) -> bool:
    return is_local_server(mcp.connection_manager, server_name) or is_archive_server(
        mcp.connection_manager, server_name
    )


def _server_mode(mcp: "DirSrvMCP", server_name: str) -> str:
    config = mcp.connection_manager.get_config(server_name)
    if config.is_archive:
        return "archive"
    if config.is_offline:
        return "offline"
    if config.is_local:
        return "local_live"
    return "remote_live"


def _log_coverage_for(ds, include_rotated: bool) -> Dict[str, Any]:
    """Inventory the log families of one server (counts/spans, no content)."""
    coverage: Dict[str, Any] = {}
    for kind, path_attr in _LOG_KINDS:
        log_path = getattr(ds.ds_paths, path_attr, None)
        family = _log_family_paths(log_path, include_archived=include_rotated)
        if not family:
            coverage[kind] = {"present": False}
            continue
        total_bytes = 0
        for path in family:
            try:
                total_bytes += os.path.getsize(path)
            except OSError:
                pass
        current_present = bool(log_path and os.path.isfile(log_path))
        is_json = _detect_json_log(family[-1])
        try:
            first, last = _log_time_span(family[-1] if not include_rotated else log_path,
                                         is_json, kind, include_rotated)
        except Exception:
            first, last = None, None
        coverage[kind] = {
            "present": True,
            "current_file_present": current_present,
            "file_count": len(family),
            "total_bytes": total_bytes,
            "format": "json" if is_json else "traditional",
            "first_timestamp": first.isoformat() if first else None,
            "last_timestamp": last.isoformat() if last else None,
            "includes_rotated": include_rotated,
        }
    return coverage


def register_case_tools(mcp: "DirSrvMCP") -> None:
    """Register case-workflow tools with the MCP server."""

    @mcp.tool(annotations=_RO, tags={"case", "live", "offline", "archive"})
    def inspect_log_coverage(
        server_name: Optional[str] = None,
        include_rotated: bool = True,
    ) -> Dict[str, Any]:
        """Inventory what log evidence exists for a server and the time span it covers.

        The first question of any log-driven investigation: which logs are
        present (including rotations), what format they use, and what time
        window they actually cover. Returns counts, byte sizes, and
        first/last parseable timestamps — never raw log content or
        identifiers, so it is safe in every privacy mode.

        Works in LOCAL, OFFLINE, and ARCHIVE modes (needs file access).

        Args:
            server_name: Target server name. Uses default if not specified.
            include_rotated: Also inventory rotated/compressed log files.
        """
        target = server_name or mcp.default_server
        if not target:
            return {"type": "log_coverage", "error": "No server configured"}

        if not _can_access_logs(mcp, target):
            return {
                "type": "log_coverage",
                "server": target,
                "error": (
                    "Log coverage requires local or archive server access. "
                    f"Server '{target}' is a remote connection."
                ),
                "try_instead": ["get_capabilities", "first_look"],
            }

        ds = None
        try:
            ds = mcp.connection_manager.connect(target)
            coverage = _log_coverage_for(ds, include_rotated)
            spans = [
                v for v in coverage.values() if isinstance(v, dict) and v.get("last_timestamp")
            ]
            dataset_end = max((v["last_timestamp"] for v in spans), default=None)
            dataset_start = min((v["first_timestamp"] for v in spans if v.get("first_timestamp")), default=None)
            return {
                "type": "log_coverage",
                "server": target,
                "mode": _server_mode(mcp, target),
                "logs": coverage,
                "dataset_start": dataset_start,
                "dataset_end": dataset_end,
                "note": (
                    "Relative time ranges on archive evidence anchor to "
                    "dataset_end, not the current wall clock."
                ),
            }
        finally:
            if ds:
                try:
                    ds.close()
                except Exception:
                    pass

    @mcp.tool(annotations=_RO, tags={"case", "live", "offline", "archive"})
    def collect_case_snapshot(
        server_names: Optional[List[str]] = None,
        focus: Annotated[str, Field(description="Evidence focus: general, logs, or config")] = "general",
    ) -> Dict[str, Any]:
        """Collect a bounded, evidence-linked snapshot across servers for a support case.

        Deterministic collection with per-probe status: every probe either
        succeeded (its evidence carries a stable evidence ID) or its failure
        is recorded — missing evidence is never silently dropped. This is
        the substrate for case intake, timelines, and escalation packets.

        Works in ALL modes; probes degrade per mode (remote servers have no
        file evidence, archives have no live evidence).

        Args:
            server_names: Servers to snapshot (default: all configured,
                          capped at 25).
            focus: general (config + logs), logs, or config.
        """
        if focus not in ("general", "logs", "config"):
            raise ToolError("focus must be one of: general, logs, config")

        all_names = mcp.connection_manager.get_server_names()
        targets = server_names or all_names
        unknown = [n for n in targets if n not in all_names]
        if unknown:
            raise ToolError(f"Unknown server(s): {', '.join(sorted(unknown))}")
        skipped_servers = targets[_MAX_SNAPSHOT_SERVERS:]
        targets = targets[:_MAX_SNAPSHOT_SERVERS]

        evidence: Dict[str, Any] = {}
        sources = []
        probes = []
        probe_seq = 0

        def _run_probe(server: str, name: str, required: bool, fn):
            nonlocal probe_seq
            probe_seq += 1
            probe_id = f"probe-{probe_seq}"
            record = {
                "id": probe_id,
                "server": server,
                "name": name,
                "required": required,
            }
            try:
                payload = fn()
            except Exception as exc:
                record["status"] = "failed"
                record["error"] = format_error_message(exc)
                record["evidence_ref"] = None
            else:
                ev_id = _evidence_id({"server": server, "probe": name, "data": payload})
                evidence[ev_id] = {"server": server, "probe": name, "data": payload}
                record["status"] = "succeeded"
                record["evidence_ref"] = ev_id
            probes.append(record)
            return record

        for server in targets:
            mode = _server_mode(mcp, server)
            ds = None
            source = {"server": server, "mode": mode}
            try:
                ds = mcp.connection_manager.connect(server)
            except Exception as exc:
                source["condition"] = "unreachable"
                source["error"] = format_error_message(exc)
                source["evidence_status"] = "unavailable"
                sources.append(source)
                probes.append({
                    "id": f"probe-{probe_seq + 1}",
                    "server": server,
                    "name": "connect",
                    "required": True,
                    "status": "failed",
                    "error": format_error_message(exc),
                    "evidence_ref": None,
                })
                probe_seq += 1
                continue

            try:
                server_probe_start = len(probes)
                file_access = _can_access_logs(mcp, server)

                if focus in ("general", "logs") and file_access:
                    _run_probe(
                        server, "log_coverage", required=True,
                        fn=lambda ds=ds: _log_coverage_for(ds, include_rotated=True),
                    )

                if focus in ("general", "config") and mode in ("offline", "archive"):
                    def _dse_summary(ds=ds):
                        from lib389.dseldif import DSEldif

                        from ldap_assistant_mcp.dirsrv_mcp.tools.dse_utils import (
                            get_dse_ldif_path,
                        )
                        dse = DSEldif(ds, path=get_dse_ldif_path(ds))
                        return {
                            "version": dse.get("cn=config", "nsslapd-versionstring", single=True),
                            "security_enabled": (dse.get("cn=config", "nsslapd-security", single=True) or "").lower() == "on",
                        }
                    _run_probe(server, "config_summary", required=True, fn=_dse_summary)

                if focus in ("general", "config") and mode in ("remote_live", "local_live"):
                    def _live_summary(ds=ds):
                        from lib389.monitor import Monitor
                        status = Monitor(ds).get_attrs_vals_utf8(
                            ["version", "currentconnections", "opscompleted"]
                        )
                        return {
                            "version": status.get("version"),
                            "current_connections": status.get("currentconnections"),
                            "ops_completed": status.get("opscompleted"),
                        }
                    _run_probe(server, "live_summary", required=True, fn=_live_summary)

                server_probes = probes[server_probe_start:]
                failed_required = [
                    p for p in server_probes if p["required"] and p["status"] != "succeeded"
                ]
                if not server_probes:
                    source["evidence_status"] = "unavailable"
                    source["condition"] = "no_applicable_probes"
                elif failed_required:
                    source["evidence_status"] = "partial"
                    source["condition"] = "degraded_evidence"
                else:
                    source["evidence_status"] = "complete"
                    source["condition"] = "collected"
            finally:
                try:
                    ds.close()
                except Exception:
                    pass
            sources.append(source)

        attempted = len(probes)
        succeeded = sum(1 for p in probes if p["status"] == "succeeded")
        failed = attempted - succeeded
        if attempted == 0:
            evidence_status = "unavailable"
        elif failed:
            evidence_status = "partial"
        else:
            evidence_status = "complete"

        result = {
            "type": "case_snapshot",
            "focus": focus,
            "servers": targets,
            "skipped_servers": skipped_servers,
            "sources": sources,
            "probes": probes,
            "evidence": evidence,
            "coverage": {
                "attempted": attempted,
                "succeeded": succeeded,
                "failed": failed,
            },
            "evidence_status": evidence_status,
        }
        return _sanitize_case_result(mcp, result)

    @mcp.tool(annotations=_RO, tags={"case", "logs", "live", "offline", "archive"})
    def correlate_incident_window(
        server_name: Optional[str] = None,
        time_range: str = "last 24h",
        bucket_minutes: Annotated[int, Field(ge=1, le=1440)] = 15,
    ) -> Dict[str, Any]:
        """Bucket log signals over an incident window and surface change points.

        Counts error-log records by severity, access-log failed results, and
        audit changes per time bucket, then flags buckets whose activity is
        anomalously high (mean + 2 standard deviations). Reports temporal
        CO-OCCURRENCE only — a spike in the same bucket is a lead, never a
        proven cause. Counts only; no identifiers leave the tool.

        Works in LOCAL, OFFLINE, and ARCHIVE modes (needs file access).
        Relative ranges anchor to the dataset end on archives.
        """
        target = server_name or mcp.default_server
        if not target:
            return {"type": "incident_correlation", "error": "No server configured"}
        if not _can_access_logs(mcp, target):
            return {
                "type": "incident_correlation",
                "server": target,
                "error": (
                    "Correlation requires local or archive server access. "
                    f"Server '{target}' is a remote connection."
                ),
            }

        bucket_seconds = max(_MIN_BUCKET_SECONDS, bucket_minutes * 60)
        anchor_to_dataset_end = is_archive_server(mcp.connection_manager, target)

        ds = None
        try:
            ds = mcp.connection_manager.connect(target)

            buckets: Dict[int, Dict[str, int]] = {}
            counters: Dict[str, int] = {}
            windows: Dict[str, Any] = {}

            def _bucket_of(dt) -> int:
                # Parsed log timestamps are naive UTC; timestamp() would
                # interpret them as local time and shift every bucket.
                from datetime import timezone as _tz
                return int(dt.replace(tzinfo=_tz.utc).timestamp() // bucket_seconds)

            # ONE shared window for every signal kind. Anchoring each log
            # family to its own dataset end would correlate signals drawn
            # from three different time windows — the buckets would claim
            # co-occurrence across windows that never overlapped.
            shared_anchor = None
            anchor_label = "absolute"
            if time_range and _is_relative_range(time_range):
                if anchor_to_dataset_end:
                    for _kind, _path_attr in (
                        ("access", "access_log"),
                        ("error", "error_log"),
                        ("audit", "audit_log"),
                    ):
                        _log_path = getattr(ds.ds_paths, _path_attr, None)
                        _family = _log_family_paths(_log_path, include_archived=True)
                        if not _family:
                            continue
                        _, _last = _log_time_span(
                            _log_path, _detect_json_log(_family[-1]), _kind, True
                        )
                        if _last is not None and (shared_anchor is None or _last > shared_anchor):
                            shared_anchor = _last
                    anchor_label = "dataset_end" if shared_anchor else "dataset_end_unavailable"
                else:
                    anchor_label = "wall_clock"
            start_ts, end_ts = _parse_time_range(time_range, anchor=shared_anchor)
            effective = None
            if time_range and time_range.strip():
                effective = {
                    "requested": time_range,
                    "start": start_ts.isoformat() if start_ts else None,
                    "end": end_ts.isoformat() if end_ts else None,
                    "anchor": anchor_label,
                }

            def _scan(kind: str, path_attr: str, classify):
                log_path = getattr(ds.ds_paths, path_attr, None)
                family = _log_family_paths(log_path, include_archived=True)
                if not family:
                    windows[kind] = {"present": False}
                    return
                windows[kind] = {"present": True, "effective_window": effective}
                for path in family:
                    if _detect_json_log(path):
                        for jentry in _read_json_lines_single(path, counters):
                            ts = (
                                jentry.get("local_time")
                                or jentry.get("gm_time")
                                or jentry.get("date", "")
                            )
                            dt = _parse_log_timestamp(ts) if ts else None
                            if dt is None:
                                continue
                            if start_ts and dt < start_ts:
                                continue
                            if end_ts and dt > end_ts:
                                continue
                            signal = classify(json_entry=jentry, line=None)
                            if signal:
                                slot = buckets.setdefault(_bucket_of(dt), {})
                                slot[signal] = slot.get(signal, 0) + 1
                    else:
                        for line in _read_lines_single(path, counters):
                            if kind == "audit":
                                # bucket on record time lines only
                                if not line.startswith("time: "):
                                    continue
                                dt = _parse_log_timestamp(line[len("time: "):].strip())
                                signal = "audit_change"
                            else:
                                if not line.startswith("["):
                                    continue
                                closing = line.find("]")
                                if closing <= 0:
                                    continue
                                dt = _parse_log_timestamp(line[1:closing])
                                signal = classify(json_entry=None, line=line)
                            if dt is None or not signal:
                                continue
                            if start_ts and dt < start_ts:
                                continue
                            if end_ts and dt > end_ts:
                                continue
                            slot = buckets.setdefault(_bucket_of(dt), {})
                            slot[signal] = slot.get(signal, 0) + 1

            def _classify_error(json_entry=None, line=None):
                if json_entry is not None:
                    sev = str(json_entry.get("severity", "INFO")).upper()
                else:
                    sev = "INFO"
                    for candidate in ("EMERG", "ALERT", "CRIT", "ERR", "WARN"):
                        if f"- {candidate}" in line:
                            sev = candidate
                            break
                if sev in ("EMERG", "ALERT", "CRIT", "ERR"):
                    return "error_log_errors"
                if sev.startswith("WARN"):
                    return "error_log_warnings"
                return "error_log_info"

            def _classify_access(json_entry=None, line=None):
                if json_entry is not None:
                    err = json_entry.get("err", json_entry.get("result"))
                    try:
                        return "access_failed_ops" if err is not None and int(err) != 0 else "access_ops"
                    except (TypeError, ValueError):
                        return "access_ops"
                if " RESULT " in line:
                    return "access_ops" if " err=0 " in line else "access_failed_ops"
                return None

            _scan("error", "error_log", _classify_error)
            _scan("access", "access_log", _classify_access)
            _scan("audit", "audit_log", lambda json_entry=None, line=None: "audit_change")

            if len(buckets) > _MAX_BUCKETS:
                # Keep the newest buckets; report the truncation
                kept = dict(sorted(buckets.items())[-_MAX_BUCKETS:])
                truncated = len(buckets) - len(kept)
                buckets = kept
            else:
                truncated = 0

            # Change points: buckets whose activity is at least double the
            # mean of all OTHER buckets (leave-one-out), with an absolute
            # floor so near-empty windows are not flagged as anomalies.
            totals = {b: sum(v.values()) for b, v in buckets.items()}
            change_points = []
            if len(totals) >= 2:
                grand_total = sum(totals.values())
                for b, total in sorted(totals.items()):
                    others_mean = (grand_total - total) / (len(totals) - 1)
                    if total >= max(5.0, 2.0 * others_mean):
                        change_points.append({
                            "bucket_start_utc": _bucket_start_iso(b, bucket_seconds),
                            "total_records": total,
                            "signals": buckets[b],
                        })

            timeline = [
                {
                    "bucket_start_utc": _bucket_start_iso(b, bucket_seconds),
                    "signals": signals,
                }
                for b, signals in sorted(buckets.items())
            ]

            return {
                "type": "incident_correlation",
                "server": target,
                "time_range": time_range,
                "bucket_minutes": bucket_minutes,
                "windows": windows,
                "bucket_count": len(timeline),
                "buckets_truncated": truncated,
                "timeline": timeline,
                "change_points": change_points,
                "note": (
                    "Change points are temporal co-occurrence, not causes. "
                    "Correlate with known changes (deploys, config edits, "
                    "restarts) before drawing conclusions."
                ),
            }
        finally:
            if ds:
                try:
                    ds.close()
                except Exception:
                    pass

    @mcp.tool(annotations=_RO, tags={"case", "live", "offline", "archive"})
    def render_case_packet(
        snapshot: Dict[str, Any],
        audience: Annotated[str, Field(description="Rendering audience: customer, support, or engineering")] = "support",
    ) -> Dict[str, Any]:
        """Render a case snapshot into an audience-appropriate Markdown packet.

        Pure rendering: no collection happens here. Every claim in the
        packet resolves to an evidence ID from the snapshot; unresolvable
        references fail validation instead of shipping. Audiences: customer
        (impact + next steps, no internals), support (full evidence table),
        engineering (adds probe-level detail and raw evidence keys).

        Args:
            snapshot: A result from ``collect_case_snapshot``.
            audience: customer, support, or engineering.
        """
        if audience not in ("customer", "support", "engineering"):
            raise ToolError("audience must be one of: customer, support, engineering")
        if not isinstance(snapshot, dict) or snapshot.get("type") != "case_snapshot":
            raise ToolError(
                "snapshot must be a result dict from collect_case_snapshot "
                "(type='case_snapshot')"
            )

        evidence = snapshot.get("evidence") or {}
        probes = snapshot.get("probes") or []
        sources = snapshot.get("sources") or []

        # Structural validation up front: rendering indexes these fields
        # directly, so a malformed snapshot must fail with a clear message
        # instead of a KeyError mid-render.
        if not isinstance(evidence, dict):
            raise ToolError("snapshot.evidence must be a mapping of evidence IDs")
        if not isinstance(probes, list) or not isinstance(sources, list):
            raise ToolError("snapshot.probes and snapshot.sources must be lists")
        skipped = snapshot.get("skipped_servers")
        if skipped is not None and not isinstance(skipped, list):
            raise ToolError("snapshot.skipped_servers must be a list when present")
        malformed = [
            i for i, p in enumerate(probes)
            if not isinstance(p, dict)
            or not all(k in p for k in ("id", "status", "server", "name"))
            or (p.get("status") == "succeeded" and "evidence_ref" not in p)
        ]
        if malformed:
            raise ToolError(
                f"snapshot.probes[{malformed}] missing required probe fields "
                "(id, status, server, name, evidence_ref for succeeded probes)"
            )
        if not all(isinstance(s, dict) for s in sources):
            raise ToolError("snapshot.sources entries must be dicts")
        if not all(isinstance(v, dict) for v in evidence.values()):
            raise ToolError("snapshot.evidence values must be dicts")

        # Validate every evidence reference resolves
        unresolved = [
            p["id"] for p in probes
            if p.get("status") == "succeeded" and p.get("evidence_ref") not in evidence
        ]
        if unresolved:
            raise ToolError(
                f"Snapshot is internally inconsistent: probe(s) {unresolved} "
                "reference evidence that is not in the snapshot."
            )

        evidence_status = snapshot.get("evidence_status", "unknown")
        coverage = snapshot.get("coverage", {})
        lines: List[str] = []
        lines.append("# Directory Server Case Packet")
        lines.append("")
        lines.append(f"- Audience: {audience}")
        lines.append(f"- Evidence status: **{evidence_status}**")
        lines.append(
            f"- Probes: {coverage.get('succeeded', 0)} succeeded / "
            f"{coverage.get('failed', 0)} failed of {coverage.get('attempted', 0)} attempted"
        )
        if snapshot.get("skipped_servers"):
            lines.append(f"- Servers skipped by fan-out cap: {len(snapshot['skipped_servers'])}")
        lines.append("")

        lines.append("## Sources")
        for source in sources:
            condition = source.get("condition", "unknown")
            lines.append(
                f"- **{source.get('server')}** ({source.get('mode')}): {condition}, "
                f"evidence {source.get('evidence_status', 'unknown')}"
            )
        lines.append("")

        if audience == "customer":
            lines.append("## Summary")
            unreachable = [s for s in sources if s.get("condition") == "unreachable"]
            if unreachable:
                lines.append(
                    f"- {len(unreachable)} server(s) could not be reached during evidence collection."
                )
            if evidence_status != "complete":
                lines.append(
                    "- Evidence collection is incomplete; conclusions below are provisional."
                )
            else:
                lines.append("- Evidence collection completed for all reachable servers.")
            lines.append("- Detailed findings are available in the support-facing packet.")
        else:
            lines.append("## Probe results")
            for probe in probes:
                if probe["status"] == "succeeded":
                    lines.append(
                        f"- `{probe['id']}` {probe['server']}/{probe['name']}: "
                        f"succeeded -> `{probe['evidence_ref']}`"
                    )
                else:
                    lines.append(
                        f"- `{probe['id']}` {probe['server']}/{probe['name']}: "
                        f"FAILED ({probe.get('error', 'unknown error')})"
                    )
            lines.append("")
            lines.append("## Evidence index")
            for ev_id, item in evidence.items():
                lines.append(f"- `{ev_id}`: {item.get('server')}/{item.get('probe')}")
                if audience == "engineering":
                    lines.append(f"  - data: `{json.dumps(item.get('data'), default=str)[:500]}`")

        lines.append("")
        lines.append(
            "_All statements above resolve to the listed evidence IDs; "
            "anything not listed here was not observed._"
        )

        return {
            "type": "case_packet",
            "audience": audience,
            "evidence_status": evidence_status,
            "evidence_ref_count": len(evidence),
            "markdown": "\n".join(lines),
        }


def _bucket_start_iso(bucket_index: int, bucket_seconds: int) -> str:
    from datetime import datetime, timezone
    dt = datetime.fromtimestamp(bucket_index * bucket_seconds, tz=timezone.utc)
    return dt.replace(tzinfo=None).isoformat()


def _sanitize_case_result(mcp: "DirSrvMCP", result: Dict[str, Any]) -> Dict[str, Any]:
    """Sanitize a case snapshot for privacy mode."""
    if not mcp.privacy_enabled:
        return result

    sanitizer = mcp.sanitizer
    sanitized = dict(result)

    if isinstance(sanitized.get("sources"), list):
        sanitized["sources"] = [
            {**s, "error": sanitizer.sanitize_text(s["error"])}
            if isinstance(s, dict) and isinstance(s.get("error"), str)
            else s
            for s in sanitized["sources"]
        ]
    if isinstance(sanitized.get("probes"), list):
        sanitized["probes"] = [
            {**p, "error": sanitizer.sanitize_text(p["error"])}
            if isinstance(p, dict) and isinstance(p.get("error"), str)
            else p
            for p in sanitized["probes"]
        ]
    if isinstance(sanitized.get("evidence"), dict):
        new_evidence = {}
        for ev_id, item in sanitized["evidence"].items():
            data = item.get("data")
            if isinstance(data, dict):
                data = {
                    k: (sanitizer.sanitize_text(v) if isinstance(v, str) else v)
                    for k, v in data.items()
                }
            new_evidence[ev_id] = {**item, "data": data}
        sanitized["evidence"] = new_evidence
    return sanitized


__all__ = ["register_case_tools"]
