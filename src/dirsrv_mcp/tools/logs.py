"""Log parsing tools for 389 Directory Server.

Six tools for parsing and analyzing access, error, and audit logs.

- **parse_*** tools return full log entries for deep investigation.
  They require ``expose_sensitive_data`` (privacy OFF) and are blocked
  when privacy mode is on.
- **analyze_*** tools return only statistics and summaries.  They are
  always safe and work in any privacy mode.

Both tool sets work with live local servers, offline instances, and
archive sources (SOS reports).
"""

from __future__ import annotations

import glob as globmod
import gzip
import json
import os
import re
from typing import TYPE_CHECKING, Any, Dict, List, Optional

from src.dirsrv_mcp.connection import is_archive_server, is_local_server
from src.dirsrv_mcp.tools.dse_utils import dn_equals, is_under_dn
from src.dirsrv_mcp.tools.error_utils import format_tool_error
from src.lib.privacy import create_privacy_error

if TYPE_CHECKING:
    from src.dirsrv_mcp.server import DirSrvMCP


def _sanitize_pattern_text(text: str) -> str:
    """Strip DN-like patterns and hostnames from normalised error patterns.

    Applied to ``common_patterns`` in analyze tools when privacy is on.
    """
    # Strip attr=value tokens (e.g. uid=admin, cn=config)
    text = re.sub(r"\b\w+=[\w.-]+(?:,\w+=[\w.-]+)*", "[dn]", text)
    # Strip hostname-like tokens (word.word.word)
    text = re.sub(r"\b[\w-]+(?:\.[\w-]+){2,}\b", "[host]", text)
    return text


def _sanitize_log_result(mcp: "DirSrvMCP", result: Dict[str, Any]) -> Dict[str, Any]:
    """Sanitize log results for privacy mode.

    Handles both parse (full entry) and analyze (stats-only) output
    shapes — keys that are absent are simply skipped.
    """
    if not mcp.privacy_enabled:
        return result

    sanitizer = mcp.sanitizer
    sanitized = dict(result)

    if "server" in sanitized:
        sanitized["server"] = sanitizer.sanitize_server_name(sanitized["server"])

    for key in ("entries", "matches"):
        if key in sanitized and isinstance(sanitized[key], list):
            sanitized[key] = [
                _sanitize_log_entry(sanitizer, e) for e in sanitized[key]
            ]

    if "slow_operations" in sanitized and isinstance(sanitized["slow_operations"], list):
        sanitized["slow_operations"] = [
            _sanitize_log_entry(sanitizer, e) for e in sanitized["slow_operations"]
        ]

    if "common_patterns" in sanitized and isinstance(sanitized["common_patterns"], list):
        sanitized["common_patterns"] = [
            {
                "pattern": _sanitize_pattern_text(p["pattern"]),
                "count": p["count"],
            }
            if "pattern" in p
            else p
            for p in sanitized["common_patterns"]
        ]

    if "changes" in sanitized and isinstance(sanitized["changes"], list):
        sanitized["changes"] = [
            _sanitize_audit_entry(sanitizer, e) for e in sanitized["changes"]
        ]

    # Analyze-tool keys: sanitize actor DN keys
    if "actor_stats" in sanitized and isinstance(sanitized["actor_stats"], dict):
        sanitized["actor_stats"] = {
            sanitizer.sanitize_dn(k): v
            for k, v in sanitized["actor_stats"].items()
        }

    return sanitized


def _sanitize_log_entry(sanitizer, entry: Dict[str, Any]) -> Dict[str, Any]:
    """Sanitize a single log entry."""
    result = dict(entry)
    for key in ("dn", "bind_dn", "target_dn", "base"):
        if key in result and result[key]:
            result[key] = sanitizer.sanitize_dn(result[key])
    if "filter" in result:
        result["filter"] = "[filter]"
    if "message" in result:
        result["message"] = sanitizer._sanitize_text_field(result["message"])
    if "raw" in result:
        result["raw"] = "[raw-line]"
    return result


def _sanitize_audit_entry(sanitizer, entry: Dict[str, Any]) -> Dict[str, Any]:
    """Sanitize an audit log change entry."""
    result = dict(entry)
    if "dn" in result:
        result["dn"] = sanitizer.sanitize_dn(result["dn"])
    if "bind_dn" in result:
        result["bind_dn"] = sanitizer.sanitize_dn(result["bind_dn"])
    if "target_dn" in result:
        result["target_dn"] = sanitizer.sanitize_dn(result["target_dn"])
    if "changes" in result:
        result["changes"] = "[redacted]"
    if "raw" in result:
        result["raw"] = "[raw-block]"
    return result


def _can_access_logs(mcp: "DirSrvMCP", server_name: str) -> bool:
    """Return True if the server has local file access (local or archive)."""
    return (
        is_local_server(mcp.connection_manager, server_name)
        or is_archive_server(mcp.connection_manager, server_name)
    )


def _detect_json_log(log_path: str) -> bool:
    """Detect if a log file is JSON-formatted by reading the first non-empty line.

    Traditional DS logs start with ``[DD/Mon/YYYY:...]`` which must not be
    mistaken for a JSON array.  We only treat a leading ``{`` as JSON.
    """
    try:
        with open(log_path, "r", errors="ignore") as fh:
            for line in fh:
                stripped = line.strip()
                if not stripped:
                    continue
                return stripped.startswith("{")
    except (OSError, IOError):
        pass
    return False


def _parse_time_range(time_range: Optional[str]):
    """Parse a time_range string into (start, end) datetime or None.

    Supports formats like:
      - ``"2024-01-01"`` (start only)
      - ``"2024-01-01 to 2024-01-02"``
      - ``"last 1h"`` / ``"last 24h"``

    Returns ``(start_str, end_str)`` — raw strings for prefix matching
    against log timestamps, or (None, None) if not parseable.
    """
    if not time_range:
        return None, None

    time_range = time_range.strip()

    # Handle "last Xh" or "last Xm"
    m = re.match(r"last\s+(\d+)\s*([hm])", time_range, re.IGNORECASE)
    if m:
        from datetime import datetime, timedelta, timezone
        amount = int(m.group(1))
        unit = m.group(2).lower()
        now = datetime.now(timezone.utc)
        if unit == "h":
            start = now - timedelta(hours=amount)
        else:
            start = now - timedelta(minutes=amount)
        return start.strftime("%Y-%m-%d"), None

    # "start to end"
    if " to " in time_range:
        parts = time_range.split(" to ", 1)
        return parts[0].strip(), parts[1].strip()

    # Single date/datetime
    return time_range, None


def _timestamp_in_range(ts: Optional[str], start: Optional[str], end: Optional[str]) -> bool:
    """Check whether a timestamp string falls in the given range via prefix comparison."""
    if not ts:
        return True
    if start and ts < start:
        return False
    if end and ts > end:
        return False
    return True


def _dn_matches_filter(entry_dn: str, filter_dn: str) -> bool:
    """Check if *entry_dn* matches a DN filter (equals or is descendant).

    Uses proper DN parsing so that ``cn=admin`` does **not** match
    ``cn=administrator``.
    """
    return dn_equals(entry_dn, filter_dn) or is_under_dn(entry_dn, filter_dn)


def _validate_regex(pattern: Optional[str]) -> tuple:
    """Validate and compile a user-supplied regex pattern.

    Returns ``(compiled_re | None, error_dict | None)``.
    If the pattern is None or empty, returns ``(None, None)``.
    """
    if not pattern:
        return None, None
    if len(pattern) > 1000:
        return None, {"error": "Pattern too long (max 1000 chars)"}
    try:
        return re.compile(pattern, re.IGNORECASE), None
    except re.error as exc:
        return None, {"error": f"Invalid regex pattern: {exc}"}


def _matches_audit_filters(
    entry_dn: str,
    entry_bind: str,
    changetype: str,
    timestamp: str,
    op_lower: Optional[str],
    target_dn: Optional[str],
    bind_dn: Optional[str],
    start_ts: Optional[str],
    end_ts: Optional[str],
) -> bool:
    """Return True if an audit log entry passes all active filters."""
    if op_lower and changetype != op_lower:
        return False
    if target_dn and not _dn_matches_filter(entry_dn, target_dn):
        return False
    if bind_dn and not _dn_matches_filter(entry_bind, bind_dn):
        return False
    if not _timestamp_in_range(timestamp, start_ts, end_ts):
        return False
    return True


# lib389's access-log parse_line() does not extract RESULT fields (err,
# etime, notes) from current DS log formats, and its error-log parser
# does not parse severity or component.  These lightweight parsers use
# re.search() to handle all format variations reliably.
#
# lib389's log parsing will be improved in the future; when that lands
# these helpers can be replaced — the field names and tool logic are
# kept compatible so the switch will be straightforward.


def _read_log_lines(log_path: str, include_archived: bool = False) -> List[str]:
    """Read lines from a log file, optionally including rotated/compressed logs."""
    lines: List[str] = []
    if include_archived:
        for path in globmod.glob(f"{log_path}.*-*") + [log_path]:
            try:
                if path.endswith(".gz"):
                    with gzip.open(path, "rt", errors="replace") as fh:
                        lines += fh.readlines()
                else:
                    with open(path, "r", errors="replace") as fh:
                        lines += fh.readlines()
            except OSError:
                continue
    else:
        with open(log_path, "r", errors="replace") as fh:
            lines = fh.readlines()
    return lines

_ACCESS_TS_RE = re.compile(r"^\[(?P<timestamp>[^\]]+)\]\s*(?P<rest>.*)")
_ACCESS_RESULT_RE = re.compile(
    r"err=(?P<err>\d+)\s+tag=(?P<tag>\d+)\s+nentries=(?P<nentries>\d+)"
)
_ACCESS_ETIME_RE = re.compile(r"etime=(?P<etime>[0-9.]+)")
_ACCESS_NOTES_RE = re.compile(r"notes=(?P<notes>\w+)")

_ACCESS_ACTIONS = {
    "SRCH", "MOD", "ADD", "DEL", "MODRDN", "CMP", "ABANDON",
    "BIND", "UNBIND", "AUTOBIND", "RESULT", "EXT",
}


def _parse_access_line(line: str) -> Optional[Dict[str, str]]:
    """Parse a traditional DS access log line.

    Handles standard ops, internal ops, connections, disconnects,
    AUTOBIND, and EXT.  Returns None for non-log lines (headers).
    """
    m = _ACCESS_TS_RE.match(line.strip())
    if not m:
        return None

    result: Dict[str, str] = {"timestamp": f"[{m.group('timestamp')}]"}
    rest = m.group("rest")

    # Find the action keyword
    for token in rest.split():
        if token in _ACCESS_ACTIONS:
            result["action"] = token
            break
        if token in ("connection", "closed"):
            result["action"] = "CONNECT" if token == "connection" else "DISCONNECT"
            break

    if result.get("action") == "RESULT":
        rm = _ACCESS_RESULT_RE.search(rest)
        if rm:
            result.update(rm.groupdict())
        em = _ACCESS_ETIME_RE.search(rest)
        if em:
            result["etime"] = em.group("etime")
        nm = _ACCESS_NOTES_RE.search(rest)
        if nm:
            result["notes"] = nm.group("notes")

    return result


_ERROR_TS_RE = re.compile(
    r"^\[(?P<timestamp>[^\]]+)\]\s*-\s*(?P<severity>\w+)\s*-\s*"
    r"(?P<component>\S+)\s*-\s*(?P<message>.*)"
)


def _parse_error_line(line: str) -> Optional[Dict[str, str]]:
    """Parse a traditional DS error log line.

    Returns None for non-log lines (headers, continuation text).
    """
    m = _ERROR_TS_RE.match(line.strip())
    if not m:
        return None
    return m.groupdict()


def _parse_access_log_entries(
    ds,
    operation: Optional[str],
    result_code: Optional[int],
    time_range: Optional[str],
    pattern: Optional[str],
    include_archived: bool,
    limit: int,
    stats_only: bool = False,
) -> Dict[str, Any]:
    """Parse access log and return structured results.

    When *stats_only* is True, individual entries and slow-op details are
    omitted — only aggregate statistics are returned.
    """
    from lib389.dirsrv_log import DirsrvAccessJSONLog

    log_path = ds.ds_paths.access_log
    if not log_path or not os.path.isfile(log_path):
        return {"error": f"Access log not found at {log_path}"}

    start_ts, end_ts = _parse_time_range(time_range)
    pattern_re, regex_err = _validate_regex(pattern)
    if regex_err:
        return regex_err
    op_upper = operation.upper() if operation else None

    entries: List[Dict[str, Any]] = []
    op_stats: Dict[str, int] = {}
    failed_ops: Dict[int, int] = {}
    slow_ops: List[Dict[str, Any]] = []
    total_parsed = 0
    # Stats-only accumulators for slow-op summary
    slow_count = 0
    slow_max = 0.0
    slow_sum = 0.0
    unindexed_count = 0

    is_json = _detect_json_log(log_path)

    if is_json:
        log_obj = DirsrvAccessJSONLog(ds)
        json_entries = log_obj.parse_log()
        for jentry in json_entries:
            if not isinstance(jentry, dict):
                continue
            total_parsed += 1
            action = jentry.get("op_type", jentry.get("action", ""))
            if op_upper and action.upper() != op_upper:
                continue
            err = jentry.get("result", jentry.get("err"))
            if result_code is not None and err is not None:
                try:
                    if int(err) != result_code:
                        continue
                except (ValueError, TypeError):
                    continue
            ts = jentry.get("local_time", jentry.get("date", ""))
            if not _timestamp_in_range(ts, start_ts, end_ts):
                continue
            raw_str = json.dumps(jentry)
            if pattern_re and not pattern_re.search(raw_str):
                continue

            op_stats[action] = op_stats.get(action, 0) + 1
            if err is not None:
                try:
                    err_int = int(err)
                    if err_int != 0:
                        failed_ops[err_int] = failed_ops.get(err_int, 0) + 1
                except (ValueError, TypeError):
                    pass

            etime = jentry.get("etime")
            if etime is not None:
                try:
                    etime_f = float(etime)
                    if etime_f > 1.0:
                        slow_count += 1
                        slow_sum += etime_f
                        if etime_f > slow_max:
                            slow_max = etime_f
                        if not stats_only:
                            slow_ops.append({"etime": etime_f, **jentry})
                except (ValueError, TypeError):
                    pass

            notes = jentry.get("notes", "")
            if notes and ("U" in notes or "A" in notes):
                unindexed_count += 1

            if not stats_only and len(entries) < limit:
                entries.append(jentry)
    else:
        for line in _read_log_lines(log_path, include_archived):
            if not line.strip():
                continue
            total_parsed += 1
            parsed = _parse_access_line(line)
            if not parsed:
                continue
            action = parsed.get("action", "")
            if op_upper and action.upper() != op_upper:
                continue
            err = parsed.get("err")
            if result_code is not None and err is not None:
                try:
                    if int(err) != result_code:
                        continue
                except (ValueError, TypeError):
                    continue
            ts = parsed.get("timestamp", "")
            if not _timestamp_in_range(ts, start_ts, end_ts):
                continue
            if pattern_re and not pattern_re.search(line):
                continue

            op_stats[action] = op_stats.get(action, 0) + 1
            if err is not None:
                try:
                    err_int = int(err)
                    if err_int != 0:
                        failed_ops[err_int] = failed_ops.get(err_int, 0) + 1
                except (ValueError, TypeError):
                    pass

            etime = parsed.get("etime")
            if etime is not None:
                try:
                    etime_f = float(etime)
                    if etime_f > 1.0:
                        slow_count += 1
                        slow_sum += etime_f
                        if etime_f > slow_max:
                            slow_max = etime_f
                        if not stats_only:
                            slow_ops.append({"etime": etime_f, "raw": line.rstrip(), **parsed})
                except (ValueError, TypeError):
                    pass

            notes = parsed.get("notes", "")
            if notes and ("U" in notes or "A" in notes):
                unindexed_count += 1

            if not stats_only and len(entries) < limit:
                entries.append({**parsed, "raw": line.rstrip()})

    if stats_only:
        result: Dict[str, Any] = {
            "total_parsed": total_parsed,
            "matched_count": sum(op_stats.values()),
            "operation_stats": op_stats,
            "failed_operations": {str(k): v for k, v in sorted(failed_ops.items())},
            "slow_operation_summary": {
                "count": slow_count,
                "max_etime": slow_max,
                "avg_etime": round(slow_sum / slow_count, 6) if slow_count else 0.0,
            },
            "unindexed_search_count": unindexed_count,
        }
        return result

    slow_ops.sort(key=lambda x: x.get("etime", 0), reverse=True)

    return {
        "entries": entries,
        "total_parsed": total_parsed,
        "matched_count": sum(op_stats.values()),
        "operation_stats": op_stats,
        "failed_operations": {str(k): v for k, v in sorted(failed_ops.items())},
        "slow_operations": slow_ops[:20],
    }


_ERROR_SEVERITY_RE = re.compile(
    r"-\s+(EMERG|ALERT|CRIT|ERR|WARN|WARNING|NOTICE|INFO|DEBUG)\s+-"
)


def _parse_error_log_entries(
    ds,
    severity: Optional[str],
    component: Optional[str],
    time_range: Optional[str],
    pattern: Optional[str],
    limit: int,
    stats_only: bool = False,
) -> Dict[str, Any]:
    """Parse error log and return structured results.

    When *stats_only* is True, individual entries are omitted — only
    aggregate statistics (severity_counts, component_counts,
    common_patterns) are returned.
    """
    from lib389.dirsrv_log import DirsrvErrorJSONLog

    log_path = ds.ds_paths.error_log
    if not log_path or not os.path.isfile(log_path):
        return {"error": f"Error log not found at {log_path}"}

    start_ts, end_ts = _parse_time_range(time_range)
    pattern_re, regex_err = _validate_regex(pattern)
    if regex_err:
        return regex_err
    sev_upper = severity.upper() if severity else None

    entries: List[Dict[str, Any]] = []
    severity_counts: Dict[str, int] = {}
    component_counts: Dict[str, int] = {}
    total_parsed = 0
    matched_count = 0
    pattern_counts: Dict[str, int] = {}

    is_json = _detect_json_log(log_path)

    if is_json:
        log_obj = DirsrvErrorJSONLog(ds)
        json_entries = log_obj.parse_log()
        for jentry in json_entries:
            if not isinstance(jentry, dict):
                continue
            total_parsed += 1
            entry_sev = jentry.get("severity", "INFO").upper()
            severity_counts[entry_sev] = severity_counts.get(entry_sev, 0) + 1
            if sev_upper and entry_sev != sev_upper:
                continue
            entry_comp = jentry.get("subsystem", "")
            if component and component.lower() not in entry_comp.lower():
                continue
            ts = jentry.get("local_time", "")
            if not _timestamp_in_range(ts, start_ts, end_ts):
                continue
            raw_str = json.dumps(jentry)
            if pattern_re and not pattern_re.search(raw_str):
                continue

            matched_count += 1
            if entry_comp:
                component_counts[entry_comp] = component_counts.get(entry_comp, 0) + 1

            msg = jentry.get("msg", jentry.get("message", ""))
            _track_pattern(pattern_counts, msg)

            if not stats_only and len(entries) < limit:
                entries.append(jentry)
    else:
        for line in _read_log_lines(log_path):
            if not line.strip():
                continue
            total_parsed += 1
            parsed = _parse_error_line(line) or {}

            entry_sev = parsed.get("severity", "").upper()
            if not entry_sev:
                sev_match = _ERROR_SEVERITY_RE.search(line)
                entry_sev = sev_match.group(1) if sev_match else "INFO"
            severity_counts[entry_sev] = severity_counts.get(entry_sev, 0) + 1

            if sev_upper and entry_sev != sev_upper:
                continue

            entry_comp = parsed.get("component", "")
            if component:
                if not entry_comp or component.lower() not in entry_comp.lower():
                    continue

            ts = parsed.get("timestamp", "")
            if not _timestamp_in_range(ts, start_ts, end_ts):
                continue
            if pattern_re and not pattern_re.search(line):
                continue

            matched_count += 1
            if entry_comp:
                component_counts[entry_comp] = component_counts.get(entry_comp, 0) + 1

            msg = parsed.get("message", line)
            _track_pattern(pattern_counts, msg)

            if not stats_only:
                parsed["severity"] = entry_sev
                parsed["raw"] = line.rstrip()
                if len(entries) < limit:
                    entries.append(parsed)

    if stats_only:
        common_patterns = [
            {"pattern": p, "count": c}
            for p, c in sorted(pattern_counts.items(), key=lambda x: -x[1])[:10]
        ]
        return {
            "total_parsed": total_parsed,
            "matched_count": matched_count,
            "severity_counts": severity_counts,
            "component_counts": component_counts,
            "common_patterns": common_patterns,
        }

    common_patterns = [
        {"pattern": p, "count": c, "example": p[:80]}
        for p, c in sorted(pattern_counts.items(), key=lambda x: -x[1])[:10]
    ]

    return {
        "entries": entries,
        "total_parsed": total_parsed,
        "matched_count": matched_count,
        "severity_counts": severity_counts,
        "component_counts": component_counts,
        "common_patterns": common_patterns,
    }


def _track_pattern(counts: Dict[str, int], message: str) -> None:
    """Track common error patterns by normalising the message."""
    normalised = re.sub(r"\d+", "N", message.strip())
    normalised = re.sub(r"\s+", " ", normalised)[:120]
    if normalised:
        counts[normalised] = counts.get(normalised, 0) + 1


_AUDIT_TIME_RE = re.compile(r"^time:\s+(\d+)$")
_AUDIT_DN_RE = re.compile(r"^dn:\s+(.+)$")


def _parse_audit_log_traditional(lines: List[str]) -> List[Dict[str, Any]]:
    """Parse traditional LDIF-style audit log into change records."""
    records: List[Dict[str, Any]] = []
    current: Optional[Dict[str, Any]] = None
    current_lines: List[str] = []

    for line in lines:
        line = line.rstrip("\n")

        time_m = _AUDIT_TIME_RE.match(line)
        if time_m:
            if current is not None:
                current["raw"] = "\n".join(current_lines)
                records.append(current)
            current = {"time": time_m.group(1)}
            current_lines = [line]
            continue

        if current is None:
            continue

        current_lines.append(line)

        dn_m = _AUDIT_DN_RE.match(line)
        if dn_m and "dn" not in current:
            current["dn"] = dn_m.group(1)
            continue

        if line.startswith("changetype: "):
            current["changetype"] = line[len("changetype: "):]
        elif line.startswith("modifiersname: "):
            current["bind_dn"] = line[len("modifiersname: "):]
        elif line.startswith("creatorsname: "):
            current.setdefault("bind_dn", line[len("creatorsname: "):])

    if current is not None:
        current["raw"] = "\n".join(current_lines)
        records.append(current)

    return records


def _parse_audit_log_entries(
    ds,
    operation: Optional[str],
    bind_dn: Optional[str],
    target_dn: Optional[str],
    time_range: Optional[str],
    limit: int,
    stats_only: bool = False,
) -> Dict[str, Any]:
    """Parse audit log and return structured results.

    When *stats_only* is True, individual change records are omitted —
    only aggregate statistics are returned.
    """
    from lib389.dirsrv_log import DirsrvAuditJSONLog

    log_path = ds.ds_paths.audit_log
    if not log_path or not os.path.isfile(log_path):
        return {"error": f"Audit log not found at {log_path}"}

    start_ts, end_ts = _parse_time_range(time_range)
    op_lower = operation.lower() if operation else None

    changes: List[Dict[str, Any]] = []
    change_type_counts: Dict[str, int] = {}
    actor_counts: Dict[str, int] = {}
    total_parsed = 0
    matched_count = 0

    is_json = _detect_json_log(log_path)

    if is_json:
        log_obj = DirsrvAuditJSONLog(ds)
        json_entries = log_obj.parse_log()
        for jentry in json_entries:
            if not isinstance(jentry, dict):
                continue
            total_parsed += 1
            ct = jentry.get("changetype", jentry.get("op_type", "")).lower()
            change_type_counts[ct] = change_type_counts.get(ct, 0) + 1

            entry_dn = jentry.get("dn", "")
            entry_bind = jentry.get("modifiersname", jentry.get("bind_dn", ""))
            ts = jentry.get("gm_time", jentry.get("date", ""))

            if not _matches_audit_filters(
                entry_dn, entry_bind, ct, ts,
                op_lower, target_dn, bind_dn, start_ts, end_ts,
            ):
                continue

            matched_count += 1
            actor_counts[entry_bind] = actor_counts.get(entry_bind, 0) + 1

            if not stats_only and len(changes) < limit:
                changes.append(jentry)
    else:
        # Traditional LDIF-style audit log — use our own parser
        try:
            with open(log_path, "r", errors="ignore") as fh:
                raw_lines = fh.readlines()
        except OSError:
            return {"error": f"Could not read audit log at {log_path}"}

        records = _parse_audit_log_traditional(raw_lines)
        for rec in records:
            total_parsed += 1
            ct = rec.get("changetype", "unknown").lower()
            change_type_counts[ct] = change_type_counts.get(ct, 0) + 1

            entry_dn = rec.get("dn", "")
            entry_bind = rec.get("bind_dn", "")
            ts = rec.get("time", "")

            if not _matches_audit_filters(
                entry_dn, entry_bind, ct, ts,
                op_lower, target_dn, bind_dn, start_ts, end_ts,
            ):
                continue

            matched_count += 1
            actor_counts[entry_bind] = actor_counts.get(entry_bind, 0) + 1

            if not stats_only and len(changes) < limit:
                changes.append(rec)

    if stats_only:
        return {
            "total_parsed": total_parsed,
            "matched_count": matched_count,
            "change_type_stats": change_type_counts,
            "actor_stats": actor_counts,
        }

    return {
        "changes": changes,
        "total_parsed": total_parsed,
        "matched_count": matched_count,
        "change_type_stats": change_type_counts,
        "actor_stats": actor_counts,
    }


def register_log_tools(mcp: "DirSrvMCP") -> None:
    """Register log parsing and analysis tools with the MCP server."""

    # ------------------------------------------------------------------
    # Parse tools — full entry detail, require expose_sensitive_data
    # ------------------------------------------------------------------

    @mcp.tool()
    def parse_access_log(
        server_name: Optional[str] = None,
        operation: Optional[str] = None,
        result_code: Optional[int] = None,
        time_range: Optional[str] = None,
        pattern: Optional[str] = None,
        include_archived_logs: bool = False,
        limit: int = 100,
    ) -> Dict[str, Any]:
        """Parse access log entries with full detail (requires expose_sensitive_data).

        Works with live local servers, offline instances, and archive sources.

        Args:
            server_name: Target server name. Uses default if not specified.
            operation: Filter by operation type (SRCH, MOD, ADD, DEL, BIND, etc.).
            result_code: Filter by LDAP result code (e.g. 0 for success, 32 for not found).
            time_range: Time range filter. Supports:
                - Single date: "2024-01-01"
                - Range: "2024-01-01 to 2024-01-02"
                - Relative: "last 24h", "last 30m"
            pattern: Regex pattern to match against log lines.
            include_archived_logs: Include rotated/compressed log files.
            limit: Maximum entries to return (default 100).

        Returns:
            Matching entries, operation statistics, failed operations summary,
            and slow operations (sorted by elapsed time).
        """
        if mcp.privacy_enabled:
            return create_privacy_error("parse_access_log")

        target = server_name or mcp.default_server
        if not target:
            return {"type": "access_log", "error": "No server configured"}

        if not _can_access_logs(mcp, target):
            return {
                "type": "access_log",
                "error": (
                    "Log parsing requires local or archive server access. "
                    f"Server '{target}' is a remote connection."
                ),
            }

        ds = None
        try:
            ds = mcp.connection_manager.connect(target)
            data = _parse_access_log_entries(
                ds, operation, result_code, time_range,
                pattern, include_archived_logs, max(1, limit),
            )
            result = {"type": "access_log", "server": target, **data}
            return _sanitize_log_result(mcp, result)
        except Exception as e:
            mcp.logger.error("Error parsing access log: %s", e)
            return _sanitize_log_result(
                mcp, format_tool_error(e, mcp, "access_log", server=target),
            )
        finally:
            if ds:
                try:
                    ds.close()
                except Exception:
                    pass

    @mcp.tool()
    def parse_error_log(
        server_name: Optional[str] = None,
        severity: Optional[str] = None,
        component: Optional[str] = None,
        time_range: Optional[str] = None,
        pattern: Optional[str] = None,
        limit: int = 100,
    ) -> Dict[str, Any]:
        """Parse error log entries with full detail (requires expose_sensitive_data).

        Works with live local servers, offline instances, and archive sources.

        Args:
            server_name: Target server name. Uses default if not specified.
            severity: Filter by severity level (INFO, WARNING, ERR, CRIT, EMERG).
            component: Filter by component name (e.g. "replication", "backend").
            time_range: Time range filter (same format as parse_access_log).
            pattern: Regex pattern to match against log lines.
            limit: Maximum entries to return (default 100).

        Returns:
            Matching entries, severity counts, component counts, and common error patterns.
        """
        if mcp.privacy_enabled:
            return create_privacy_error("parse_error_log")

        target = server_name or mcp.default_server
        if not target:
            return {"type": "error_log", "error": "No server configured"}

        if not _can_access_logs(mcp, target):
            return {
                "type": "error_log",
                "error": (
                    "Log parsing requires local or archive server access. "
                    f"Server '{target}' is a remote connection."
                ),
            }

        ds = None
        try:
            ds = mcp.connection_manager.connect(target)
            data = _parse_error_log_entries(
                ds, severity, component, time_range,
                pattern, max(1, limit),
            )
            result = {"type": "error_log", "server": target, **data}
            return _sanitize_log_result(mcp, result)
        except Exception as e:
            mcp.logger.error("Error parsing error log: %s", e)
            return _sanitize_log_result(
                mcp, format_tool_error(e, mcp, "error_log", server=target),
            )
        finally:
            if ds:
                try:
                    ds.close()
                except Exception:
                    pass

    @mcp.tool()
    def parse_audit_log(
        server_name: Optional[str] = None,
        operation: Optional[str] = None,
        bind_dn: Optional[str] = None,
        target_dn: Optional[str] = None,
        time_range: Optional[str] = None,
        limit: int = 100,
    ) -> Dict[str, Any]:
        """Parse audit log entries with full detail (requires expose_sensitive_data).

        Works with live local servers, offline instances, and archive sources.
        Handles both traditional LDIF-format and JSON-format audit logs.

        Args:
            server_name: Target server name. Uses default if not specified.
            operation: Filter by change type (modify, add, delete, modrdn).
            bind_dn: Filter by the DN that performed the change.
            target_dn: Filter by the target DN that was changed.
            time_range: Time range filter (same format as parse_access_log).
            limit: Maximum entries to return (default 100).

        Returns:
            Change entries, change type statistics, and actor statistics.
        """
        if mcp.privacy_enabled:
            return create_privacy_error("parse_audit_log")

        target = server_name or mcp.default_server
        if not target:
            return {"type": "audit_log", "error": "No server configured"}

        if not _can_access_logs(mcp, target):
            return {
                "type": "audit_log",
                "error": (
                    "Log parsing requires local or archive server access. "
                    f"Server '{target}' is a remote connection."
                ),
            }

        ds = None
        try:
            ds = mcp.connection_manager.connect(target)
            data = _parse_audit_log_entries(
                ds, operation, bind_dn, target_dn,
                time_range, max(1, limit),
            )
            result = {"type": "audit_log", "server": target, **data}
            return _sanitize_log_result(mcp, result)
        except Exception as e:
            mcp.logger.error("Error parsing audit log: %s", e)
            return _sanitize_log_result(
                mcp, format_tool_error(e, mcp, "audit_log", server=target),
            )
        finally:
            if ds:
                try:
                    ds.close()
                except Exception:
                    pass

    # ------------------------------------------------------------------
    # Analyze tools — statistics only, safe in all privacy modes
    # ------------------------------------------------------------------

    @mcp.tool()
    def analyze_access_log(
        server_name: Optional[str] = None,
        operation: Optional[str] = None,
        result_code: Optional[int] = None,
        time_range: Optional[str] = None,
        pattern: Optional[str] = None,
        include_archived_logs: bool = False,
    ) -> Dict[str, Any]:
        """Analyze access log statistics (operations, errors, slow queries).

        Returns aggregate statistics only — no individual log entries.
        Safe to use in privacy mode.

        Args:
            server_name: Target server name. Uses default if not specified.
            operation: Filter by operation type (SRCH, MOD, ADD, DEL, BIND, etc.).
            result_code: Filter by LDAP result code (e.g. 0 for success, 32 for not found).
            time_range: Time range filter. Supports:
                - Single date: "2024-01-01"
                - Range: "2024-01-01 to 2024-01-02"
                - Relative: "last 24h", "last 30m"
            pattern: Regex pattern to match against log lines.
            include_archived_logs: Include rotated/compressed log files.

        Returns:
            Operation statistics, failed operations, slow operation summary,
            and unindexed search count.
        """
        target = server_name or mcp.default_server
        if not target:
            return {"type": "access_log_analysis", "error": "No server configured"}

        if not _can_access_logs(mcp, target):
            return {
                "type": "access_log_analysis",
                "error": (
                    "Log analysis requires local or archive server access. "
                    f"Server '{target}' is a remote connection."
                ),
            }

        ds = None
        try:
            ds = mcp.connection_manager.connect(target)
            data = _parse_access_log_entries(
                ds, operation, result_code, time_range,
                pattern, include_archived_logs, 0,
                stats_only=True,
            )
            result = {"type": "access_log_analysis", "server": target, **data}
            return _sanitize_log_result(mcp, result)
        except Exception as e:
            mcp.logger.error("Error analyzing access log: %s", e)
            return _sanitize_log_result(
                mcp, format_tool_error(e, mcp, "access_log_analysis", server=target),
            )
        finally:
            if ds:
                try:
                    ds.close()
                except Exception:
                    pass

    @mcp.tool()
    def analyze_error_log(
        server_name: Optional[str] = None,
        severity: Optional[str] = None,
        component: Optional[str] = None,
        time_range: Optional[str] = None,
        pattern: Optional[str] = None,
    ) -> Dict[str, Any]:
        """Analyze error log statistics (severity, components, patterns).

        Returns aggregate statistics only — no individual log entries.
        Safe to use in privacy mode.

        Args:
            server_name: Target server name. Uses default if not specified.
            severity: Filter by severity level (INFO, WARNING, ERR, CRIT, EMERG).
            component: Filter by component name (e.g. "replication", "backend").
            time_range: Time range filter (same format as analyze_access_log).
            pattern: Regex pattern to match against log lines.

        Returns:
            Severity counts, component counts, and common error patterns.
        """
        target = server_name or mcp.default_server
        if not target:
            return {"type": "error_log_analysis", "error": "No server configured"}

        if not _can_access_logs(mcp, target):
            return {
                "type": "error_log_analysis",
                "error": (
                    "Log analysis requires local or archive server access. "
                    f"Server '{target}' is a remote connection."
                ),
            }

        ds = None
        try:
            ds = mcp.connection_manager.connect(target)
            data = _parse_error_log_entries(
                ds, severity, component, time_range,
                pattern, 0,
                stats_only=True,
            )
            result = {"type": "error_log_analysis", "server": target, **data}
            return _sanitize_log_result(mcp, result)
        except Exception as e:
            mcp.logger.error("Error analyzing error log: %s", e)
            return _sanitize_log_result(
                mcp, format_tool_error(e, mcp, "error_log_analysis", server=target),
            )
        finally:
            if ds:
                try:
                    ds.close()
                except Exception:
                    pass

    @mcp.tool()
    def analyze_audit_log(
        server_name: Optional[str] = None,
        operation: Optional[str] = None,
        bind_dn: Optional[str] = None,
        target_dn: Optional[str] = None,
        time_range: Optional[str] = None,
    ) -> Dict[str, Any]:
        """Analyze audit log statistics (change types, actors).

        Returns aggregate statistics only — no individual change records.
        Safe to use in privacy mode.

        Args:
            server_name: Target server name. Uses default if not specified.
            operation: Filter by change type (modify, add, delete, modrdn).
            bind_dn: Filter by the DN that performed the change.
            target_dn: Filter by the target DN that was changed.
            time_range: Time range filter (same format as analyze_access_log).

        Returns:
            Change type statistics and actor statistics.
        """
        target = server_name or mcp.default_server
        if not target:
            return {"type": "audit_log_analysis", "error": "No server configured"}

        if not _can_access_logs(mcp, target):
            return {
                "type": "audit_log_analysis",
                "error": (
                    "Log analysis requires local or archive server access. "
                    f"Server '{target}' is a remote connection."
                ),
            }

        ds = None
        try:
            ds = mcp.connection_manager.connect(target)
            data = _parse_audit_log_entries(
                ds, operation, bind_dn, target_dn,
                time_range, 0,
                stats_only=True,
            )
            result = {"type": "audit_log_analysis", "server": target, **data}
            return _sanitize_log_result(mcp, result)
        except Exception as e:
            mcp.logger.error("Error analyzing audit log: %s", e)
            return _sanitize_log_result(
                mcp, format_tool_error(e, mcp, "audit_log_analysis", server=target),
            )
        finally:
            if ds:
                try:
                    ds.close()
                except Exception:
                    pass
