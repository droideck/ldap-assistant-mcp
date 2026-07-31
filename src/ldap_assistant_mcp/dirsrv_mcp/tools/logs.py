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

import base64
import glob as globmod
import gzip
import heapq
import json
import math
import os
import re
import zlib
from collections import deque
from datetime import datetime, timedelta, timezone
from typing import TYPE_CHECKING, Annotated, Any, Dict, List, Optional

from pydantic import Field

from fastmcp.exceptions import ToolError
from mcp.types import ToolAnnotations

from ldap_assistant_mcp.dirsrv_mcp.connection import is_archive_server, is_local_server
from ldap_assistant_mcp.dirsrv_mcp.tools.dse_utils import dn_equals, is_under_dn
from ldap_assistant_mcp.dirsrv_mcp.tools.error_utils import format_tool_error
from ldap_assistant_mcp.lib.privacy import create_privacy_error

if TYPE_CHECKING:
    from ldap_assistant_mcp.dirsrv_mcp.server import DirSrvMCP

_RO = ToolAnnotations(readOnlyHint=True, idempotentHint=True, destructiveHint=False, openWorldHint=False)


def _sanitize_pattern_text(sanitizer, text: str) -> str:
    """Scrub sensitive data from normalised error patterns.

    Applied to ``common_patterns`` in analyze tools when privacy is on.
    Runs the text through the central :class:`PrivacySanitizer`
    (``sanitize_text`` handles URLs, paths, multi-component DNs, and
    FQDNs), then strips single-component ``attr=value`` tokens and
    arbitrary-TLD hostnames the sanitizer's patterns do not cover.
    """
    text = sanitizer.sanitize_text(text)
    # Strip remaining attr=value tokens (e.g. uid=admin, cn=config)
    text = re.sub(r"\b\w+=[\w.-]+(?:,\w+=[\w.-]+)*", "[dn]", text)
    # Strip remaining hostname-like tokens (word.word.word)
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

    # Server names are never sanitized (user-chosen config labels).
    if "error" in sanitized and isinstance(sanitized["error"], str):
        sanitized["error"] = sanitizer.sanitize_text(sanitized["error"])

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
                "pattern": _sanitize_pattern_text(sanitizer, p["pattern"]),
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
        result["message"] = sanitizer.sanitize_text(result["message"])
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

    Gzip-compressed rotations are inspected through gzip (sniffed by magic
    bytes, not filename) — reading raw gz bytes would misdetect a JSON
    rotation as traditional and route it to the wrong parser.
    """
    try:
        with open(log_path, "rb") as fh:
            magic = fh.read(2)
        opener = gzip.open if magic == b"\x1f\x8b" else open
        with opener(log_path, "rt", errors="ignore") as fh:
            for line in fh:
                stripped = line.strip()
                if not stripped:
                    continue
                return stripped.startswith("{")
    except (OSError, IOError, EOFError, zlib.error):
        pass
    return False


_MONTH_NUM = {
    "jan": 1, "feb": 2, "mar": 3, "apr": 4, "may": 5, "jun": 6,
    "jul": 7, "aug": 8, "sep": 9, "oct": 10, "nov": 11, "dec": 12,
}

# Traditional DS access/error log timestamp: 28/Jan/2024:11:01:31.123456789 +0000
_DS_TS_RE = re.compile(
    r"^(?P<day>\d{1,2})/(?P<mon>[A-Za-z]{3})/(?P<year>\d{4})"
    r":(?P<hour>\d{2}):(?P<minute>\d{2}):(?P<second>\d{2})"
    r"(?:\.(?P<frac>\d+))?"
    r"(?:\s*(?P<tz>[+-]\d{4}))?$"
)

_DATE_ONLY_RE = re.compile(r"^\d{4}-\d{2}-\d{2}$")

_TIME_RANGE_FORMATS_HINT = (
    "Supported formats: 'YYYY-MM-DD', 'YYYY-MM-DD to YYYY-MM-DD', "
    "ISO datetimes (e.g. '2024-01-01 10:00:00'), and 'last Nh' / 'last Nm'."
)


def _to_naive_utc(dt: datetime) -> datetime:
    """Normalise a datetime to naive UTC for comparison."""
    if dt.tzinfo is not None:
        dt = dt.astimezone(timezone.utc).replace(tzinfo=None)
    return dt


def _parse_log_timestamp(ts: str) -> Optional[datetime]:
    """Parse a log timestamp string into a naive UTC datetime.

    Handles the formats produced by all supported log types:

    - Traditional access/error logs: ``[28/Jan/2024:11:01:31.123456789 +0000]``
      (brackets and fractional seconds optional)
    - Traditional audit logs:        ``20240101100001`` (``%Y%m%d%H%M%S``)
    - JSON logs:                     ISO 8601, e.g. ``2024-01-01T10:00:01Z``
      or ``2025-02-12T17:00:47.699153015 -0500``

    Returns None if the timestamp cannot be parsed.
    """
    if not ts:
        return None
    ts = ts.strip().strip("[]").strip()
    if not ts:
        return None

    m = _DS_TS_RE.match(ts)
    if m:
        month = _MONTH_NUM.get(m.group("mon").lower())
        if month is None:
            return None
        frac = m.group("frac") or ""
        micro = int(frac[:6].ljust(6, "0")) if frac else 0
        tzinfo = None
        tz = m.group("tz")
        if tz:
            sign = 1 if tz[0] == "+" else -1
            tzinfo = timezone(
                sign * timedelta(hours=int(tz[1:3]), minutes=int(tz[3:5]))
            )
        try:
            dt = datetime(
                int(m.group("year")), month, int(m.group("day")),
                int(m.group("hour")), int(m.group("minute")),
                int(m.group("second")), micro, tzinfo=tzinfo,
            )
        except ValueError:
            return None
        return _to_naive_utc(dt)

    # Traditional audit log: time: 20240101100001
    if re.fullmatch(r"\d{14}", ts):
        try:
            return datetime.strptime(ts, "%Y%m%d%H%M%S")
        except ValueError:
            return None

    # ISO 8601 (JSON logs).  Normalise variants fromisoformat rejects:
    # a space before the UTC offset ("...47.699 -0500").
    iso = re.sub(r"\s+([+-]\d{2}:?\d{2})$", r"\1", ts)
    try:
        return _to_naive_utc(datetime.fromisoformat(iso))
    except ValueError:
        return None


def _parse_user_bound(value: str, *, is_end: bool) -> datetime:
    """Parse a user-supplied time_range bound into a naive UTC datetime.

    Date-only end bounds are made inclusive of the whole day so that
    ``"2024-01-01 to 2024-01-02"`` includes entries from Jan 2nd.

    Raises ToolError if the value cannot be parsed.
    """
    value = value.strip()
    if _DATE_ONLY_RE.match(value):
        try:
            dt = datetime.strptime(value, "%Y-%m-%d")
        except ValueError:
            raise ToolError(
                f"Invalid time_range date: {value!r}. {_TIME_RANGE_FORMATS_HINT}"
            )
        if is_end:
            dt = dt + timedelta(days=1) - timedelta(microseconds=1)
        return dt

    dt = _parse_log_timestamp(value)
    if dt is None:
        raise ToolError(
            f"Invalid time_range value: {value!r}. {_TIME_RANGE_FORMATS_HINT}"
        )
    return dt


_RELATIVE_RANGE_RE = re.compile(r"last\s+(\d+)\s*([hmd])[a-z]*", re.IGNORECASE)


def _is_relative_range(time_range: Optional[str]) -> bool:
    """True when *time_range* is a relative "last N" expression."""
    return bool(time_range) and bool(_RELATIVE_RANGE_RE.fullmatch(time_range.strip()))


def _parse_time_range(time_range: Optional[str], anchor: Optional[datetime] = None):
    """Parse a time_range string into (start, end) datetimes.

    Supports formats like:
      - ``"2024-01-01"`` (start only)
      - ``"2024-01-01 to 2024-01-02"`` (end inclusive of the whole day)
      - ``"last 1h"`` / ``"last 24h"`` / ``"last 30m"``

    Relative ranges are anchored to *anchor* when given (e.g. the newest
    timestamp in an archived dataset) and to the current wall clock
    otherwise.

    Returns ``(start_dt, end_dt)`` — naive UTC datetimes (either may be
    None).  Raises ToolError for values that cannot be parsed instead of
    silently matching nothing.
    """
    if not time_range:
        return None, None

    time_range = time_range.strip()
    if not time_range:
        return None, None

    # Handle "last Xh" / "last Xm" / "last Xd" (unit may be spelled out)
    m = _RELATIVE_RANGE_RE.fullmatch(time_range)
    if m:
        amount = int(m.group(1))
        unit = m.group(2).lower()
        now = anchor or datetime.now(timezone.utc).replace(tzinfo=None)
        delta = {
            "h": timedelta(hours=amount),
            "m": timedelta(minutes=amount),
            "d": timedelta(days=amount),
        }[unit]
        return now - delta, None

    # "start to end"
    if " to " in time_range:
        start_s, end_s = time_range.split(" to ", 1)
        return (
            _parse_user_bound(start_s, is_end=False),
            _parse_user_bound(end_s, is_end=True),
        )

    # Single date/datetime — start bound only
    return _parse_user_bound(time_range, is_end=False), None


def _timestamp_in_range_known(
    ts: Optional[str],
    start: Optional[datetime],
    end: Optional[datetime],
) -> tuple:
    """Range-check a log timestamp, reporting whether it was parseable.

    Returns ``(in_range, known)``. Entries whose timestamp is missing or
    unparseable are kept (fail open, ``in_range=True``) so time filtering
    never silently hides log data — but ``known=False`` lets callers count
    them so the mix is reported instead of silent.
    """
    if start is None and end is None:
        return True, True
    if not ts:
        return True, False
    dt = _parse_log_timestamp(ts)
    if dt is None:
        return True, False
    if start and dt < start:
        return False, True
    if end and dt > end:
        return False, True
    return True, True


def _timestamp_in_range(
    ts: Optional[str],
    start: Optional[datetime],
    end: Optional[datetime],
) -> bool:
    """Check whether a log timestamp string falls within [start, end].

    *start*/*end* are naive UTC datetimes from :func:`_parse_time_range`.
    Entries whose timestamp is missing or unparseable are kept (fail
    open) so that time filtering never silently hides log data.
    """
    return _timestamp_in_range_known(ts, start, end)[0]


def _log_time_span(log_path: str, kind: str = "access",
                   include_archived: bool = False) -> tuple:
    """Scan a log family for its first and last parseable timestamps.

    Returns ``(first_dt, last_dt)`` as naive UTC datetimes (either may be
    None when no timestamp could be parsed). Used to anchor relative time
    ranges to the dataset end for archived evidence and to report log
    coverage.

    Format is detected PER FILE so mixed families — e.g. traditional
    rotations from before a JSON-logging switch under a JSON current
    file — contribute their timestamps too instead of being silently
    excluded from the span.
    """
    first = None
    last = None

    def _consider(ts: Optional[str]) -> None:
        nonlocal first, last
        if not ts:
            return
        dt = _parse_log_timestamp(ts)
        if dt is None:
            return
        if first is None or dt < first:
            first = dt
        if last is None or dt > last:
            last = dt

    for path in _log_family_paths(log_path, include_archived):
        try:
            if _detect_json_log(path):
                counters: Dict[str, int] = {}
                for jentry in _read_json_lines_single(path, counters):
                    _consider(
                        jentry.get("local_time")
                        or jentry.get("gm_time")
                        or jentry.get("date")
                    )
            elif kind == "audit":
                for line in _read_lines_single(path):
                    m = _AUDIT_TIME_RE.match(line.rstrip("\n"))
                    if m:
                        _consider(m.group(1))
            else:
                for line in _read_lines_single(path):
                    if line.startswith("["):
                        closing = line.find("]")
                        if closing > 0:
                            _consider(line[1:closing])
        except OSError:
            continue

    return first, last


def _resolve_time_window(
    time_range: Optional[str],
    log_path: str,
    kind: str,
    anchor_to_dataset_end: bool,
    include_archived: bool = False,
) -> tuple:
    """Resolve a time_range into (start, end, effective_window dict).

    For archived evidence (*anchor_to_dataset_end*), relative ranges like
    "last 24h" are anchored to the newest timestamp in the dataset instead
    of the current wall clock — an old SOS report would otherwise always
    match nothing.
    """
    if not time_range or not time_range.strip():
        return None, None, None

    anchor = None
    anchor_label = "absolute"
    if _is_relative_range(time_range):
        if anchor_to_dataset_end:
            _, dataset_end = _log_time_span(log_path, kind, include_archived)
            if dataset_end is not None:
                anchor = dataset_end
                anchor_label = "dataset_end"
            else:
                anchor_label = "dataset_end_unavailable"
        else:
            anchor_label = "wall_clock"

    start_ts, end_ts = _parse_time_range(time_range, anchor=anchor)
    effective_window = {
        "requested": time_range,
        "start": start_ts.isoformat() if start_ts else None,
        "end": end_ts.isoformat() if end_ts else None,
        "anchor": anchor_label,
    }
    return start_ts, end_ts, effective_window


def _dn_matches_filter(entry_dn: str, filter_dn: str) -> bool:
    """Check if *entry_dn* matches a DN filter (equals or is descendant).

    Uses proper DN parsing so that ``cn=admin`` does **not** match
    ``cn=administrator``.
    """
    return dn_equals(entry_dn, filter_dn) or is_under_dn(entry_dn, filter_dn)


# A repeat with a bounded max at or below this is eligible for the
# decomposition-budget check below; + / * / {2,} count as unbounded.
_SAFE_REPEAT_MAX = 64

# Maximum number of distinct ways a repeated group may decompose its match
# before the pattern is rejected.  2**16 keeps worst-case backtracking per
# start position trivially cheap while admitting harmless bounded forms
# like (\d{1,3}\.){3} (27 ways).  (a|aa){2,64} is ~2**64 and rejected.
_AMBIGUITY_BUDGET = 2.0 ** 16


def _branch_literal_words(branch_arg) -> Optional[List[str]]:
    """Extract the alternatives of a branch node as literal strings.

    Returns None when any alternative is not a plain non-empty literal
    sequence (categories, classes, nested groups, ...).
    """
    words: List[str] = []
    for alt in branch_arg[1]:
        chars: List[str] = []
        for op, arg in alt:
            # Exact op match: NOT_LITERAL's name contains "literal" but a
            # negated class is NOT a literal — treating it as one would let
            # ambiguous alternations like ([^a]|b)+ bypass the check.
            if str(op).lower() != "literal" or not isinstance(arg, int):
                return None
            chars.append(chr(arg))
        if not chars:
            return None  # empty alternative matches "" — always ambiguous
        words.append("".join(chars))
    return words


def _is_prefix_code(words: List[str]) -> bool:
    """True when no word is a prefix of another (unique decodability).

    A repeated alternation over a prefix code decomposes any input in at
    most one way, so it cannot backtrack exponentially. ``{a, aa}`` fails
    (``aa`` = ``a``+``a``); ``{ADD, MOD, DEL}`` passes.

    Comparison is case-insensitive because the pattern is compiled with
    re.IGNORECASE — ``(A|aa)+`` is exactly as ambiguous as ``(a|aa)+``.
    """
    folded = [w.lower() for w in words]
    for i, w1 in enumerate(folded):
        for j, w2 in enumerate(folded):
            if i != j and w2.startswith(w1):
                return False
    return True


def _ambiguity_factor(node_list) -> float:
    """Upper-bound estimate of how many distinct ways this subpattern can
    decompose one fixed piece of text (its match multiplicity).

    ``1.0`` means unambiguous — at most one way, cannot backtrack.
    ``math.inf`` means unbounded — an inner ``+``/``*`` can split its span
    in ~len(text) ways.  Per-node choice counts multiply: alternation over
    non-prefix-code words contributes the number of alternatives; a
    bounded repeat contributes its span flexibility (max - min + 1) times
    its body's ambiguity per iteration.
    """
    factor = 1.0
    for op, arg in node_list:
        name = str(op).lower()
        if "branch" in name:
            words = _branch_literal_words(arg)
            if words is not None:
                if not _is_prefix_code(words):
                    factor *= len(words)
            else:
                # Non-literal alternatives: disjointness cannot be proven,
                # so count the alternatives times the worst inner factor.
                alt_factors = [_ambiguity_factor(list(alt)) for alt in arg[1]]
                worst = max(alt_factors, default=1.0)
                if math.isinf(worst):
                    return math.inf
                factor *= len(alt_factors) * worst
        elif "repeat" in name or "possessive" in name:
            # arg = (min, max, subpattern)
            _min, _max, body = arg
            body_factor = _ambiguity_factor(list(body))
            if not isinstance(_max, int) or _max > _SAFE_REPEAT_MAX:
                # Unbounded span: as a component of an enclosing repeat it
                # can split its match in ~len(text) ways.
                return math.inf
            span_choices = float(_max - _min + 1)
            try:
                per_iteration = (
                    body_factor ** min(_max, _SAFE_REPEAT_MAX)
                    if body_factor > 1.0
                    else 1.0
                )
            except OverflowError:
                return math.inf
            factor *= span_choices * per_iteration
        elif "subpattern" in name:
            # arg = (group, add_flags, del_flags, subpattern)
            inner = arg[3] if isinstance(arg, tuple) and len(arg) >= 4 else None
            if inner is not None:
                factor *= _ambiguity_factor(list(inner))
        if math.isinf(factor):
            return math.inf
    return factor


def _has_catastrophic_repeat(node_list) -> bool:
    """Walk a parsed regex tree looking for repeats whose body can match
    the same text in multiple ways — the exponential-backtracking shape.

    An unbounded repeat over an ambiguous body (``(a|aa)+``, ``(a+)+``)
    is always rejected.  A bounded repeat allowing 2+ iterations is
    rejected when its total decomposition budget ``body_factor ** max``
    exceeds ``_AMBIGUITY_BUDGET`` — ``(a|aa){2,64}`` (~2**64 ways) and
    ``(a+){2,64}`` (unbounded body) are rejected, while ``(\\d{1,3}\\.){3}``
    (27 ways) and single-iteration groups like ``(uid=[a-z]+)?`` pass.
    """
    for op, arg in node_list:
        name = str(op).lower()
        if "repeat" in name or "possessive" in name:
            # arg = (min, max, subpattern)
            _min, _max, body = arg
            body_list = list(body)
            unbounded = not isinstance(_max, int) or _max > _SAFE_REPEAT_MAX
            # Cross-iteration recomposition needs at least 2 iterations;
            # {0,1} groups have no composition ambiguity of their own.
            if unbounded or _max >= 2:
                body_factor = _ambiguity_factor(body_list)
                if body_factor > 1.0:
                    if unbounded:
                        return True
                    try:
                        total = body_factor ** _max
                    except OverflowError:
                        return True
                    if total > _AMBIGUITY_BUDGET:
                        return True
            if _has_catastrophic_repeat(body_list):
                return True
        elif "subpattern" in name:
            inner = arg[3] if isinstance(arg, tuple) and len(arg) >= 4 else None
            if inner is not None and _has_catastrophic_repeat(list(inner)):
                return True
        elif "branch" in name:
            # arg = (None, [subpattern, subpattern, ...])
            for alt in arg[1]:
                if _has_catastrophic_repeat(list(alt)):
                    return True
    return False


def _validate_regex(pattern: Optional[str]) -> tuple:
    """Validate and compile a user-supplied regex pattern.

    Returns ``(compiled_re | None, error_dict | None)``.
    If the pattern is None or empty, returns ``(None, None)``.

    Rejects patterns exceeding 500 chars and ReDoS-prone constructs by
    STRUCTURAL analysis of the parsed regex tree (not text heuristics):
    any repeat (bounded or unbounded) whose body can match the same text
    in multiple ways and whose decomposition budget exceeds
    ``_AMBIGUITY_BUDGET`` can backtrack catastrophically under Python's
    ``re`` engine — ``(a+)+``, ``(a|aa)+``, ``(\\d|\\d\\d)*``, ``((a+))+``,
    and bounded forms like ``(a+){2,64}`` are all caught.
    Polynomial ``.*.*.*`` stacking is additionally capped.
    """
    if not pattern:
        return None, None
    if len(pattern) > 500:
        return None, {"error": "Pattern too long (max 500 chars)"}

    # Repeated .* sequences (polynomial blowup)
    if re.search(r'(\.\*.*){3,}', pattern):
        return None, {"error": "Pattern contains too many .* sequences"}

    try:
        import re._parser as sre_parser
        parsed = sre_parser.parse(pattern, re.IGNORECASE)
    except re.error as exc:
        return None, {"error": f"Invalid regex pattern: {exc}"}
    except Exception:
        # Parser internals changed or exotic input: fail closed
        return None, {"error": "Pattern could not be analyzed for safety"}

    if _has_catastrophic_repeat(list(parsed)):
        return None, {
            "error": (
                "Pattern contains potentially unsafe nested quantifiers or "
                "quantified alternation (exponential backtracking risk). "
                "Rewrite without repeating a group that can match the same "
                "text in multiple ways."
            )
        }

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
    start_ts: Optional[datetime],
    end_ts: Optional[datetime],
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

# Cap on detailed slow-operation records kept in memory while scanning.
_SLOW_OPS_TOP_N = 20


# Per-file decompression budget: a corrupt or hostile .gz must not expand
# without bound just because its compressed size passed the archive checks.
_MAX_DECOMPRESSED_BYTES_PER_FILE = 512 * 1024 * 1024
# A single (pretty-printed) JSON record larger than this is malformed.
_MAX_JSON_RECORD_BYTES = 1024 * 1024


def _log_family_paths(log_path: Optional[str], include_archived: bool = False) -> List[str]:
    """List the existing files of a log family, oldest rotation first,
    current file last.

    A family whose current base file is missing (rotated-only evidence in
    an old archive) is still inventoried when *include_archived* is set.
    """
    paths: List[str] = []
    if include_archived and log_path:
        paths.extend(p for p in sorted(globmod.glob(f"{log_path}.*-*")) if os.path.isfile(p))
    if log_path and os.path.isfile(log_path):
        paths.append(log_path)
    return paths


def _bump(counters: Optional[Dict[str, int]], key: str) -> None:
    if counters is not None:
        counters[key] = counters.get(key, 0) + 1


def _read_lines_single(path: str, counters: Optional[Dict[str, int]] = None):
    """Stream lines from one (possibly gzipped) log file.

    Corrupt or unreadable files are recorded in *counters* and skipped so
    one bad rotation cannot abort the whole family. Gzipped files stop at
    the per-file decompression budget instead of expanding unbounded.
    """
    is_gz = path.endswith(".gz")
    try:
        fh = gzip.open(path, "rt", errors="replace") if is_gz else open(path, "r", errors="replace")
    except OSError:
        _bump(counters, "unreadable_files")
        return
    with fh:
        read_bytes = 0
        try:
            for line in fh:
                if is_gz:
                    read_bytes += len(line)
                    if read_bytes > _MAX_DECOMPRESSED_BYTES_PER_FILE:
                        _bump(counters, "decompression_truncated")
                        return
                yield line
        except (OSError, EOFError, zlib.error):
            # Truncated/corrupt gzip mid-stream: keep what was read
            _bump(counters, "unreadable_files")
            return


def _read_log_lines(log_path: str, include_archived: bool = False,
                    counters: Optional[Dict[str, int]] = None):
    """Yield lines from a log family, optionally including rotated/compressed
    logs. A generator so multi-GB logs are streamed instead of loaded whole.
    """
    for path in _log_family_paths(log_path, include_archived):
        yield from _read_lines_single(path, counters)


def _brace_delta(line: str) -> int:
    """Net JSON brace depth change of *line*, ignoring braces in strings."""
    depth = 0
    in_string = False
    escape = False
    for ch in line:
        if escape:
            escape = False
            continue
        if ch == "\\":
            escape = in_string
            continue
        if ch == '"':
            in_string = not in_string
        elif not in_string:
            if ch == "{":
                depth += 1
            elif ch == "}":
                depth -= 1
    return depth


def _read_json_lines_single(path: str, counters: Dict[str, int]):
    """Yield parsed entries from one JSON DS log file.

    Handles both NDJSON (one record per line) and pretty-printed JSON
    (multi-line records starting with a bare ``{``). Malformed records are
    counted in ``counters["malformed_lines"]`` and skipped.
    """
    pretty: Optional[bool] = None
    buf: List[str] = []
    depth = 0
    for line in _read_lines_single(path, counters):
        stripped = line.strip()
        if pretty is None:
            if not stripped:
                continue
            pretty = stripped == "{"
        if not pretty:
            if not stripped:
                continue
            try:
                entry = json.loads(stripped)
            except ValueError:
                _bump(counters, "malformed_lines")
                continue
            if isinstance(entry, dict):
                yield entry
            else:
                _bump(counters, "malformed_lines")
        else:
            if not buf and not stripped:
                continue
            buf.append(line)
            depth += _brace_delta(line)
            if depth <= 0:
                text = "".join(buf)
                buf = []
                depth = 0
                try:
                    entry = json.loads(text)
                except ValueError:
                    _bump(counters, "malformed_lines")
                    continue
                if isinstance(entry, dict):
                    yield entry
                else:
                    _bump(counters, "malformed_lines")
            elif sum(len(chunk) for chunk in buf) > _MAX_JSON_RECORD_BYTES:
                _bump(counters, "malformed_lines")
                buf = []
                depth = 0
    if buf:
        _bump(counters, "malformed_lines")


def _read_json_log_entries(
    log_path: str,
    counters: Dict[str, int],
    include_archived: bool = False,
):
    """Yield parsed entries from a JSON DS log family.

    Format is detected PER FILE: a traditional-format rotation mixed into a
    JSON family is skipped and counted in ``counters["non_json_files"]``
    instead of having every line misparsed as malformed JSON.
    """
    for path in _log_family_paths(log_path, include_archived):
        if _detect_json_log(path):
            yield from _read_json_lines_single(path, counters)
        else:
            _bump(counters, "non_json_files")


# Reader-level incident counters worth surfacing to the caller when nonzero.
_READ_COUNTER_KEYS = (
    "header_records",
    "unreadable_files",
    "decompression_truncated",
    "non_json_files",
)


def _attach_read_counters(result: Dict[str, Any], counters: Dict[str, int]) -> None:
    """Copy nonzero reader-level counters into a tool result (additive keys)."""
    for key in _READ_COUNTER_KEYS:
        if counters.get(key):
            result[key] = counters[key]


class _TopNHeap:
    """Keep the N highest-scoring items seen, in O(log N) per push."""

    def __init__(self, n: int):
        self._n = n
        self._heap: List[tuple] = []
        self._counter = 0  # tiebreak — dicts are not comparable

    def push(self, score: float, item: Any) -> None:
        self._counter += 1
        if len(self._heap) < self._n:
            heapq.heappush(self._heap, (score, self._counter, item))
        elif score > self._heap[0][0]:
            heapq.heapreplace(self._heap, (score, self._counter, item))

    def items_desc(self) -> List[Any]:
        return [item for _, _, item in sorted(self._heap, reverse=True)]

_ACCESS_TS_RE = re.compile(r"^\[(?P<timestamp>[^\]]+)\]\s*(?P<rest>.*)")
_ACCESS_RESULT_RE = re.compile(
    r"err=(?P<err>\d+)\s+tag=(?P<tag>\d+)\s+nentries=(?P<nentries>\d+)"
)
_ACCESS_ETIME_RE = re.compile(r"etime=(?P<etime>[0-9.]+)")
# notes flags can be comma-combined (e.g. notes=P,U) — \w would stop at the comma
_ACCESS_NOTES_RE = re.compile(r"notes=(?P<notes>[A-Z],?(?:[A-Z],?)*)")

_ACCESS_ACTIONS = {
    "SRCH", "MOD", "ADD", "DEL", "MODRDN", "CMP", "ABANDON",
    "BIND", "UNBIND", "AUTOBIND", "RESULT", "EXT",
}


def _json_entry_has_unindexed_note(jentry: Dict[str, Any]) -> bool:
    """Check a JSON access-log entry for unindexed-search notes (U or A).

    389 DS emits ``notes`` as an array of objects like
    ``[{"note": "U", "description": ...}]`` (accesslog.c); a plain string
    is also accepted for tolerance.
    """
    notes = jentry.get("notes", "")
    if isinstance(notes, str):
        return bool(notes) and ("U" in notes or "A" in notes)
    if isinstance(notes, list):
        for note in notes:
            if isinstance(note, dict):
                if note.get("note") in ("U", "A"):
                    return True
            elif note in ("U", "A"):
                return True
    return False


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
    anchor_to_dataset_end: bool = False,
) -> Dict[str, Any]:
    """Parse access log and return structured results.

    When *stats_only* is True, individual entries and slow-op details are
    omitted — only aggregate statistics are returned. When
    *anchor_to_dataset_end* is True (archive evidence), relative time
    ranges anchor to the newest log timestamp instead of the wall clock.
    """
    log_path = ds.ds_paths.access_log
    family = _log_family_paths(log_path, include_archived)
    if not family:
        return {"error": f"Access log not found at {log_path}"}

    pattern_re, regex_err = _validate_regex(pattern)
    if regex_err:
        return regex_err
    op_upper = operation.upper() if operation else None

    # Bounded to the NEWEST matches: with rotations included, keeping the
    # first `limit` matches would return the oldest records and silently
    # hide recent incident evidence.
    entries = deque(maxlen=max(1, limit))
    op_stats: Dict[str, int] = {}
    failed_ops: Dict[int, int] = {}
    slow_ops = _TopNHeap(_SLOW_OPS_TOP_N)
    counters: Dict[str, int] = {"malformed_lines": 0}
    total_parsed = 0
    unknown_ts_count = 0
    # Stats-only accumulators for slow-op summary
    slow_count = 0
    slow_max = 0.0
    slow_sum = 0.0
    unindexed_count = 0

    is_json = _detect_json_log(log_path) if os.path.isfile(log_path or "") else _detect_json_log(family[-1])
    start_ts, end_ts, effective_window = _resolve_time_window(
        time_range, log_path, "access", anchor_to_dataset_end, include_archived
    )

    # Format is decided per file so mixed-format rotations each get the
    # right parser instead of inheriting the current file's format.
    for path in family:
        file_is_json = _detect_json_log(path)
        if file_is_json:
            records = (("json", e) for e in _read_json_lines_single(path, counters))
        else:
            records = (("line", ln) for ln in _read_lines_single(path, counters))

        for kind, rec in records:
            if kind == "json":
                jentry = rec
                total_parsed += 1
                # 389 DS JSON access logs use "operation" (e.g. SEARCH, RESULT)
                action = jentry.get(
                    "operation", jentry.get("op_type", jentry.get("action", ""))
                )
                err = jentry.get("err", jentry.get("result"))
                # Header/metadata records have neither an operation nor a
                # result code — excluded from operation statistics.
                if not action and err is None:
                    _bump(counters, "header_records")
                    total_parsed -= 1
                    continue
                ts = jentry.get("local_time", jentry.get("date", ""))
                etime = jentry.get("etime")
                pattern_target = json.dumps(jentry)
                entry_obj = jentry
                is_unindexed = _json_entry_has_unindexed_note(jentry)
                slow_item = {**jentry, "etime": None}  # etime set below
            else:
                line = rec
                if not line.strip():
                    continue
                total_parsed += 1
                parsed = _parse_access_line(line)
                if not parsed:
                    continue
                action = parsed.get("action", "")
                err = parsed.get("err")
                ts = parsed.get("timestamp", "")
                etime = parsed.get("etime")
                pattern_target = line
                entry_obj = {**parsed, "raw": line.rstrip()}
                notes = parsed.get("notes", "")
                is_unindexed = bool(notes and ("U" in notes or "A" in notes))
                slow_item = {**parsed, "raw": line.rstrip(), "etime": None}

            if op_upper and action.upper() != op_upper:
                continue
            if result_code is not None:
                if err is None:
                    continue
                try:
                    if int(err) != result_code:
                        continue
                except (ValueError, TypeError):
                    continue
            in_range, ts_known = _timestamp_in_range_known(ts, start_ts, end_ts)
            if (start_ts or end_ts) and not ts_known:
                unknown_ts_count += 1
            if not in_range:
                continue
            if pattern_re and not pattern_re.search(pattern_target):
                continue

            op_stats[action] = op_stats.get(action, 0) + 1
            if err is not None:
                try:
                    err_int = int(err)
                    if err_int != 0:
                        failed_ops[err_int] = failed_ops.get(err_int, 0) + 1
                except (ValueError, TypeError):
                    pass
            if etime is not None:
                try:
                    etime_f = float(etime)
                    if etime_f > 1.0:
                        slow_count += 1
                        slow_sum += etime_f
                        if etime_f > slow_max:
                            slow_max = etime_f
                        if not stats_only:
                            slow_ops.push(etime_f, {**slow_item, "etime": etime_f})
                except (ValueError, TypeError):
                    pass

            if is_unindexed:
                unindexed_count += 1

            if not stats_only:
                entries.append(entry_obj)

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
        if is_json:
            result["malformed_lines"] = counters["malformed_lines"]
        if effective_window is not None:
            result["effective_window"] = effective_window
            result["unknown_timestamp_count"] = unknown_ts_count
        _attach_read_counters(result, counters)
        return result

    result = {
        "entries": list(entries),
        "total_parsed": total_parsed,
        "matched_count": sum(op_stats.values()),
        "operation_stats": op_stats,
        "failed_operations": {str(k): v for k, v in sorted(failed_ops.items())},
        "slow_operations": slow_ops.items_desc(),
    }
    if is_json:
        result["malformed_lines"] = counters["malformed_lines"]
    if effective_window is not None:
        result["effective_window"] = effective_window
        result["unknown_timestamp_count"] = unknown_ts_count
    _attach_read_counters(result, counters)
    return result


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
    anchor_to_dataset_end: bool = False,
    include_archived: bool = False,
) -> Dict[str, Any]:
    """Parse error log and return structured results.

    When *stats_only* is True, individual entries are omitted — only
    aggregate statistics (severity_counts, component_counts,
    common_patterns) are returned.

    ``severity_counts`` contains only records that matched every active
    filter; ``source_severity_counts`` counts all parsed records so the
    two can never be silently conflated.
    """
    log_path = ds.ds_paths.error_log
    family = _log_family_paths(log_path, include_archived)
    if not family:
        return {"error": f"Error log not found at {log_path}"}

    pattern_re, regex_err = _validate_regex(pattern)
    if regex_err:
        return regex_err
    sev_upper = severity.upper() if severity else None

    # Newest matches win when the family exceeds the limit
    entries = deque(maxlen=max(1, limit))
    severity_counts: Dict[str, int] = {}
    source_severity_counts: Dict[str, int] = {}
    component_counts: Dict[str, int] = {}
    counters: Dict[str, int] = {"malformed_lines": 0}
    total_parsed = 0
    matched_count = 0
    unknown_ts_count = 0
    pattern_counts: Dict[str, int] = {}

    is_json = _detect_json_log(log_path) if os.path.isfile(log_path or "") else _detect_json_log(family[-1])
    start_ts, end_ts, effective_window = _resolve_time_window(
        time_range, log_path, "error", anchor_to_dataset_end, include_archived
    )

    for path in family:
        file_is_json = _detect_json_log(path)
        if file_is_json:
            records = (("json", e) for e in _read_json_lines_single(path, counters))
        else:
            records = (("line", ln) for ln in _read_lines_single(path, counters))

        for kind, rec in records:
            if kind == "json":
                jentry = rec
                # Header/metadata records carry neither a severity nor a
                # message — keep them out of the severity statistics.
                if "severity" not in jentry and not (
                    jentry.get("msg") or jentry.get("message")
                ):
                    _bump(counters, "header_records")
                    continue
                total_parsed += 1
                entry_sev = jentry.get("severity", "INFO").upper()
                source_severity_counts[entry_sev] = source_severity_counts.get(entry_sev, 0) + 1
                if sev_upper and entry_sev != sev_upper:
                    continue
                entry_comp = jentry.get("subsystem", "")
                if component and component.lower() not in entry_comp.lower():
                    continue
                ts = jentry.get("local_time", "")
                pattern_target = json.dumps(jentry)
                msg = jentry.get("msg", jentry.get("message", ""))
                entry_obj = jentry
            else:
                line = rec
                if not line.strip():
                    continue
                total_parsed += 1
                parsed = _parse_error_line(line) or {}

                entry_sev = parsed.get("severity", "").upper()
                if not entry_sev:
                    sev_match = _ERROR_SEVERITY_RE.search(line)
                    entry_sev = sev_match.group(1) if sev_match else "INFO"
                source_severity_counts[entry_sev] = source_severity_counts.get(entry_sev, 0) + 1

                if sev_upper and entry_sev != sev_upper:
                    continue

                entry_comp = parsed.get("component", "")
                if component:
                    if not entry_comp or component.lower() not in entry_comp.lower():
                        continue

                ts = parsed.get("timestamp", "")
                pattern_target = line
                msg = parsed.get("message", line)
                parsed["severity"] = entry_sev
                parsed["raw"] = line.rstrip()
                entry_obj = parsed

            in_range, ts_known = _timestamp_in_range_known(ts, start_ts, end_ts)
            if (start_ts or end_ts) and not ts_known:
                unknown_ts_count += 1
            if not in_range:
                continue
            if pattern_re and not pattern_re.search(pattern_target):
                continue

            matched_count += 1
            severity_counts[entry_sev] = severity_counts.get(entry_sev, 0) + 1
            if entry_comp:
                component_counts[entry_comp] = component_counts.get(entry_comp, 0) + 1

            _track_pattern(pattern_counts, msg)

            if not stats_only:
                entries.append(entry_obj)

    if stats_only:
        common_patterns = [
            {"pattern": p, "count": c}
            for p, c in sorted(pattern_counts.items(), key=lambda x: -x[1])[:10]
        ]
        result: Dict[str, Any] = {
            "total_parsed": total_parsed,
            "matched_count": matched_count,
            "severity_counts": severity_counts,
            "source_severity_counts": source_severity_counts,
            "component_counts": component_counts,
            "common_patterns": common_patterns,
        }
        if is_json:
            result["malformed_lines"] = counters["malformed_lines"]
        if effective_window is not None:
            result["effective_window"] = effective_window
            result["unknown_timestamp_count"] = unknown_ts_count
        _attach_read_counters(result, counters)
        return result

    common_patterns = [
        {"pattern": p, "count": c, "example": p[:80]}
        for p, c in sorted(pattern_counts.items(), key=lambda x: -x[1])[:10]
    ]

    result = {
        "entries": list(entries),
        "total_parsed": total_parsed,
        "matched_count": matched_count,
        "severity_counts": severity_counts,
        "source_severity_counts": source_severity_counts,
        "component_counts": component_counts,
        "common_patterns": common_patterns,
    }
    if is_json:
        result["malformed_lines"] = counters["malformed_lines"]
    if effective_window is not None:
        result["effective_window"] = effective_window
        result["unknown_timestamp_count"] = unknown_ts_count
    _attach_read_counters(result, counters)
    return result


def _track_pattern(counts: Dict[str, int], message: str) -> None:
    """Track common error patterns by normalising the message."""
    normalised = re.sub(r"\d+", "N", message.strip())
    normalised = re.sub(r"\s+", " ", normalised)[:120]
    if normalised:
        counts[normalised] = counts.get(normalised, 0) + 1


_AUDIT_TIME_RE = re.compile(r"^time:\s+(\d+)$")
_AUDIT_DN_RE = re.compile(r"^dn:\s+(.+)$")


def _unfold_ldif_lines(lines):
    """Yield logical LDIF lines with folded continuation lines joined.

    A physical line starting with a single space continues the previous
    logical line (RFC 2849 folding) — without unfolding, a folded ``dn:``
    never matches the DN pattern and silently escapes DN filters.
    """
    pending: Optional[str] = None
    for line in lines:
        line = line.rstrip("\n")
        if line.startswith(" ") and pending is not None:
            pending += line[1:]
            continue
        if pending is not None:
            yield pending
        pending = line
    if pending is not None:
        yield pending


def _iter_audit_records(lines, collect_raw: bool = True):
    """Stream change records from a traditional LDIF-style audit log.

    A generator: only the current record is held in memory (the previous
    implementation accumulated the entire log, raw text included, before
    any filter or limit was applied). Folded lines are unfolded and
    base64 DNs (``dn:: ...``) are decoded so DN filters can match them.
    """
    current: Optional[Dict[str, Any]] = None
    current_lines: List[str] = []

    for line in _unfold_ldif_lines(lines):
        time_m = _AUDIT_TIME_RE.match(line)
        if time_m:
            if current is not None:
                if collect_raw:
                    current["raw"] = "\n".join(current_lines)
                yield current
            current = {"time": time_m.group(1)}
            current_lines = [line] if collect_raw else []
            continue

        if current is None:
            continue

        if collect_raw:
            current_lines.append(line)

        if "dn" not in current:
            dn_m = _AUDIT_DN_RE.match(line)
            if dn_m:
                current["dn"] = dn_m.group(1)
                continue
            if line.startswith("dn:: "):
                try:
                    current["dn"] = base64.b64decode(
                        line[len("dn:: "):].strip()
                    ).decode("utf-8", "replace")
                except (ValueError, TypeError):
                    current["dn"] = ""
                continue

        if line.startswith("changetype: "):
            current["changetype"] = line[len("changetype: "):]
        elif line.startswith("modifiersname: "):
            current["bind_dn"] = line[len("modifiersname: "):]
        elif line.startswith("creatorsname: "):
            current.setdefault("bind_dn", line[len("creatorsname: "):])

    if current is not None:
        if collect_raw:
            current["raw"] = "\n".join(current_lines)
        yield current


def _parse_audit_log_traditional(lines) -> List[Dict[str, Any]]:
    """Parse traditional LDIF-style audit log into change records.

    Compatibility wrapper around the streaming :func:`_iter_audit_records`.
    """
    return list(_iter_audit_records(lines))


def _parse_audit_log_entries(
    ds,
    operation: Optional[str],
    bind_dn: Optional[str],
    target_dn: Optional[str],
    time_range: Optional[str],
    limit: int,
    stats_only: bool = False,
    anchor_to_dataset_end: bool = False,
    include_archived: bool = False,
) -> Dict[str, Any]:
    """Parse audit log and return structured results.

    When *stats_only* is True, individual change records are omitted —
    only aggregate statistics are returned.

    ``change_type_stats`` contains only records that matched every active
    filter; ``source_change_type_counts`` counts all parsed records.
    """
    log_path = ds.ds_paths.audit_log
    family = _log_family_paths(log_path, include_archived)
    if not family:
        return {"error": f"Audit log not found at {log_path}"}

    op_lower = operation.lower() if operation else None

    # Newest matches win when the family exceeds the limit
    changes = deque(maxlen=max(1, limit))
    change_type_counts: Dict[str, int] = {}
    source_change_type_counts: Dict[str, int] = {}
    actor_counts: Dict[str, int] = {}
    counters: Dict[str, int] = {"malformed_lines": 0}
    total_parsed = 0
    matched_count = 0
    unknown_ts_count = 0

    is_json = _detect_json_log(log_path) if os.path.isfile(log_path or "") else _detect_json_log(family[-1])
    start_ts, end_ts, effective_window = _resolve_time_window(
        time_range, log_path, "audit", anchor_to_dataset_end, include_archived
    )
    time_filter_active = start_ts is not None or end_ts is not None

    for path in family:
        file_is_json = _detect_json_log(path)
        if file_is_json:
            records = (
                ("json", e) for e in _read_json_lines_single(path, counters)
            )
        else:
            records = (
                ("ldif", r)
                for r in _iter_audit_records(
                    _read_lines_single(path, counters),
                    collect_raw=not stats_only,
                )
            )

        for kind, rec in records:
            total_parsed += 1
            if kind == "json":
                ct = rec.get("changetype", rec.get("op_type", "")).lower()
                entry_dn = rec.get("dn", "")
                entry_bind = rec.get("modifiersname", rec.get("bind_dn", ""))
                ts = rec.get("gm_time", rec.get("date", ""))
            else:
                ct = rec.get("changetype", "unknown").lower()
                entry_dn = rec.get("dn", "")
                entry_bind = rec.get("bind_dn", "")
                ts = rec.get("time", "")

            source_change_type_counts[ct] = source_change_type_counts.get(ct, 0) + 1

            # Non-time filters first, so unknown-timestamp counting matches
            # the access/error loops: only records that survive the other
            # filters are counted as time-unknown.
            if not _matches_audit_filters(
                entry_dn, entry_bind, ct, ts,
                op_lower, target_dn, bind_dn, None, None,
            ):
                continue

            in_range, ts_known = _timestamp_in_range_known(ts, start_ts, end_ts)
            if time_filter_active and not ts_known:
                unknown_ts_count += 1
            if not in_range:
                continue

            matched_count += 1
            change_type_counts[ct] = change_type_counts.get(ct, 0) + 1
            actor_counts[entry_bind] = actor_counts.get(entry_bind, 0) + 1

            if not stats_only:
                changes.append(rec)

    if stats_only:
        result: Dict[str, Any] = {
            "total_parsed": total_parsed,
            "matched_count": matched_count,
            "change_type_stats": change_type_counts,
            "source_change_type_counts": source_change_type_counts,
            "actor_stats": actor_counts,
        }
        if is_json:
            result["malformed_lines"] = counters["malformed_lines"]
        if effective_window is not None:
            result["effective_window"] = effective_window
            result["unknown_timestamp_count"] = unknown_ts_count
        _attach_read_counters(result, counters)
        return result

    result = {
        "changes": list(changes),
        "total_parsed": total_parsed,
        "matched_count": matched_count,
        "change_type_stats": change_type_counts,
        "source_change_type_counts": source_change_type_counts,
        "actor_stats": actor_counts,
    }
    if is_json:
        result["malformed_lines"] = counters["malformed_lines"]
    if effective_window is not None:
        result["effective_window"] = effective_window
        result["unknown_timestamp_count"] = unknown_ts_count
    _attach_read_counters(result, counters)
    return result


def register_log_tools(mcp: "DirSrvMCP") -> None:
    """Register log parsing and analysis tools with the MCP server."""

    # ------------------------------------------------------------------
    # Parse tools — full entry detail, require expose_sensitive_data
    # ------------------------------------------------------------------

    @mcp.tool(annotations=_RO, tags={"logs", "live", "offline", "archive"})
    def parse_access_log(
        server_name: Optional[str] = None,
        operation: Optional[str] = None,
        result_code: Optional[int] = None,
        time_range: Optional[str] = None,
        pattern: Annotated[Optional[str], Field(max_length=500, description="Regex filter pattern")] = None,
        include_archived_logs: bool = False,
        limit: Annotated[int, Field(ge=1, le=10000, description="Max entries to return")] = 100,
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
            return _sanitize_log_result(mcp, {
                "type": "access_log",
                "server": target,
                "error": (
                    "Log parsing requires local or archive server access. "
                    f"Server '{target}' is a remote connection."
                ),
                "try_instead": ["get_connection_statistics", "get_operation_statistics", "run_monitor"],
            })

        ds = None
        try:
            ds = mcp.connection_manager.connect(target)
            data = _parse_access_log_entries(
                ds, operation, result_code, time_range,
                pattern, include_archived_logs, max(1, limit),
                anchor_to_dataset_end=is_archive_server(mcp.connection_manager, target),
            )
            result = {"type": "access_log", "server": target, **data}
            return _sanitize_log_result(mcp, result)
        except ToolError:
            raise
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

    @mcp.tool(annotations=_RO, tags={"logs", "live", "offline", "archive"})
    def parse_error_log(
        server_name: Optional[str] = None,
        severity: Optional[str] = None,
        include_archived_logs: bool = False,
        component: Optional[str] = None,
        time_range: Optional[str] = None,
        pattern: Annotated[Optional[str], Field(max_length=500, description="Regex filter pattern")] = None,
        limit: Annotated[int, Field(ge=1, le=10000, description="Max entries to return")] = 100,
    ) -> Dict[str, Any]:
        """Parse error log entries with full detail (requires expose_sensitive_data).

        Works with live local servers, offline instances, and archive sources.
        Reads the current error log only — rotated logs are not scanned.

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
            return _sanitize_log_result(mcp, {
                "type": "error_log",
                "server": target,
                "error": (
                    "Log parsing requires local or archive server access. "
                    f"Server '{target}' is a remote connection."
                ),
                "try_instead": ["first_look", "run_healthcheck"],
            })

        ds = None
        try:
            ds = mcp.connection_manager.connect(target)
            data = _parse_error_log_entries(
                ds, severity, component, time_range,
                pattern, max(1, limit),
                anchor_to_dataset_end=is_archive_server(mcp.connection_manager, target),
                include_archived=include_archived_logs,
            )
            result = {"type": "error_log", "server": target, **data}
            return _sanitize_log_result(mcp, result)
        except ToolError:
            raise
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

    @mcp.tool(annotations=_RO, tags={"logs", "live", "offline", "archive"})
    def parse_audit_log(
        server_name: Optional[str] = None,
        operation: Optional[str] = None,
        bind_dn: Optional[str] = None,
        target_dn: Optional[str] = None,
        time_range: Optional[str] = None,
        limit: Annotated[int, Field(ge=1, le=10000, description="Max entries to return")] = 100,
        include_archived_logs: bool = False,
    ) -> Dict[str, Any]:
        """Parse audit log entries with full detail (requires expose_sensitive_data).

        Works with live local servers, offline instances, and archive sources.
        Handles both traditional LDIF-format and JSON-format audit logs.
        Set include_archived_logs=True to also scan rotated logs.

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
            return _sanitize_log_result(mcp, {
                "type": "audit_log",
                "server": target,
                "error": (
                    "Log parsing requires local or archive server access. "
                    f"Server '{target}' is a remote connection."
                ),
            })

        ds = None
        try:
            ds = mcp.connection_manager.connect(target)
            data = _parse_audit_log_entries(
                ds, operation, bind_dn, target_dn,
                time_range, max(1, limit),
                anchor_to_dataset_end=is_archive_server(mcp.connection_manager, target),
                include_archived=include_archived_logs,
            )
            result = {"type": "audit_log", "server": target, **data}
            return _sanitize_log_result(mcp, result)
        except ToolError:
            raise
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

    @mcp.tool(annotations=_RO, tags={"logs", "live", "offline", "archive"})
    def analyze_access_log(
        server_name: Optional[str] = None,
        operation: Optional[str] = None,
        result_code: Optional[int] = None,
        time_range: Optional[str] = None,
        pattern: Annotated[Optional[str], Field(max_length=500, description="Regex filter pattern")] = None,
        include_archived_logs: bool = False,
    ) -> Dict[str, Any]:
        """Analyze access log statistics (operations, errors, slow queries). LOCAL/ARCHIVE.

        Returns aggregate statistics only — no individual log entries.
        Privacy-safe (works with privacy mode ON). For full log entries,
        use ``parse_access_log`` (requires expose_sensitive_data).

        Args:
            server_name: Target server name. Uses default if not specified.
            operation: Filter by operation type (SRCH, MOD, ADD, DEL, BIND, etc.).
            result_code: Filter by LDAP result code (e.g. 0 for success, 32 for not found).
            time_range: Time range filter. Supports:
                - Single date: "2024-01-01"
                - Range: "2024-01-01 to 2024-01-02"
                - Relative: "last 24h", "last 30m"
            pattern: Regex pattern to match against log lines.
                Requires expose_sensitive_data (rejected in privacy mode).
            include_archived_logs: Include rotated/compressed log files.

        Returns:
            Operation statistics, failed operations, slow operation summary,
            and unindexed search count.
        """
        if pattern and mcp.privacy_enabled:
            raise ToolError(
                "Parameter 'pattern' of tool 'analyze_access_log' is disabled "
                "in privacy mode. Set LDAP_MCP_EXPOSE_SENSITIVE_DATA=true to enable."
            )

        target = server_name or mcp.default_server
        if not target:
            return {"type": "access_log_analysis", "error": "No server configured"}

        if not _can_access_logs(mcp, target):
            return _sanitize_log_result(mcp, {
                "type": "access_log_analysis",
                "server": target,
                "error": (
                    "Log analysis requires local or archive server access. "
                    f"Server '{target}' is a remote connection."
                ),
                "try_instead": ["get_connection_statistics", "get_operation_statistics", "run_monitor"],
            })

        ds = None
        try:
            ds = mcp.connection_manager.connect(target)
            data = _parse_access_log_entries(
                ds, operation, result_code, time_range,
                pattern, include_archived_logs, 0,
                stats_only=True,
                anchor_to_dataset_end=is_archive_server(mcp.connection_manager, target),
            )
            result = {"type": "access_log_analysis", "server": target, **data}
            return _sanitize_log_result(mcp, result)
        except ToolError:
            raise
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

    @mcp.tool(annotations=_RO, tags={"logs", "live", "offline", "archive"})
    def analyze_error_log(
        server_name: Optional[str] = None,
        severity: Optional[str] = None,
        component: Optional[str] = None,
        time_range: Optional[str] = None,
        pattern: Annotated[Optional[str], Field(max_length=500, description="Regex filter pattern")] = None,
        include_archived_logs: bool = False,
    ) -> Dict[str, Any]:
        """Analyze error log statistics (severity, components, patterns). LOCAL/ARCHIVE.

        Reads the current error log only — rotated logs are not scanned.
        Returns aggregate statistics only — no individual log entries.
        Privacy-safe (works with privacy mode ON). For full log entries,
        use ``parse_error_log`` (requires expose_sensitive_data).

        Args:
            server_name: Target server name. Uses default if not specified.
            severity: Filter by severity level (INFO, WARNING, ERR, CRIT, EMERG).
            component: Filter by component name (e.g. "replication", "backend").
            time_range: Time range filter (same format as analyze_access_log).
            pattern: Regex pattern to match against log lines.
                Requires expose_sensitive_data (rejected in privacy mode).

        Returns:
            Severity counts, component counts, and common error patterns.
        """
        if pattern and mcp.privacy_enabled:
            raise ToolError(
                "Parameter 'pattern' of tool 'analyze_error_log' is disabled "
                "in privacy mode. Set LDAP_MCP_EXPOSE_SENSITIVE_DATA=true to enable."
            )

        target = server_name or mcp.default_server
        if not target:
            return {"type": "error_log_analysis", "error": "No server configured"}

        if not _can_access_logs(mcp, target):
            return _sanitize_log_result(mcp, {
                "type": "error_log_analysis",
                "server": target,
                "error": (
                    "Log analysis requires local or archive server access. "
                    f"Server '{target}' is a remote connection."
                ),
                "try_instead": ["first_look", "run_healthcheck"],
            })

        ds = None
        try:
            ds = mcp.connection_manager.connect(target)
            data = _parse_error_log_entries(
                ds, severity, component, time_range,
                pattern, 0,
                stats_only=True,
                anchor_to_dataset_end=is_archive_server(mcp.connection_manager, target),
                include_archived=include_archived_logs,
            )
            result = {"type": "error_log_analysis", "server": target, **data}
            return _sanitize_log_result(mcp, result)
        except ToolError:
            raise
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

    @mcp.tool(annotations=_RO, tags={"logs", "live", "offline", "archive"})
    def analyze_audit_log(
        server_name: Optional[str] = None,
        operation: Optional[str] = None,
        bind_dn: Optional[str] = None,
        target_dn: Optional[str] = None,
        time_range: Optional[str] = None,
        include_archived_logs: bool = False,
    ) -> Dict[str, Any]:
        """Analyze audit log statistics (change types, actors). LOCAL/ARCHIVE.

        Set include_archived_logs=True to also scan rotated logs.
        Returns aggregate statistics only — no individual change records.
        Privacy-safe (works with privacy mode ON). For full change records,
        use ``parse_audit_log`` (requires expose_sensitive_data).

        Args:
            server_name: Target server name. Uses default if not specified.
            operation: Filter by change type (modify, add, delete, modrdn).
            bind_dn: Filter by the DN that performed the change.
            target_dn: Filter by the target DN that was changed.
            time_range: Time range filter (same format as analyze_access_log).

        Returns:
            Change type statistics and actor statistics.
        """
        # DN-filtered exact counts are an existence/count oracle
        # for arbitrary DNs (with subtree matching, even enumeration).
        if mcp.privacy_enabled and (bind_dn or target_dn):
            raise ToolError(
                "Parameters 'bind_dn' and 'target_dn' of tool 'analyze_audit_log' "
                "are disabled in privacy mode: DN-filtered match counts can be "
                "used to probe for the existence of arbitrary entries. "
                "Set LDAP_MCP_EXPOSE_SENSITIVE_DATA=true to enable DN filters."
            )

        target = server_name or mcp.default_server
        if not target:
            return {"type": "audit_log_analysis", "error": "No server configured"}

        if not _can_access_logs(mcp, target):
            return _sanitize_log_result(mcp, {
                "type": "audit_log_analysis",
                "server": target,
                "error": (
                    "Log analysis requires local or archive server access. "
                    f"Server '{target}' is a remote connection."
                ),
            })

        ds = None
        try:
            ds = mcp.connection_manager.connect(target)
            data = _parse_audit_log_entries(
                ds, operation, bind_dn, target_dn,
                time_range, 0,
                stats_only=True,
                anchor_to_dataset_end=is_archive_server(mcp.connection_manager, target),
                include_archived=include_archived_logs,
            )
            result = {"type": "audit_log_analysis", "server": target, **data}
            return _sanitize_log_result(mcp, result)
        except ToolError:
            raise
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
