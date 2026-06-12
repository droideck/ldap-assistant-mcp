# Code Style Guide

Concise style guide for 389 DS MCP. Code should be self-explanatory.

## File Structure

```python
"""Module docstring - one line description."""

from __future__ import annotations

# stdlib
# third-party (lib389, fastmcp)
# local (src.*)

from typing import TYPE_CHECKING, Any, Dict, List, Optional

if TYPE_CHECKING:
    from ldap_assistant_mcp.dirsrv_mcp.server import DirSrvMCP


def _helper_function() -> str:
    """Private helpers at module level, prefixed with underscore."""
    pass


def register_*_tools(mcp: DirSrvMCP) -> None:
    """Registration function - one per module."""

    @mcp.tool()
    def tool_name(server_name: Optional[str] = None) -> Dict[str, Any]:
        """Tool docstring."""
        pass
```

## Tool Pattern

```python
@mcp.tool()
def get_something(
    param: str,
    server_name: Optional[str] = None,
) -> Dict[str, Any]:
    """Brief description.

    Args:
        param: Description.
        server_name: Target server. Uses default if not specified.

    Returns:
        Description of return structure.
    """
    target = server_name or mcp.default_server
    if not target:
        return {"type": "something", "error": "No server configured"}

    ds = None
    try:
        ds = mcp.connection_manager.connect(target)
        # ... work ...
        return {
            "type": "something",
            "server": target,
            "summary": "HEALTHY: ...",  # or "WARNING: ..." or "CRITICAL: ..."
            "data": result,
            "findings": findings,
        }
    except Exception as e:
        mcp.logger.error("Error doing something: %s", e)
        return {"type": "something", "server": target, "error": str(e)}
    finally:
        if ds:
            try:
                ds.close()
            except Exception:
                pass
```

Alternative using context manager (for simpler tools):

```python
@mcp.tool()
def list_something(server_name: Optional[str] = None) -> Dict[str, Any]:
    """Brief description."""
    target = server_name or mcp.default_server
    with mcp._connection(target) as (srv, ds):
        # ... work ...
        return {"type": "something_list", "server": srv, "items": results}
```

## Return Structure

All tools return `Dict[str, Any]` with consistent keys:

| Key | Required | Description |
|-----|----------|-------------|
| `type` | Yes | Tool identifier (e.g., `"replication_status"`) |
| `server` | Yes | Server name |
| `summary` | Diagnostic tools | Human-readable status line |
| `error` | On failure | Error message |
| `items` | List tools | Array of results |
| `findings` | Diagnostic tools | Array of `format_finding()` results |

### Summary Format

```
"HEALTHY: All 3 agreements in sync"
"WARNING: 2 issues found"
"CRITICAL: Replication failing"
```

### Findings

Use `format_finding()` from `src.lib.result_formatter`:

```python
from ldap_assistant_mcp.lib.result_formatter import Severity, format_finding

findings.append(format_finding(
    title="Descriptive Title",
    severity=Severity.HIGH,
    impact="What users/service experience",
    details="Technical details",
    remediation="Steps to fix",
    server=target,
    metadata={"key": value},  # optional
))
```

## lib389 API

```python
# Connection objects
from lib389.replica import Replicas
from lib389.monitor import Monitor
from lib389.backend import Backends

replicas = Replicas(ds)
for replica in replicas.list():
    suffix = replica.get_suffix()

# Attribute access
value = obj.get_attr_val_utf8("attributeName")      # single value
values = obj.get_attr_vals_utf8("attributeName")    # multi-value
all_attrs = obj.get_all_attrs_json()                # all as JSON string

# Status/monitor
status = monitor.get_status()  # returns dict
```

## Naming

- `snake_case` for functions and variables
- Tool names: `verb_noun` (e.g., `get_replication_status`, `list_users`)
- Helper functions: prefix with `_`
- No abbreviations except common ones (`dn`, `cn`, `url`)

## Comments

- Docstrings for public functions
- No inline comments unless truly necessary for non-obvious logic
- Code should be self-explanatory

## Error Handling

- Return error in result dict, don't raise (except for truly invalid input)
- Log errors: `mcp.logger.error("Message: %s", error)`
- Log warnings for non-fatal issues: `mcp.logger.warning(...)`
- Log debug for skipped operations: `mcp.logger.debug(...)`

## Shared Utilities

Put reusable helpers in appropriate locations:

- `src/ldap_assistant_mcp/lib/result_formatter.py` - Finding formatting, severity
- `src/ldap_assistant_mcp/lib/datetime_utils.py` - Date/time conversion
- `src/ldap_assistant_mcp/lib/value_utils.py` - Safe value conversion, byte formatting
- `src/ldap_assistant_mcp/dirsrv_mcp/connection.py` - Connection management, local server checks
- `src/ldap_assistant_mcp/dirsrv_mcp/tools/dse_utils.py` - DN normalization, DSEldif helpers (shared across config, indexes, health, archive tools)

```python
from ldap_assistant_mcp.lib.value_utils import safe_int, safe_float, format_bytes

# Use for status dict values (handles None, lists, invalid strings)
value = safe_int(status.get("currentconnections"))

# For direct lib389 object access, prefer typed methods:
value = obj.get_attr_val_int("nsslapd-threadnumber")
```

Don't duplicate helpers across tool modules.

## Version-Agnostic Design

Tools must work across all 389 Directory Server versions. Follow these principles:

### Dynamic Data Retrieval

Prefer dynamic attribute fetching over hardcoded lists:

```python
# GOOD - works across all versions
all_attrs = config.get_all_attrs()
for attr, values in all_attrs.items():
    if pattern and pattern.lower() not in attr.lower():
        continue
    result[attr] = normalize_value(values)

# BAD - may miss attributes in newer/older versions
HARDCODED_ATTRS = ["nsslapd-port", "nsslapd-security", ...]
for attr in HARDCODED_ATTRS:
    result[attr] = config.get_attr_val_utf8(attr)
```

### Acceptable Hardcoded Elements

Some hardcoded values are acceptable when they represent **universal best practices**:

| Category | Example | Rationale |
|----------|---------|-----------|
| Recommended indexes | `uid`, `cn`, `mail`, `member` | RFC standard attributes |
| Index types | `eq`, `pres`, `sub`, `approx` | LDAP spec, won't change |
| Industry thresholds | 95% disk critical, 85% warning | Universal ops standards |
| Certificate warnings | 30 days, 7 days | Industry best practice |
| Cache health | 70%+ hit ratio = acceptable | Performance best practice |

### lib389 Handles Version Differences

Trust lib389 to handle version-specific logic internally:

```python
# GOOD - lib389 handles role enum across versions
from lib389._constants import ReplicaRole
role = replica.get_role()  # Returns ReplicaRole enum

# GOOD - lib389 status colors are version-independent
status = agmt.get_agmt_status(return_json=True)
if status.get("state") == "red":  # lib389's internal indicator
    ...
```

### Separation of Concerns

**Tools provide data** - LLMs provide situational analysis:

```python
# GOOD - Return raw metrics, let LLM contextualize
return {
    "type": "cache_statistics",
    "entry_cache_hit_ratio": 65.4,
    "entry_cache_tries": 50000,
    "findings": findings,  # Universal threshold violations only
}

# BAD - Making situational recommendations in tools
if hit_ratio < 90 and workload_type == "read_heavy":
    recommendations.append("Consider increasing cache")  # Situational!
```

### Pattern-Based Filtering

Use flexible patterns instead of fixed categories:

```python
# GOOD - Flexible pattern matching
def get_server_configuration(
    pattern: Optional[str] = None,  # e.g., "cache", "security", "port"
    server_name: Optional[str] = None,
) -> Dict[str, Any]:
    all_attrs = config.get_all_attrs()
    for attr, values in all_attrs.items():
        if pattern and pattern.lower() not in attr.lower():
            continue
        ...

# BAD - Fixed sections that may not match all versions
SECTIONS = {
    "cache": ["nsslapd-cachememsize", "nsslapd-cachesize"],  # May be incomplete
    ...
}
```

### Error Resilience

Handle missing attributes gracefully:

```python
# GOOD - Safe retrieval with fallbacks
from ldap_assistant_mcp.lib.value_utils import safe_int, safe_float

value = safe_int(status.get("some_attribute"))  # Returns 0 if missing
ratio = safe_float(status.get("hit_ratio"))     # Returns 0.0 if missing

# BAD - Assumes attribute exists
value = int(status["some_attribute"])  # KeyError if missing in some versions
```
