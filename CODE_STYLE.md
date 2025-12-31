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
    from src.dirsrv_mcp.server import DirSrvMCP


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
from src.lib.result_formatter import Severity, format_finding

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

- `src/lib/result_formatter.py` - Finding formatting, severity
- `src/lib/datetime_utils.py` - Date/time conversion
- `src/lib/value_utils.py` - Safe value conversion, byte formatting
- `src/dirsrv_mcp/connection.py` - Connection management, local server checks

```python
from src.lib.value_utils import safe_int, safe_float, format_bytes

# Use for status dict values (handles None, lists, invalid strings)
value = safe_int(status.get("currentconnections"))

# For direct lib389 object access, prefer typed methods:
value = obj.get_attr_val_int("nsslapd-threadnumber")
```

Don't duplicate helpers across tool modules.
