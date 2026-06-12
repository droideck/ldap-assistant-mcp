# Contributing Guide

Thank you for your interest in contributing to LDAP Assistant MCP!

## Getting Started

1. Fork the repository
2. Clone your fork
3. Set up the development environment (see [DEVELOPMENT.md](DEVELOPMENT.md))
4. Create a feature branch

## Development Workflow

### 1. Set Up Your Environment

First, install the required system dependencies for building `python-ldap` — see the [Prerequisites](../README.md#prerequisites) section in the README.

```bash
# Clone and enter the project
git clone https://github.com/YOUR_USERNAME/ldap-assistant-mcp.git
cd ldap-assistant-mcp

# Create dev containers
./scripts/ds-dev.sh create

# Verify everything works
./scripts/ds-test.sh
```

### 2. Make Your Changes

- Follow existing code style and patterns
- Add tests for new functionality
- Update documentation as needed

### 3. Run Tests

Before submitting, ensure all tests pass:

```bash
./scripts/ds-test.sh
```

See [TESTING.md](TESTING.md) for more testing options.

### 4. Submit a Pull Request

- Write a clear PR description
- Reference any related issues
- Ensure CI passes

## Code Style

- Use Python type hints
- Follow PEP 8 conventions
- Keep functions focused and small
- Write descriptive docstrings

## Project Structure

When adding new features:

- **New tools:** 389 DS tools live in `src/ldap_assistant_mcp/dirsrv_mcp/tools/`; OpenLDAP tools are registered directly in `src/ldap_assistant_mcp/openldap_mcp/server.py`
- **Shared utilities:** Add to `src/ldap_assistant_mcp/lib/`
- **Configuration:** Modify `src/ldap_assistant_mcp/config/`
- **Tests:** Add to `tests/dirsrv_mcp/` (all tests live in the top-level `tests/` directory, outside the distribution package)

## Adding New Tools

1. Create the tool function in the appropriate provider module
2. Register it with the MCP server
3. Add tests
4. Document in [TOOLS.md](../src/ldap_assistant_mcp/dirsrv_mcp/TOOLS.md)

Example tool structure (see `src/ldap_assistant_mcp/dirsrv_mcp/tools/groups.py` for a full example):

```python
from mcp.types import ToolAnnotations

_RO = ToolAnnotations(readOnlyHint=True, idempotentHint=True, destructiveHint=False, openWorldHint=True)


def register_my_tools(mcp: DirSrvMCP) -> None:
    """Register tools with the MCP server."""

    @mcp.tool(annotations=_RO, tags={"mydomain", "live"})
    def my_new_tool(param: str) -> Dict[str, Any]:
        """Tool description (this docstring becomes the MCP tool description)."""
        # Implementation
        return {"result": "value"}
```

Each `src/ldap_assistant_mcp/dirsrv_mcp/tools/<module>.py` exposes a `register_*_tools(mcp)` function that is called during server setup in `src/ldap_assistant_mcp/dirsrv_mcp/server.py`.

## Reporting Issues

When reporting bugs:
- Include Python version and OS
- Provide steps to reproduce
- Include error messages and logs
- Mention which LDAP server (389 DS, OpenLDAP) you're using

## Questions?

Open an issue for questions about contributing.
