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

- **New tools:** Add to `src/dirsrv_mcp/tools/` or `src/openldap_mcp/tools/`
- **Shared utilities:** Add to `src/lib/`
- **Configuration:** Modify `src/config/`
- **Tests:** Add to `tests/`

## Adding New Tools

1. Create the tool function in the appropriate provider module
2. Register it with the MCP server
3. Add tests
4. Document in [TOOLS.md](TOOLS.md)

Example tool structure:

```python
from fastmcp import tool

@tool
def my_new_tool(param: str) -> dict:
    """Tool description.

    Args:
        param: Description of parameter

    Returns:
        Dictionary with results
    """
    # Implementation
    return {"result": "value"}
```

## Reporting Issues

When reporting bugs:
- Include Python version and OS
- Provide steps to reproduce
- Include error messages and logs
- Mention which LDAP server (389 DS, OpenLDAP) you're using

## Questions?

Open an issue for questions about contributing.
