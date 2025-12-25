# OpenLDAP Tools Reference

Complete reference for OpenLDAP MCP tools, resources, and prompts.

This documentation covers the `openldap_mcp` provider.

> **Status:** In Development
>
> OpenLDAP support is currently under development. This document will be updated as tools are implemented.

## Planned Tools

The following tools are planned for the OpenLDAP provider:

### Health & Diagnostics
- `first_look()` - Quick health overview
- `monitor_stats()` - OpenLDAP monitor backend statistics

### User Management
- `list_all_users()` - Enumerate users
- `search_users_by_name()` - Search by name/email
- `get_user_details()` - Get user details

### Group Management
- `list_all_groups()` - Enumerate groups

### Advanced
- `ldap_search()` - Generic LDAP search

## Configuration

To use the OpenLDAP provider, set `provider_type` to `openldap` in your `servers.json`:

```json
{
  "servers": [
    {
      "name": "openldap-server",
      "ldap_url": "ldap://localhost:389",
      "base_dn": "dc=example,dc=com",
      "bind_dn": "cn=admin,dc=example,dc=com",
      "bind_password": "secret",
      "provider_type": "openldap"
    }
  ]
}
```

## Contributing

Contributions to OpenLDAP support are welcome! See [CONTRIBUTING.md](CONTRIBUTING.md) for guidelines.
