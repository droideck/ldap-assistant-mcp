# Security Policy

## Supported Versions

| Version      | Supported          |
| ------------ | ------------------ |
| 0.5.x (beta) | :white_check_mark: |
| < 0.5        | :x:                |

Only the latest 0.5.x release receives security fixes. The project is in beta —
there is no long-term support branch.

## Reporting a Vulnerability

Please report vulnerabilities privately via
[GitHub Security Advisories](https://github.com/droideck/ldap-assistant-mcp/security/advisories/new).
**Do not open a public issue** for anything you believe is a security problem.

This is a single-maintainer project. Realistically:

- You should get an initial response within **one week**.
- Confirmed issues are fixed on a best-effort basis, typically in the next
  release. There is no bug bounty and no guaranteed fix timeline.
- If you get no response after two weeks, feel free to ping by opening a public
  issue that says only "submitted a security advisory, please take a look" —
  without details.

## Scope

This is a read-only diagnostic MCP server for 389 Directory Server, so the
attack surface is narrow — but the data it reads is sensitive. Reports
explicitly in scope as security issues:

- **Privacy-mode data leakage** — any tool output, error message, or log line
  that exposes unsanitized DNs, hostnames, IP addresses, or other identifying
  directory data while privacy mode is enabled. Treat these as
  vulnerabilities, not bugs.
- Credential exposure — bind passwords logged, echoed in tool output, or
  written to disk.
- Any way a tool can modify the directory server or the host despite the
  read-only contract.
- Path traversal or injection via tool arguments (archive paths, LDIF files,
  log paths, regex filters).
