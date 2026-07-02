# Playbook: Summarize an SOS Report Before Opening the Case

**Symptom:** a customer or colleague hands you an SOS report (or a tarball of
`/etc/dirsrv` + logs) from a 389 Directory Server machine and asks "what's
wrong?". You want a structured summary — version, configuration problems,
error patterns, what changed — before you read a single raw file or open the
support case.

Everything in this playbook runs **without any LDAP connection** and works
with privacy mode on (the default). The archive never leaves your machine.

## What the assistant can read from an SOS report

| Data | Location inside the report | Used by |
|------|---------------------------|---------|
| Instance configuration | `etc/dirsrv/slapd-<inst>/dse.ldif` | `analyze_archive`, `validate_configuration`, `compare_dse_configs`, config/index tools |
| Access / error / audit logs | `var/log/dirsrv/slapd-<inst>/` | `analyze_*_log`, `parse_*_log`, `find_unindexed_searches` |
| `dsctl healthcheck` output captured by sos | `sos_commands/dirsrv/dsctl_slapd-<inst>_healthcheck` | `analyze_archive` |
| Schema and NSS cert databases | `etc/dirsrv/slapd-<inst>/` | inventory only |

Three layouts are auto-detected: a full SOS report (as above), a manual
extract (a `slapd-<inst>/` directory), and config-only (a bare `dse.ldif`).
Tarballs (`.tar`, `.tar.gz`, `.tar.xz`) are accepted directly — no need to
extract first.

## Setup

Add an archive entry to `servers.json` (no credentials needed):

```json
{
  "servers": [
    {
      "name": "customer-sos",
      "provider_type": "389ds",
      "is_archive": true,
      "archive_path": "/cases/01234567/sosreport-prod01-2026-06-28.tar.xz",
      "instance_name": "slapd-userroot"
    }
  ]
}
```

- `instance_name` is only needed when the report contains **multiple**
  instances; omit it otherwise.
- For a logs-only or unusually laid-out extract, `config_path` and
  `logs_path` can point at the directories explicitly.

## Step 1 — Inventory: `analyze_archive`

> *"Analyze the customer-sos archive — what are we looking at?"*

Always start here. It returns:

- **Source type** (`sos_report`, `manual_extract`, `config_only`) and instance name
- **DS version** and port configuration from dse.ldif
- **Data inventory** — which logs, schema, and certificate files are actually
  present (so you know which follow-up tools have data to work with)
- **Configuration summary** — backends, suffixes, plugins, replication
  enabled or not
- **Parsed `dsctl healthcheck` results** if sos captured them — these are the
  customer machine's own lint findings at collection time

**Expected findings:** the healthcheck section is the fastest signal — real
`DS Lint Error` blocks (severity, details, resolution) parsed from the sos
output. An empty inventory row tells you what you *cannot* analyze (e.g. no
audit log collected).

## Step 2 — Static config lint: `validate_configuration`

> *"Validate the configuration in the customer-sos archive."*

Runs the offline equivalent of `run_healthcheck` against dse.ldif: nsState
(replica clock skew), password storage scheme, TLS minimum version, access
log buffering, audit logging, TLS/SSL enablement, anonymous access. Findings
come back in the same severity/description/remediation format as
`run_healthcheck`.

**Expected findings:** weak password schemes, `sslVersionMin` below TLS1.2,
audit logging disabled, unrestricted anonymous access.

## Step 3 — Logs: `analyze_error_log`, `analyze_access_log`

> *"Analyze the error log in customer-sos — what are the most common errors?"*
> *"Analyze the access log for the last day covered by the report."*

- `analyze_error_log` — severity counts, component counts, recurring error
  patterns. Filter with `severity="ERR"` or `component="replication"` to
  drill in.
- `analyze_access_log` — operation statistics, failed operations, slow
  operations, unindexed search count. `include_archived_logs=true` also scans
  rotated access logs; error/audit analysis reads the current file only.
- `find_unindexed_searches` — pulls the actual unindexed (`notes=U/A`)
  queries out of the access log, aggregated by filter. Traditional-format
  access logs only; on a JSON-logging instance use `analyze_access_log`
  (its unindexed count handles both formats).
- `analyze_audit_log` — change-type and actor statistics, if the report
  includes an audit log.

These return **statistics only** and are privacy-safe. The `parse_*_log`
variants return full log entries and require
`LDAP_MCP_EXPOSE_SENSITIVE_DATA=true` — only enable that with a local or
private model.

**Expected findings:** replication component errors, disk/BDB warnings,
spikes of err=32/err=49, slow or unindexed searches matching the reported
symptom window.

## Step 4 — Diff against known-good: `compare_dse_configs`

If you have a baseline — an SOS report from before the problem started, a
lab instance's config, or another supplier in the same topology — add it as a
second archive server and compare:

> *"Compare dse.ldif between customer-sos and baseline-sos, replication
> section only."*

`compare_dse_configs(server1, server2, section=...)` diffs **every entry** in
dse.ldif (not just `cn=config`). `section` narrows it: `plugins`, `indexes`,
`replication`, `security`, `backends`, `config`, or `all`.

**Expected findings:** the "what changed" answer — entries present on only
one side, per-attribute differences (credential attributes are always
redacted).

## What these tools cannot know

- **Runtime state.** An SOS report is a snapshot of config + logs. There is
  no cn=monitor data: no current connections, cache hit ratios, replication
  lag, or thread state. Statements about *current* behavior are
  extrapolation.
- **Whether the config still matches production.** The customer may have
  changed things since collection.
- **Directory data.** User entries, group membership, and database contents
  are not in an SOS report — only configuration and logs.
- **Log coverage gaps.** sos truncates/rotates collection; the window in the
  report may not include the incident. Check log timestamps in the
  `analyze_archive` inventory first.
- **Root cause vs. symptom.** The LLM interprets the findings; verify its
  narrative against the raw findings before writing it into the case.

## Verify on the customer system (safe, read-only)

Ask the customer (or run on the live system, if you have access) to confirm
findings from the archive analysis:

```bash
# The same lint the archive tools approximate, but live:
dsctl <instance> healthcheck

# Replication: full topology report and per-suffix status
dsconf <instance> replication monitor
dsconf <instance> replication status --suffix "dc=example,dc=com"

# Current runtime counters that the SOS report cannot contain:
dsconf <instance> monitor server
dsconf <instance> monitor dbmon
dsconf <instance> monitor disk

# Config values flagged by validate_configuration / compare_dse_configs:
dsconf <instance> config get nsslapd-auditlog-logging-enabled
dsconf <instance> backend suffix list
dsconf <instance> plugin list
```

All of these are read-only. Do not act on remediation suggestions (index
rebuilds, config changes) without normal change control.

## Quick reference: the four questions in order

1. "Analyze the `<name>` archive" → `analyze_archive`
2. "Validate its configuration" → `validate_configuration`
3. "What do the error and access logs show?" → `analyze_error_log`, `analyze_access_log`
4. "What changed vs. `<baseline>`?" → `compare_dse_configs`

The `archive_investigation` MCP prompt walks through the same sequence
interactively.
