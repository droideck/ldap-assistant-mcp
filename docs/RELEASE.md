# Release Checklist

Publishing is **automated**: pushing a `v*` tag runs
[release.yml](../.github/workflows/release.yml), which builds the package,
verifies the tag matches `pyproject.toml`, publishes to PyPI via trusted
publishing, and then publishes to the official MCP Registry via
`mcp-publisher` (that last step self-skips while `server.json` is absent).

This checklist covers only what the workflow cannot do for you.

## One-time setup (before the first release)

- [ ] PyPI: confirm the name `ldap-assistant-mcp` is still unclaimed, then
      add a **trusted publisher** (project `ldap-assistant-mcp` → Publishing →
      GitHub → this repo, workflow `release.yml`, environment `pypi`).
- [ ] GitHub: create an environment named `pypi`
      (Settings → Environments).

## Pre-tag checklist

Version lockstep — all of these must agree:

- [ ] `pyproject.toml` `version`
- [ ] README version badge
- [ ] `server.json` `version` (once it exists)
- [ ] `CHANGELOG.md` has a section for this version (dated, no "Unreleased"
      leftovers)

Quality gates (all local, no containers needed):

- [ ] `ruff check src tests` clean
- [ ] `pytest -m "not live"` green — this includes the eval routing suite
      (`tests/eval/run_eval.py`) and the privacy/sanitizer suites
      (`test_privacy*.py`, `test_phase2_blockers.py`); none may be skipped or
      deselected
- [ ] `python -m build && twine check dist/*` pass locally

Artifact hygiene:

- [ ] No secrets in the artifacts:
      `tar tzf dist/*.tar.gz | grep -E 'servers.*\.json|fastmcp\.json'`
      matches **nothing** (the sdist only-includes `src/` and `CHANGELOG.md`;
      any hit means the build config regressed)
- [ ] The MCP Registry ownership token survives into the PyPI long
      description: `unzip -p dist/*.whl '*/METADATA' | grep mcp-name`
      must print `mcp-name: io.github.droideck/ldap-assistant-mcp`

Smoke test on a clean host (or at minimum a clean venv):

- [ ] `uvx --from dist/ldap_assistant_mcp-*.whl ldap-assistant-mcp` starts,
      logs the configured servers, and waits on stdio (Ctrl+C to exit)
- [ ] With a real `LDAP_SERVERS_CONFIG`, `list_servers` answers through an
      MCP client

## Tag and release

```bash
git tag v0.X.Y
git push origin v0.X.Y
```

- [ ] Watch the Actions run: build → publish-pypi → publish-mcp-registry
      (registry step skips until `server.json` lands)

## Post-publish verification

- [ ] PyPI page shows the new version and the README renders (badge, no
      broken relative links)
- [ ] MCP Registry lists the server:
      `curl -s 'https://registry.modelcontextprotocol.io/v0/servers?search=ldap-assistant-mcp'`
- [ ] Clean-host install from the published package:
      `uvx ldap-assistant-mcp==0.X.Y`
- [ ] Configure one MCP client against the **published** package (not an
      editable checkout) and run `first_look` end to end

## If something goes wrong

- PyPI versions are immutable: never re-upload a deleted version. Fix,
  bump the patch version (all lockstep locations), and tag again.
- A failed `publish-mcp-registry` step can be re-run from the Actions UI —
  PyPI publication is not affected.
