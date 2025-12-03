# UAT CLI Usability Audit

Version: 1.0  
Scope: Assess current CLI commands, help/UX, and gaps relative to the UAT Plan.

## Summary
The CLI is implemented via Typer in `src/agent/cli.py`. Available commands:
- init
- recon
- report
- add_asset
- list_assets
- remove_asset

Help text is present for all commands and uses Rich formatting for improved UX.

## Findings

### What Works (PASS)
- Global and per-command `--help` display with clear descriptions.
- Recon modes supported: `passive`, `active`, `lab` (argument to `recon`).
- Report generation supports `--format` and `--output`.
- Assets management lifecycle: add/list/remove.
- Initialization flow:
  - Legal notice with acknowledgment (can bypass with `--skip-legal` for tests)
  - Docker connectivity check
  - LLM endpoint connectivity check (non-fatal warnings)
  - File permission checks
  - Directory creation, config bootstrap, DB init

### Gaps vs UAT Plan (Action Needed)
- Adapters listing: No `adapters list` command exists.
  - Proposal: Add `adapters` Typer sub-app with `list` to enumerate available adapters via `PluginManager`.
- Dry-run planning: No explicit `run --dry-run`.
  - Proposal: Add `--dry-run` option to `recon`:
    - `passive`: validate assets/permissions only, no execution
    - `active/lab`: show `plan_active_scans()` steps without execution
- Version flag:
  - Proposal: Add `--version` using Typer’s version option (reads from package metadata).
- Exit code policy:
  - Ensure non-zero exit codes on fatal errors; warnings do not flip to failure.
- Windows UX niceties:
  - Add hints for PowerShell vs Cmd where quoting differs (only in help text documentation).

### UX/Copy Observations
- Consistent iconography and color styling via Rich.
- Error messages are informative and aligned with action prompts.
- `init` requires Docker; for environments without Docker, provide guidance to proceed with passive-only workflows.

## Compatibility Notes
- Typer app structure supports adding sub-apps (`adapters`) without breaking changes.
- `recon` already encapsulates planning/execution; adding `--dry-run` is a minimal, safe extension.

## Recommended Changes (Shortlist)
1. Add `adapters` group with `list`:
   - Reads available adapters from `src/agent/plugin_manager.py`.
   - Output table: name, description, category (passive/active), requirements (e.g., Docker).
2. Extend `recon`:
   - `--dry-run`: Show plan or validate only; do not execute.
   - `--adapters passive|nmap|gobuster,...` (optional filter for execution scope).
3. Add `--version` flag:
   - Pull from package metadata (e.g., `import importlib.metadata as im; im.version("black-glove")`).
4. Document expected behavior in README and UAT plan.

## Acceptance Matrix (Current)
- CLI help/subcommands: Partial PASS (no adapters list)
- Init/config workflows: PASS
- Plugin discovery via CLI: FAIL (missing adapters list)
- Dry-run planning: FAIL (missing)
- Evidence/reporting linkage (triggered after recon): PASS (per orchestrator/reporting implementation)

## Test Coverage Pointers
- `tests/test_cli_commands.py` covers:
  - Recon/report help text
  - Recon passive invocation (mocked)
  - Report invocation and error handling
  - Invalid recon mode
- Proposed new tests:
  - `tests/test_cli_usability.py`
    - `init --skip-legal` flow (mock Docker, requests; avoid real dependencies)
    - `recon --dry-run` with mocked orchestrator (plan only)
    - `adapters list` output formatting (mock PluginManager)
    - `--version` returns semver and exit code 0

## Next Steps
- Implement CLI extensions (adapters list, --dry-run, --version).
- Add tests per above and update UAT plan status.
- Update docs/README with new commands and examples.
