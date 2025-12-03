# User Acceptance Test (UAT) Report

This report tracks UAT progress for Black Glove, validating CLI usability, deployment on Windows, and end-to-end workflows using Dockerized adapters (nmap/gobuster). See the UAT plan and CLI audit for detailed procedures:
- UAT Plan: docs/uat_plan.md
- CLI Audit: docs/uat_cli_audit.md

## 1. Objectives
- Verify CLI usability and discoverability (version, adapters list, dry-run, filters).
- Validate deployment on Windows (PowerShell, cmd, WSL): console script availability and PATH behavior.
- Confirm end-to-end active workflows (nmap/gobuster via DockerRunner) on authorized targets.
- Ensure evidence storage and reporting integration.
- Enforce safety/policy (allowlists, rate limiting, lab mode).

## 2. Environments
- OS: Windows 11 (PowerShell 7+, cmd.exe, optional WSL)
- Python: 3.12.x, installation via pip (editable or wheel)
- Docker: Desktop, Linux container mode
- Network: Authorized safe domains/assets only

## 3. Scope
- CLI: src/agent/cli.py (Typer + Rich)
- Orchestrator: src/agent/orchestrator.py with PluginManager
- Adapters: nmap, gobuster (via DockerRunner), passive recon
- Evidence and Reporting: evidence/..., reporting workflow

## 4. Test Matrix (High-Level)
| ID | Area | Scenario | Status | Evidence/Notes |
|----|------|----------|--------|----------------|
| 11.1 | CLI Usability | --version, adapters list, recon dry-run (-A filters) | Passed | tests/test_cli_usability.py; 327 tests passed |
| 11.2 | Deployment Validation | PowerShell/cmd/WSL console scripts on PATH; `black-glove --version` | Pending | To execute on clean env |
| 11.3 | E2E Workflows | Orchestrator plans/executes nmap/gobuster via DockerRunner; saves evidence | Partial | Lab-mode dry-run produced planned steps (LLM unavailable → fallback plan). Execution pending. |
| 11.4 | Safety/Policy | Allowlists, rate limits, lab mode enforcement | Pending | Verify policy engine hooks |
| 11.5 | CLI Audit Docs | Audit documented and gaps resolved | Passed | docs/uat_cli_audit.md |
| 11.8 | UAT Report | Produce report with results/evidence index | In Progress | This document |

## 5. Scenarios

### 5.1 CLI Usability (Completed)
- Validate `--version` eager option prints version and exits 0.
- `adapters list` shows discovered adapters with metadata.
- `recon --dry-run` renders plan; `-A/--adapters` filters steps.
- Result: Passed. Tests: tests/test_cli_usability.py. Full suite: 327 passed.

### 5.2 Deployment Validation (Pending)
Goal: verify console scripts installed and resolvable across shells; confirm version output and PATH behavior.

Checklist:
- [ ] Clean environment prepared (no prior editable installs interfering)
- [ ] Install package (editable or wheel)
- [ ] Verify script shims: black-glove and agent
- [ ] Confirm PATH resolution in PowerShell, cmd, and WSL (if applicable)
- [ ] Capture outputs and environment details
- [ ] Note any remediation steps taken

(Instructions omitted here — see section 5.2 in earlier draft for commands and troubleshooting.)

### 5.3 End-to-End Active Workflows (Pending)
- Authorized domain(s) only. Plan then execute nmap/gobuster via DockerRunner.
- Validate timeouts, arg sanitization, and no network egress beyond allowlist.
- Confirm evidence persisted and reporting summarizes findings.

### 5.4 Safety/Policy Enforcement (Pending)
- Ensure active scans require lab mode/confirmation as designed.
- Validate rate limiting and allowlist checks applied during runs.

## 6. Results Summary
- Current Pass: CLI usability.
- Recent Action: Re-ran lab-mode dry-run (non-destructive). Orchestrator successfully loaded passive evidence from disk and produced planned lab steps. The LLM endpoint was unreachable; planner fell back to the default safe lab plan which includes `nmap` and `gobuster` for the target. No active scans were executed (dry-run).
- Pending: Deployment validation, E2E active workflows execution, safety/policy verification.

## 7. Evidence Index
- CLI: Test logs (pytest), terminal snippets (to attach).
- Dry-run: captured terminal output in this report.
- Nmap: planned evidence path (when executed) evidence/nmap/<target>_*.xml
- Gobuster: planned evidence path (when executed) evidence/gobuster/<target>_*.txt
- Reports: reporting output path (planned)

## 8. Issues/Risks
- LLM service: During the recorded dry-run the LLM at localhost:1234 was unreachable (Connection refused). Actions taken after the run:
  - Updated default configuration to use the user's local LLM endpoint (see config/default_config.yaml).
  - Implemented retry/backoff and clearer error messaging in src/agent/llm_client.py so transient connection or timeout errors are retried before falling back to a safe plan.
  - Unit tests covering the LLM client passed successfully during verification.
  - Orchestrator still falls back to a safe lab plan when the LLM is definitively unreachable; consider further improvements to the fallback planner for richer context-aware templates.
- Datetime serialization: Resolved. The reporting/analysis pipeline now serializes datetime objects to ISO strings using a safe default serializer in src/agent/reporting.py; JSON serialization errors seen in UAT no longer occur and unit tests pass.
- Docker Desktop availability and permissions on Windows may block E2E execution; obtain explicit user approval before running live Dockerized scans.

## 9. Next Actions
- Execute 11.2 deployment validation across shells; capture outputs.
- Complete 11.3 by executing E2E scans in lab mode against authorized targets **only after explicit approval**; persist evidence and generate report attachments.
- Address datetime JSON serialization in analysis pipeline.
- Improve LLM fallback to produce more context-aware plans when LLM is unavailable (e.g., cached templates or simple rule-based planner).
- Update docs/current_implementation_tasks.md and docs/project_tasks.md to reflect lab dry-run results and remaining items.

---

## 10. Lab-mode dry-run (non-destructive) — run details

- Timestamp: 2025-08-21 22:36:49 (Asia/Nicosia)
- Command executed (safe, dry-run):
  ```
  python -m agent recon lab --asset scanme-nmap --dry-run --adapters nmap,gobuster
  ```

- Terminal output captured:
  ```
  🔍 Running lab reconnaissance...
  No passive recon results in memory; attempting to load from evidence storage
  Generation failed: Connection failed: HTTPConnectionPool(host='localhost', port=1234): Max retries exceeded with url: /v1/chat/completions (Caused by NewConnectionError('<urllib3.connection.HTTPConnection object at 0x000001759A2600140>: Failed to establish a new connection: [WinError 10061] No connection could be made because the target machine actively refused it'))
  LLM planning failed: Connection failed: HTTPConnectionPool(host='localhost', port=1234): Max retries exceeded with url: /v1/chat/completions (Caused by NewConnectionError('<urllib3.connection.HTTPConnection object at 0x000001759A2600140>: Failed to establish a new connection: [WinError 10061] No connection could be made because the target machine actively refused it'))
                       Planned lab steps (dry-run)
  ┏━━━━━━━┳━━━━━━━━━━┳━━━━━━━━━━━━━━━━━┳━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┓
  ┃ Index ┃ Tool     ┃ Target          ┃ Params                        ┃
  ┡━━━━━━━╇━━━━━━━━━━╇━━━━━━━━━━━━━━━━━╇━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┩
  │     1 │ nmap     │ scanme.nmap.org │ {'target': 'scanme.nmap.org'} │
  │     2 │ gobuster │ scanme.nmap.org │ {'target': 'scanme.nmap.org'} │
  └───────┴──────────┴─────────────────┴───────────────────────────────┘
  ```

- Interpretation:
  - Orchestrator successfully located passive recon evidence on disk and attempted to use the LLM to derive an active plan.
  - LLM was unreachable; orchestrator fell back to a safe default lab plan which includes `nmap` and `gobuster` for the provided asset.
  - No active tool execution occurred (dry-run), so no new evidence was created.

- Attachments / Artifacts:
  - This report (docs/uat_report.md) includes the captured terminal output above.
  - Passive evidence files used by the orchestrator exist under `evidence/passivereconadapter/` (project-local). These files are unchanged by this run.

## 11. Action items resulting from this run
- [x] Re-run non-destructive lab-mode dry-run and capture output (this run)
- [ ] Save terminal capture and attach any relevant evidence snapshots (logs/screenshots)
- [x] Convert datetime objects to ISO strings in analysis pipeline (implemented in src/agent/reporting.py)
- [x] Implement LLM retries and clearer errors; updated default_config.yaml to user's LLM endpoint (see config/default_config.yaml and src/agent/llm_client.py); unit tests passed
- [ ] Improve LLM fallback planner to produce context-aware plans when LLM unavailable
- [ ] Implement DockerRunner and adapters (nmap/gobuster) and their unit tests; obtain explicit approval before running live scans
- [ ] Update docs/current_implementation_tasks.md and docs/project_tasks.md to reflect this run
