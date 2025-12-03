# User Acceptance Testing (UAT) Plan

Version: 1.0  
Scope: Validate that Black Glove Agent is usable from the CLI, correctly deployable on Windows, and can run end-to-end workflows (passive + active adapters) against authorized safe targets, with evidence and reporting generated as specified.

## Objectives
- Verify CLI usability and discoverability (help, subcommands, init, config, adapter listing).
- Validate deployment (pip install, entry point, versioning) on Windows.
- Prove end-to-end workflows via orchestrator with passive adapters and active adapters (nmap, gobuster) executed via DockerRunner.
- Ensure safety: policy engine enforcement, rate limits, timeouts, and evidence storage contract.

## In Scope
- CLI UX, configuration, plugin discovery.
- Dockerized execution via DockerRunner (SDK with CLI fallback).
- Evidence storage under `evidence/{adapter}/`.
- Reporting pipeline production of summary output.

Out of Scope
- Real production targets beyond listed safe domains.
- Performance benchmarking beyond basic responsiveness.

## Environments & Prerequisites
- OS: Windows 11
- Shells:
  - Cmd.exe
  - PowerShell 7+
- Python: 3.12.x with virtualenv
- Docker Desktop installed and running (Linux container mode)
- Network access to safe domains (listed below)

## Authorized Safe Test Data (opt-in via config)
- example.com, example.net, example.org (IANA)
- scanme.nmap.org (nmap scans only; keep light, e.g., `-p 22,80,443 -T3`)
- badssl.com (SSL checks; selected subdomains)
- dnssec-failed.org (DNSSEC behavior)

Ensure these are explicitly authorized in `config/default_config.yaml` or user config before tests.

## Test Matrix

| Scenario | Cmd.exe | PowerShell 7+ | Python venv | Docker Desktop | Notes |
|---|---|---|---|---|---|
| CLI help/subcommands | ✅ | ✅ | ✅ | N/A | `black-glove --help`, `adapters list` |
| Init/config workflows | ✅ | ✅ | ✅ | N/A | Creates config, sets values |
| Plugin discovery | ✅ | ✅ | ✅ | N/A | Lists adapters incl. nmap/gobuster |
| Orchestrator passive (dry) | ✅ | ✅ | ✅ | N/A | No Docker required |
| Orchestrator active (nmap/gobuster) | ✅ | ✅ | ✅ | ✅ | DockerRunner executes tools |
| Evidence & reporting | ✅ | ✅ | ✅ | ✅ | Files under `evidence/*`, summary present |

## Test Scenarios

### 1) CLI Usability
- black-glove --help prints usage and subcommands
- black-glove adapters list shows passive and active adapters
- black-glove init creates baseline config
- black-glove config set/get updates and reads values
- black-glove run --dry-run validates targets and plan without execution

Acceptance:
- Exit code 0; clear usage text; adapters listed; config created; dry-run summarizes plan without errors.

### 2) Deployment Validation
- pip install . produces `black-glove` console script available in PATH
- black-glove --version shows version from package metadata
- `python -c "import black_glove"` succeeds in a clean venv

Acceptance:
- Installation completes without errors; entry point runnable in both Cmd and PowerShell.

### 3) End-to-End Workflows (Smoke)
- Passive adapters on example.com domains; evidence stored
- Active adapters:
  - Nmap: `-p 22,80,443 -T3` on scanme.nmap.org; XML parsed; evidence `.xml` saved
  - Gobuster:
    - DNS mode for example.com with tiny wordlist; stdout parsed; evidence `.txt`
    - DIR mode against a local controlled endpoint or example.com over HEAD-only with minimal wordlist if applicable
- Orchestrator run honoring policy engine, limits, and timeouts

Acceptance:
- Runs complete within configured timeout; no unauthorized target execution; evidence files present and non-empty; parsed results in AdapterResult payload.

### 4) Evidence, Reporting, and DB Integration (smoke)
- Evidence files written to `evidence/{adapter}/`
- Reporting module produces summary (JSON or textual) referencing evidence paths
- DB schema init occurs without migration errors (if applicable to run path)

Acceptance:
- Paths valid and accessible; report includes counts/summary without exceptions.

### 5) Safety & Policy
- Unauthorized targets are refused with a clear error/status
- Rate limiting and timeouts enforced; long operations abort cleanly with `TIMEOUT` status
- DockerRunner uses safe argument handling; no host FS leakage beyond mapped volumes

Acceptance:
- Attempts to run outside authorized domains fail fast; timeout scenarios recorded as such; no unsafe volume mounts.

## Execution Guide (Windows)

- PowerShell (preferred)
```powershell
# Create and activate venv
python -m venv .venv
.\.venv\Scripts\Activate.ps1

# Install
pip install --upgrade pip
pip install -e .

# Quick smoke
black-glove --help
black-glove adapters list
black-glove init
black-glove config get authorized_domains
```

- Cmd.exe
```bat
python -m venv .venv
.\.venv\Scripts\activate.bat
pip install -e .
black-glove --version
```

- Orchestrator dry-run
```powershell
black-glove run --targets example.com --dry-run
```

- Orchestrator active (ensure safe domains are authorized)
```powershell
black-glove run --targets example.com,scanme.nmap.org --adapters passive,nmap,gobuster --timeout 180
```

## Evidence & Reporting Expectations
- Evidence files:
  - Nmap: `evidence/nmap/<target>_*.xml`
  - Gobuster: `evidence/gobuster/<target>_*.txt`
  - Passive: `evidence/passive_recon/<target>_*.json`
- Report:
  - Summary includes adapter statuses, counts, and evidence paths
  - Stored under `evidence/uat/uat_summary_<timestamp>.json` (recommended)

## Acceptance Criteria Summary
- 100% pass for CLI usability and deployment on both shells
- End-to-end smoke completes with SUCCESS/INFO statuses (or graceful TIMEOUT where configured) and valid evidence
- Policy engine blocks unauthorized inputs
- No unhandled exceptions; non-zero exit codes only for genuine failures

## Data Capture & Reporting
- Capture terminal transcripts when possible
- Produce `docs/uat_report.md` including:
  - Date/time, environment, versions
  - Scenarios executed and results
  - Evidence index
  - Issues and recommended actions

Template snippet:
```markdown
# UAT Report
- Date:
- Env: Windows 11, PS 7, Python 3.12
- Version: <x.y.z>
## Results
- CLI: PASS
- Deploy: PASS
- E2E Passive: PASS
- E2E Active: PASS/WARN
## Evidence
- nmap: evidence/nmap/...
- gobuster: evidence/gobuster/...
```

## Risks & Mitigations
- Docker not available: skip active adapters; mark as N/A, document
- Network latency: extend timeouts minimally; keep scans light
- Windows path/quoting issues: prefer PowerShell; use absolute volume paths

## Traceability
- Adapters and DockerRunner behavior validated per `docs/project_requirements_plan.md`
- Task 11 items mapped to UAT checklist in current implementation tasks
