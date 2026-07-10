# Black Glove — Tool Skills & Result Contract

This document describes adapter/tool behavior visible to agents, the trace API, and the findings/reporting pipeline.

## Tool result statuses

All adapter-backed tools flow through `ToolResultEnvelope` with these canonical statuses:

| Status | Meaning |
|--------|---------|
| `success` | Core data collected; interpretation and findings may proceed |
| `partial` | Tool ran but core fields are missing or degraded (e.g. RDAP/WHOIS empty registrar) |
| `error` | Execution failed; `error_message` explains the failure |
| `not_applicable` | Preconditions not met (e.g. web vuln/SQLi scan with zero query parameters) |

**Rules:**
- `partial` is **not** treated as unconditional success in the envelope, trace, or findings normalizer.
- `not_applicable` / zero-test coverage must **not** produce "no vulnerabilities found" findings.
- Warnings, coverage metrics, bounded report text, and evidence paths are preserved end-to-end.

## Trace metadata

`agent_events.details_json` stores structured fields for `tool_result` events:

- `tool`, `status`, `warnings`, `coverage`, `evidence_paths`, `digest`, worker/approval fields when present
- Legacy rows without `details_json` deserialize safely from `params` only

## Run-scoped reporting

- Findings persist `run_id` and `step_id` when execution provenance is available.
- **`finding_observations`** is an append-only ledger: each save records a run/step snapshot even when fingerprints deduplicate across runs.
- `get_findings_from_database(run_id=...)` returns **one row per canonical finding** (latest observation per `finding_id`); duplicate re-saves of unchanged conflicted peers do not inflate report counts.
- `generate_report` defaults to the current run's findings when provenance context is set.

## Cross-tool conflict reconciliation

When Wappalyzer detects HSTS but `web_server_scanner` reports a missing `Strict-Transport-Security` header on the same asset **within the same run**:

- The missing-header finding is downgraded to `INFO` with `verification_state: conflicted`.
- Reports exclude conflicted items from risk score / key findings and list them under **Reconciled Observations**.
- Reconciliation is scoped to the active `run_id`; stale HSTS fingerprinting from prior runs does not trigger conflicts.
- Only findings **newly mutated** by reconciliation are persisted; unrelated tools do not re-append observations for already-conflicted rows.

## External dependency degradation

### `passive_recon` / `osint_harvester` (crt.sh)
- Upstream crt.sh 502/503/timeout → `partial` (not hard `error`) with `warnings` and `coverage.crt_sh_ok: false`.
- Empty Wayback results (0 snapshots, no exception) → `partial` with `wayback: no snapshots returned` warning.
- crt.sh subdomain data is normalized into findings; generic `scan completed` rows are omitted when crt.sh or Wayback produced data.
- Shared retry logic lives in `crt_sh_client` (not discovered as an adapter).

## Adapter notes (user-visible)

### `whois`
- RDAP-first for Google Registry TLDs (`.dev`, `.app`, etc.) via IANA DNS bootstrap with Google Registry fallback.
- Legacy python-whois is a fallback for other TLDs.
- Empty registrar/dates → `partial` with warnings, never a successful registration finding.

### `web_vuln_scanner` / `sqli_scanner`
- URLs without query parameters → `not_applicable` with `coverage.parameters_tested = 0`.

### `web_server_scanner`
- Missing security headers include request URL and HTTP status in evidence.
- HSTS detected by fingerprinting but absent in direct header checks is flagged as a cross-tool conflict note when scanned over HTTPS in the same run.
- Missing HSTS on a plain **HTTP** response is `informational` (not ranked as a high-severity key finding).

### Subdomain findings
- `passive_recon` and `osint_harvester` share a unified `Subdomains discovered (N)` finding fingerprint per asset (normalized hostname set), avoiding duplicate rows for the same hosts.

### `generate_report`
- Full report markdown is written to `~/.homepentest/evidence/reports/{run_id}.md`.
- Trace events store a short executive `summary` plus `report_path` (not truncated full markdown).
- Executive summaries use ASCII punctuation (hyphen separators) for Windows-safe trace storage.
- The **Scanned Assets** table has four columns: target, IP addresses, tech stack, and open ports (from DNS, Wappalyzer, and nmap inventory findings).
- Informational findings (`verification_state: informational`) appear under **Scan Coverage**, not Detailed Findings or risk score.

### Adapter transient retries
- All `BaseAdapter` subclasses retry up to `retries` times (default **3**) on transient DNS/connect/timeout errors.
- Configure globally via `adapter_retries` or per-adapter under `adapters.<name>.retries` in `config.yaml`.
- Failed attempts are logged; final failures may be marked `retryable` in tool trace metadata when the error is transient.

### Finding observations
- At most **one** `finding_observations` row per `(finding_id, run_id)`; re-saves update the row and merge `Sources:` labels when subdomain tools agree.

### `dns_lookup`
- Benign empty record types (`No answer for record type`, `Domain does not exist`) do **not** create findings.
- Genuine resolver failures (timeouts, etc.) emit informational `DNS <type> query issue` findings.

### `asset_manager`
- `add` is idempotent: re-registering an existing `value` returns `success` with `action: exists` and the existing `asset_id` (no spurious error trace).

### `gobuster`
- Bare wordlist filenames (e.g. `common.txt`) and config-relative paths (`bin/wordlists/common.txt`) resolve to the bundled wordlist under `bin/wordlists/`.
- Omit `wordlist` in tool params to use the bundled default automatically.

### `nmap`
- Emits an informational `Open ports discovered (N)` finding listing all open ports (not only high-risk services).
- Port inventory feeds the report **Scanned Assets** open-ports column when present.
