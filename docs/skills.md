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
- crt.sh subdomain data is normalized into findings; generic `scan completed` rows are never emitted for `passive_recon` (empty partial runs surface warnings in trace only).
- Shared retry logic lives in `crt_sh_client` (not discovered as an adapter).

## Adapter notes (user-visible)

### `whois`
- RDAP-first for Google Registry TLDs (`.dev`, `.app`, etc.) via IANA DNS bootstrap with Google Registry fallback.
- Legacy python-whois is a fallback for other TLDs.
- Empty registrar/dates → `partial` with warnings, never a successful registration finding.

### `web_vuln_scanner` / `sqli_scanner`
- URLs without query parameters → envelope status `not_applicable` with `coverage.scanned_params = 0`, `coverage.untested = true`, and `coverage.reason = no_query_parameters`.
- That result does not create a finding. A parameterless URL is not reported as "no vulnerabilities found".

### `web_server_scanner`
- Missing security headers include request URL and HTTP status in evidence.
- HSTS detected by Wappalyzer but absent in the direct header check is stored as `verification_state: conflicted` and severity INFO.
- The tool interpretation then appends `Reconciled observations (not confirmed findings)` for those titles, so the chat summary does not leave the header as a confirmed high finding.
- Missing HSTS on a plain **HTTP** response is `informational` (not ranked as a high-severity key finding).
- Connection failures (`ERROR` severity, "Connection failed") are **not** persisted as HIGH findings; they are skipped (coverage only).

### `camera_security`
- Benign negative results (e.g. "No common camera ports are open") do **not** create findings.
- An open-port inventory line is not a finding. Ordinary web ports (80, 443, 8080, 8443) stay in the raw `open_ports` list only.
- A finding is saved only when the text contains `VULNERABILITY`, `RISK`, `CRITICAL`, or `WEAK`.

### `nmap`
- Port **53/DNS** is not flagged as a high-risk service; open DNS still appears in the informational `Open ports discovered` note.
- Emits an informational `Open ports discovered (N)` finding listing all open ports (not only high-risk services).
- Port inventory feeds the report **Scanned Assets** open-ports column when present.

### `public_ip`
- Public IP detection is inventory (`verification_state: informational`); excluded from detailed findings and risk score.

### Web/SSL tool gating (agent behavior)
- Root and Planner agents should schedule `web_server_scanner`, `ssl_check`, `wappalyzer`, `web_vuln_scanner`, and `sqli_scanner` only when nmap shows HTTP/HTTPS ports (80, 443, 8080, 8443) open.

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

### `dns_recon`
- `mode: zone_transfer` attempts AXFR and records each nameserver as `success` or `denied`. A refusal is an informational `DNS zone transfer denied (N)` finding, not a generic "scan completed" row.
- A successful AXFR stays CRITICAL.
- Brute-force text is included only when that mode actually ran. `zone_transfer` mode does not claim that brute force found nothing.

### `asset_manager`
- `add` is idempotent: re-registering an existing `value` returns `success` with `action: exists` and the existing `asset_id` (no spurious error trace).
- The human-readable message stays in `value`. `action` and `asset_id` from adapter metadata are copied onto the tool result so the agent can see them.

### `gobuster`
- Bare wordlist filenames (e.g. `common.txt`) and config-relative paths (`bin/wordlists/common.txt`) resolve to the bundled wordlist under `bin/wordlists/`.
- Omit `wordlist` in tool params to use the bundled default automatically.
- SPA catch-all HTTP 200 responses (soft-404): pre-probes a random path, retries with `--exclude-length`, and returns `partial` (not hard `error`) when enumeration cannot proceed after exclusion.
- Every remaining path is listed in one informational `Paths discovered (N)` finding. Only sensitive paths (admin, login, `.env`, `.git`, backups, and similar) also get their own severity finding. A normal page with HTTP 200 is not stored as a high vulnerability.

### Subdomain findings
