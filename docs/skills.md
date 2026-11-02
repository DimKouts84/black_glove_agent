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
- URLs without query parameters, and a `params_to_test` filter that matches none of those parameters, → envelope status `not_applicable` with `coverage.scanned_params = 0`, `coverage.untested = true`, and `coverage.reason = no_query_parameters`.
- That result does not create a finding. A parameterless URL is not reported as "no vulnerabilities found".
- `web_vuln_scanner` decides this from the URL before opening a connection.
- A target URL is stored on the host asset (`https://zebeh.com/?s=test` → `zebeh.com`). Evidence directories replace characters that Windows rejects in file names (`?`, `:`, and similar), so a query string cannot fail finding normalization.

### `web_server_scanner`
- A PUT response that matches the GET catch-all for the same path (same status and nearly the same body length) is not stored as "PUT method accepted". Status 201 or 204 still is.
- Missing security headers include the final response URL and HTTP status in evidence.
- HSTS is classified from the final response URL. Missing HSTS on a final **HTTP** response is `informational`. Missing HSTS on a final **HTTPS** response stays a normal finding and does not say the response was HTTP.
- HSTS detected by Wappalyzer but absent in the direct header check is stored as `verification_state: conflicted` and severity INFO.
- The reconciled sentence is placed at the start of the tool summary, including when the later tool is the one that detects the conflict.
- Connection failures are untested coverage (`coverage.untested` / `reason: connection_failed`). They are not saved as findings and they are not a completed "no issues" scan.

### `camera_security`
- The spoken summary calls 80/443/8080/8443 ordinary web ports, not camera-specific ports. An inventory line is added only for other open ports.
- Benign negative results (e.g. "No common camera ports are open") do **not** create findings.
- An open-port inventory line is not a finding. Ordinary web ports (80, 443, 8080, 8443) stay in the raw `open_ports` list only.
- A finding is saved only when the text contains `VULNERABILITY`, `RISK`, `CRITICAL`, or `WEAK`.
- A hostname that does not resolve is status `error`, not a clean "no ports" result.
- Ports 443 and 8443 are probed over TLS. Vendor names are matched on the `Server` header and page title. The word `video` alone is not a camera finding.

### `nmap`
- `extra_flags` accepts a flag value as the next list item (`--version-intensity`, `5`) or as `--version-intensity=5`. Characters outside letters, digits, and `_.-,:+` are rejected.
- Port **53/DNS** is not flagged as a high-risk service; open DNS still appears in the informational `Open ports discovered` note.
- Emits an informational `Open ports discovered (N)` finding listing all open ports (not only high-risk services).
- Port inventory feeds the report **Scanned Assets** open-ports column when present.

### `public_ip`
- Public IP detection is inventory (`verification_state: informational`); excluded from detailed findings and risk score.
- The finding is always stored on the session asset `local-agent`, even when the scan step passes another target. The adapter reports the agent machine's address.

### Web/SSL tool gating (agent behavior)
- Interactive chat: `gobuster`, `wappalyzer`, `web_server_scanner`, `web_vuln_scanner`, and `sqli_scanner` refuse to run until this session has nmap evidence of an open port 80, 443, 8080, or 8443. The check is in `src/agent/ai/tool_bridge.py`.
- Scripted plans: the planner still schedules `web_server_scanner`, `ssl_check`, `wappalyzer`, and the vuln scanners only after nmap, and `validate_scan_plan` auto-wires those steps onto `nmap`.

### Subdomain findings
- `passive_recon` and `osint_harvester` share a unified `Subdomains discovered (N)` finding fingerprint per asset (normalized hostname set), avoiding duplicate rows for the same hosts.

### `generate_report`
- Full report markdown is written to `~/.homepentest/evidence/reports/{run_id}.md`.
- `POST /api/reports` uses the latest `agent_runs` row and returns that run's full report body. It does not mix runs, and it does not return only the 1500-character preview. No runs returns 404. `GET /reports/{run_id}` still loads one named run.
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
- Genuine resolver failures (timeouts, etc.) are stored on `records[type].error` and emit informational `DNS <type> query issue` findings. If every queried type fails that way, the adapter status is `partial`.

### `dns_recon`
- `mode: zone_transfer` attempts AXFR and records each nameserver as `success`, `denied`, `timeout`, or `failed`. A refusal is an informational `DNS zone transfer denied (N)` finding. A timeout or other error is `DNS zone transfer failed`, not a refusal and not a generic "scan completed" row.
- A successful AXFR stays CRITICAL.
- Brute-force text is included only when the wordlist was opened and that mode ran. A missing wordlist is an error, not "found no subdomains".

### `credential_tester`
- A transport or handshake failure is status `error` with a connection message. It is not `success` with an empty credential list.
- A completed login exchange that rejects the password stays a successful negative result.

### `ssl_check`
- `is_not_yet_valid` is high severity, same as an expired certificate, and the description says the certificate is not yet valid.
- A `host:port` target uses that port instead of the default 443.

### `asset_manager`
- Removing an asset also deletes its findings and finding observations, so a scanned asset can be removed from the Assets page.
- `add` is idempotent: re-registering an existing `value` returns `success` with `action: exists` and the existing `asset_id` (no spurious error trace).
- The human-readable message stays in `value`. `action` and `asset_id` from adapter metadata are copied onto the tool result so the agent can see them.

### `gobuster`
- `mode` is `dir` or `dns`. `vhost` is rejected.
- A directory scan that fails TLS certificate verification retries once with `-k` and records that certificate checks were skipped.
- Bare wordlist filenames that exist under `bin/wordlists/` (e.g. `common.txt`) and config-relative paths (`bin/wordlists/common.txt`) resolve to that file.
- A bare name that is not in `bin/wordlists/` is an error. It is not replaced with `common.txt`.
- Omit `wordlist` in tool params to use the bundled default automatically.
- Sensitive paths match on a path boundary (`/.git` does not match `/.github`).
- SPA catch-all HTTP 200 responses (soft-404): pre-probes a random path, retries with `--exclude-length`, and returns `partial` (not hard `error`) when enumeration cannot proceed after exclusion.
- Every remaining path is listed in one informational `Paths discovered (N)` finding. Only sensitive paths (admin, login, `.env`, `.git`, backups, and similar) also get their own severity finding. A normal page with HTTP 200 is not stored as a high vulnerability.

### Subdomain findings
