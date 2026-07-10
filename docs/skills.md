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
- `get_findings_from_database(run_id=...)` reads from observations so earlier runs stay reportable after later scans.
- `generate_report` defaults to the current run's findings when provenance context is set.

## Cross-tool conflict reconciliation

When Wappalyzer detects HSTS but `web_server_scanner` reports a missing `Strict-Transport-Security` header on the same asset:

- The missing-header finding is downgraded to `INFO` with `verification_state: conflicted`.
- Reports exclude conflicted items from risk score / key findings and list them under **Reconciled Observations**.

## External dependency degradation

### `passive_recon` / `osint_harvester` (crt.sh)
- Upstream crt.sh 502/503/timeout → `partial` (not hard `error`) with `warnings` and `coverage.crt_sh_ok: false`.
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
- HSTS detected by fingerprinting but absent in direct header checks is flagged as a cross-tool conflict note.
