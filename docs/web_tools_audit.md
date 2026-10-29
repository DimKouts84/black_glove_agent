# Web Application Intelligence — Tool Audit Matrix

Audit baseline for the Web Application Intelligence adapter group (2026-07-09).

| Tool | Canonical param | Also accepts | Output keys | Severity source | FP vectors | Test gaps (pre-fix) |
|------|-----------------|--------------|-------------|-----------------|------------|---------------------|
| `web_vuln_scanner` | `target_url` | `target`, `url` | `vulnerabilities[]`, `scanned_params` | per-finding `severity` | XSS reflection without context; LFI marker in static pages; SSTI via bare `49`; header noise | No negative cases; no `interpret_result` tests |
| `sqli_scanner` | `target_url` | `target`, `url` | `vulnerabilities[]`, `scanned_params` | per-finding `severity` (added) | SQL-like WAF text; length-only boolean; single-sample time blind | No baseline-error rejection tests |
| `web_server_scanner` | `target_url` | `target`, `url` | `findings[]`, `summary` | per-finding `severity` | HTTP 200 soft-404; 403 as "exists"; OK headers in risk counts | No content-signature tests; `target_url` param broken |
| `gobuster` | `url` (dir) / `domain` (dns) | `target_url`, `target` | `entries[]` | per-entry severity + dir normalizer | 301/403 without context | Normalizer read `paths[]` not `entries[]` |
| `wappalyzer` | `url` | `target_url`, `target` | `technologies[]` | confidence threshold | Low-confidence CDN fingerprints | Generic normalizer only |
| `sublist3r` | `domain` | `target` | `subdomains[]` | pattern-based (dev/staging) | Unvalidated third-party subs | No import guard; `max_results` ignored |

## Reporting pipeline (pre-fix)

- `FindingsNormalizer` used generic branch → one MEDIUM finding per scan.
- `interpretation` injected after normalization in `AdapterToolWrapper`.
- Executor truncated all tool output at 2000 chars.

## Post-fix expectations (custom scanners — done)

- Unified `target_url` (with aliases) for all web scanners.
- Hardened heuristics with baseline comparison and content signatures.
- Per-issue findings in DB via `_normalize_web_scan_output`.
- Agent prompts treat INTERPRETATION as primary summary, not infallible ground truth.

## Post-fix expectations (wrappers — network/web intel pass)

- Gobuster: `_extract_found_paths` reads `entries[].path` / `entries[].host`; per-entry severity in adapter output.
- Wappalyzer / Sublist3r: `_normalize_web_intel_wrapper_output` with confidence gating and parent-zone validation.
- Unified params via `plugin_manager` and `url_params` / `domain_params` helpers.
- Evidence files use real newlines; sublist3r import failure returns clean ERROR.

## Post-fix status (verified 2026-07-09)

| Tool | Status | Notes |
|------|--------|-------|
| `web_vuln_scanner` | Done | Returns `not_applicable` when URL has no query parameters; coverage metrics prevent false "clean scan" findings |
| `sqli_scanner` | Done | Returns `not_applicable` when URL has no query parameters; coverage metrics prevent false "clean scan" findings |
| `web_server_scanner` | Done | Header findings include response URL/status evidence; HSTS fingerprint vs direct header conflicts surfaced as warnings |
| `gobuster` | Done | `entries[]` normalizer; post-parse `status_codes` filter |
| `wappalyzer` | Done | Wrapper normalizer + confidence gating |
| `sublist3r` | Done | Config `threads` via `PluginManager`; import guard |

## Live check (2026-10-29, https://dimkouts.dev)

- `web_vuln_scanner` and `sqli_scanner`: homepage has no query string. Envelope status `not_applicable`, `coverage.reason = no_query_parameters`, zero vulnerabilities, zero findings. No payloads were sent.
- `web_server_scanner`: success. Header findings (missing CSP, HSTS, X-Frame-Options, and the low header notes) are saved. File probes did not confirm a real `/.env`. When a stored Wappalyzer HSTS row exists for the same asset, the missing-HSTS finding is `conflicted` and the interpretation appends "Reconciled observations".
- `gobuster` dir: success, 7 paths, with a soft-404 length excluded. Saved finding is informational "Paths discovered (7)" only. Non-sensitive HTTP 200/307 paths are not high findings.
- `wappalyzer`: success, technologies at confidence >= 50, including HSTS and Cloudflare. Each technology is a low "Technology detected" finding (deduped on repeat runs).
- `sublist3r`: success, `subdomains` empty. No finding is saved. An empty result is not "scan completed".
