# Specialized Intelligence — Tool Audit Matrix

Audit baseline for the Specialized Intelligence adapter group.

| Tool | Canonical param | Also accepts | Output keys | Severity source | FP vectors | Test gaps (pre-fix) |
|------|-----------------|--------------|-------------|-----------------|------------|---------------------|
| `passive_recon` | `domain` | `target` | `crt_sh`, `wayback`, `potential_secrets[]` | per-secret `confidence` | URL-only secret patterns; `.json` in Wayback URLs | Broken `interpret_result` schema; PARTIAL ignored |
| `osint_harvester` | `target` | `domain` | `emails[]`, `subdomains[]`, `metadata` | generic normalizer | `domain in email` filter | No normalizer integration; PARTIAL wrapper gap |
| `credential_tester` | `target` | `target_url` | `valid_credentials[]` | should be CRITICAL | HTTP 200 public page = valid cred | `test_http_basic_success` inconsistent |
| `camera_security` | `target` | — | `findings[]` strings, `vulnerabilities_detected` | string tags | TCP open = camera; HTTP 200 = cred success | `interpret_result` expects dicts |

## Reporting pipeline (pre-fix)

- `FindingsNormalizer` generic branch → one MEDIUM finding per scan.
- `AdapterToolWrapper` SUCCESS-only → PARTIAL runs lose interpretation + DB.
- Analyst prompts auto-CRITICAL all `passive_recon` secrets.

## Post-fix expectations

- Fixed interpret_result for passive_recon and camera_security (string findings for cameras; secret list schema for passive recon).
- FindingsNormalizer._normalize_specialized_intel_output emits per-item findings (secrets, credentials, camera strings, OSINT emails/subdomains) with mapped severity; empty actionable output falls back to a single LOW completion finding.
- AdapterToolWrapper treats PARTIAL like SUCCESS for interpretation and evidence persistence.
- src/adapters/domain_params.resolve_domain unifies domain / 	arget for passive_recon and osint_harvester; plugin_manager registers the same aliases for agents.
- credential_tester HTTP Basic: pre-check requires 401 + WWW-Authenticate containing Basic; otherwise brute force is skipped with ttempts: 0 and a 
ote. Valid creds require status change and response fingerprint change vs unauthenticated 401.
- Executor truncates large passive_recon / osint_harvester payloads before agent context; Root/Researcher/Analyst prompts treat secrets as indicators until manually verified.
- Tests: `test_plugin_manager_specialized_intel_params`, `test_findings_normalizer_specialized_intel`, `test_passive_recon_interpret`, `test_camera_security_interpret`, `test_credential_tester_adapter` (HTTP Basic pre-check/skip).

## Post-fix status (verified 2026-07-09)

| Tool | Status | Notes |
|------|--------|-------|
| `passive_recon` | Done | interpret + normalizer + PARTIAL wrapper |
| `osint_harvester` | Done | Specialized normalizer branch |
| `credential_tester` | Done | HTTP Basic pre-check; CRITICAL cred findings |
| `camera_security` | Done | String finding interpret + normalizer |

## Live check (2026-10-29, dimkouts.dev)

- `passive_recon`: `partial`. crt.sh returned certificates and names. Wayback returned 0 snapshots with warning `wayback: no snapshots returned` and `coverage.wayback_ok: false`. Subdomain names fold into the shared "Subdomains discovered (N)" fingerprint. No secret indicators. Partial is not a clean pass.
- `osint_harvester`: success. Emails 0, subdomains 2 (`dimkouts.dev`, `www.dimkouts.dev`). Same subdomain fingerprint as passive recon. No email finding when the list is empty.
- `camera_security`: success. Raw `open_ports` lists 80, 443, 8080, 8443. The inventory sentence is not a finding. `vulnerabilities_detected` stayed false. No camera finding is saved.
- `credential_tester`: not pointed at the live site. Valid credentials remain a CRITICAL finding in the normalizer tests. HTTP Basic still requires a 401 challenge before any attempt.
