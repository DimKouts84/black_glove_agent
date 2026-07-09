# Network & Infrastructure Reconnaissance — Tool Audit Matrix

Audit baseline for the Network & Infrastructure Reconnaissance adapter group.

| Tool | Canonical param | Also accepts | Output keys | Severity source | FP vectors | Test gaps (pre-fix) |
|------|-----------------|--------------|-------------|-----------------|------------|---------------------|
| `nmap` | `target` | `domain`, `host` | `hosts[]`, `summary` | port-scan normalizer | Multi-homed hosts truncated; filtered ports omitted | Normalizer schema mismatch (`hosts[].ports` vs `ports[]`) |
| `public_ip` | (none) | — | `ipv4`, `ipv6` | generic normalizer | api64 mislabeled IPv6 | No unit tests; DB persistence skipped (no target) |
| `dns_lookup` | `domain` | `target` | `records`, `errors` | generic normalizer | PTR on bare IP from orchestrator | No mocked DNS tests |
| `dns_recon` | `target` | `domain` | `zone_transfer`, `brute_force[]` | generic normalizer | Wildcard DNS brute false positives | `interpret_result` brute-force schema mismatch |
| `whois` | `domain` | `target` | `domain`, `registrar`, dates | generic normalizer | List/datetime field variance | `interpret_result` used `domain_name` key |
| `ssl_check` | `host` | `target`, `domain` | cert metadata | generic normalizer | CERT_NONE — metadata only, not trust | root.py documented `target` not `host` |
| `viewdns` | `host` | `target`, `domain` | `open_ports[]` | generic (not port-scan branch) | API errors silent | Evidence `\\n` bug; reverse-IP not implemented |

## Reporting pipeline (pre-fix)

- `nmap` routed to `_normalize_port_scan_output` but `_extract_open_ports` ignored `hosts[].ports[]`.
- `viewdns` fell through to generic branch despite open port data.
- `dns_lookup`, `dns_recon`, `whois`, `ssl_check`, `public_ip` used generic single MEDIUM finding.

## Post-fix expectations

- `_extract_open_ports` supports nmap `hosts[].ports[]`, viewdns `open_ports[]`, legacy `ports[]`.
- `viewdns` included in port-scan normalizer branch.
- `_normalize_network_infra_output` emits per-record/per-cert/per-IP findings with mapped severity.
- `plugin_manager._normalize_params` aliases `target`/`domain`/`host` per adapter contract.
- Fixed `whois` interpret header, `dns_recon` brute-force string summaries, `ssl_check` host aliases.
- Agent prompts treat SSL output as cert metadata (not trust validation); zone transfer as CRITICAL indicator.

## Post-fix status (verified 2026-07-09)

| Tool | Status | Notes |
|------|--------|-------|
| `nmap` | Done | `resolve_host` wired; bundled binary in `validate_config`; interpret summary fallback |
| `public_ip` | Done | IPv6 validation; `services_used` in data; session asset persistence via wrapper |
| `dns_lookup` | Done | Normalizer branch + mocked unit tests |
| `dns_recon` | Done | Prior refactor; brute-force interpret fixed |
| `whois` | Done | Normalizer branch; unused `timeout` param removed from docs |
| `ssl_check` | Done | Timezone-aware expiry; expired cert tests |
| `viewdns` | Done | PARTIAL on API errors with zero ports; evidence newlines fixed |
