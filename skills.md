# Agent Skills & Capabilities (AAIF Standard)

## Overview

In the Black Glove architecture, a **Skill** equates to a specific technical capability that an agent can execute. These skills are implemented as **Tool Adapters**, which are standardized wrappers around external CLI tools, APIs, or internal logic.

This modular "Skill" approach allows agents to "learn" new capabilities simply by registering a new Adapter, without requiring changes to the agent's core logic.

---

## Skill Abstraction (The Adapter Pattern)

All skills leverage the `AdapterInterface` to ensure uniform execution, error handling, and result reporting.

*   **Interface Definition**: [`src/adapters/interface.py`](../src/adapters/interface.py)
*   **Key Contract**:
    *   `execute(params)`: Runs the tool.
    *   `validate_params(params)`: Ensures inputs are safe and correct before execution.
    *   `get_info()`: Returns metadata about the skill's capabilities.
    *   **Result**: Always returns a standardized `AdapterResult` object containing `status`, `data`, and `metadata`.

### Governance Layer (All Adapter Calls)

Every adapter invocation passes through:

1. **`tool_risk.py`** — classifies tools (passive/active/credential/exploit) and enforces phase rules
2. **`audit.py`** — append-only `audit_log` entries for attempts, blocks, approvals, and results
3. **`work_graph_executor.py`** — deterministic multi-step execution for planner/recon workflows

Interactive chat uses the ReAct loop (`AgentExecutor`); adapter calls share exploit-gate and audit paths. Full scans can be executed via `AgentRuntime.execute_scan_plan()`. Users are responsible for legal authorization of targets.

---

## Skill Catalog

### 1. Network & Infrastructure Reconnaissance

| Skill Name | Description | Responsible File | Key Capabilities |
|------------|-------------|------------------|------------------|
| **nmap** | Network Discovery | `src/adapters/nmap.py` | Port scanning, service version detection, OS detection. |
| **public_ip** | Identity Verification | `src/adapters/public_ip.py` | Detects the agent's public-facing IP address to verify VPN/Proxy status. |
| **dns_lookup** | DNS Enumeration | `src/adapters/dns_lookup.py` | Retrieves A, AAAA, MX, NS, and TXT records for a domain. |
| **dns_recon** | Advanced DNS Recon | `src/adapters/dns_recon.py` | Zone transfers, subdomain brute-forcing, and thorough DNS discovery. |
| **whois** | Registration Info | `src/adapters/whois.py` | Queries registrar data to identify domain ownership details. |
| **ssl_check** | Certificate Analysis | `src/adapters/ssl_check.py` | Retrieves SSL/TLS certificate metadata (issuer, expiry, SANs). Trust chain is not validated (`CERT_NONE`). Optional `cryptography` for binary cert parsing. |
| **viewdns** | ViewDNS Port Scan | `src/adapters/viewdns.py` | Active port scanning via ViewDNS.info API (requires API key). |

**Network recon parameters:** `dns_lookup`/`whois`/`sublist3r` use `domain` (alias `target`). `dns_recon` uses `target` (alias `domain`). `ssl_check`/`viewdns` use `host` (aliases `target`, `domain`). `nmap` uses `target`. See [`docs/network_infra_audit.md`](docs/network_infra_audit.md).

### 2. Web Application Intelligence

| Skill Name | Description | Responsible File | Key Capabilities |
|------------|-------------|------------------|------------------|
| **gobuster** | Directory Bruteforce | `src/adapters/gobuster.py` | Discovers hidden directories and files (URIs) on a web server. |
| **wappalyzer** | Tech Stack Detection | `src/adapters/wappalyzer.py` | Identifies technologies used on a website (CMS, Frameworks, Analytics). |
| **sublist3r** | Subdomain Enum | `src/adapters/sublist3r.py` | Aggregates subdomains from many public sources (Google, Yahoo, Bing, etc.). |
| **web_server_scanner**| Server Analysis | `src/adapters/web_server_scanner.py` | Nikto-like checks for headers, dangerous files, methods, and versions. |
| **sqli_scanner** | SQLi Detection | `src/adapters/sqli_scanner.py` | Heuristic SQL injection detection (error, boolean, time). Not a sqlmap replacement. |
| **web_vuln_scanner**| Web Vulnerability | `src/adapters/web_vuln_scanner.py` | Active scanning for XSS, Path Traversal, and SSTI (query params only). |

**Web scanner parameters:** Custom scanners accept `target_url` (canonical) or `target`. Wrappers: `gobuster` (`url`/`target_url` for dir, `domain` for dns), `wappalyzer` (`url`/`target_url`), `sublist3r` (`domain`/`target`). See [`docs/web_tools_audit.md`](docs/web_tools_audit.md).

### 3. Specialized Intelligence

| Skill Name | Description | Responsible File | Key Capabilities |
|------------|-------------|------------------|------------------|
| **passive_recon** | Deep Passive Intel | `src/adapters/passive_recon.py` | **Enhanced Secret Scanning**: Automatically scans Wayback Machine snapshots for leaked API keys, `.env` files, and credentials. |
| **osint_harvester** | OSINT Discovery | `src/adapters/osint_harvester.py` | Email harvesting, crt.sh subdomains, and web metadata extraction. |
| **credential_tester**| Brute-force | `src/adapters/credential_tester.py` | Lab-safe credential testing for SSH, FTP, and HTTP Basic. |
| **camera_security**| IoT Exposure | `src/adapters/camera_security.py` | Checks for known vulnerabilities or exposures in IP cameras. |

**Specialized intelligence parameters:** See [docs/specialized_intel_audit.md](docs/specialized_intel_audit.md) for the audit matrix. Canonical inputs: passive_recon uses domain (alias 	arget); osint_harvester uses 	arget (alias domain); credential_tester uses 	arget (alias 	arget_url); camera_security uses 	arget. Domain resolution strips URLs via src/adapters/domain_params.py.

**Known limitations:**
- **passive_recon**: Domain names only (not raw IPs). potential_secrets are Wayback URL/pattern indicators; archived page content is not fetched or verified.
- **osint_harvester**: Email harvesting filters addresses that do not contain the target domain string.
- **credential_tester**: HTTP Basic runs only after a pre-check sees 401 with WWW-Authenticate: Basic; public pages are skipped. A credential counts as valid only when the authenticated response differs from the unauthenticated fingerprint.
- **camera_security**: Heuristic TCP/HTTP checks; string-tagged findings in output. Confirm exposures manually.

### 4. Operational Skills

| Skill Name | Description | Responsible File | Key Capabilities |
|------------|-------------|------------------|------------------|
| **asset_manager** | Target Management | `src/adapters/asset_manager.py` | CRUD for engagement scope: `add`, `list`, `remove` only. Uses shared SQLite DB via `init_db`. Assessment reports use the `generate_report` tool, not asset_manager. |
| **generate_report** | Report Generation | `src/agent/tools/report_tool.py` | DB-backed assessment reports (markdown/json/html/csv). |

**Session-level findings:** `public_ip` has no target parameter; `AdapterToolWrapper` persists findings against a session asset (`local-agent`). `services_used` is included in normalized finding descriptions.

**Per-adapter config:** `config.yaml` `adapters:` block is merged by `PluginManager._get_adapter_config` (e.g. `sublist3r.threads`, `nmap.timeout`). See [`docs/operational_audit.md`](docs/operational_audit.md).

---

## Integration Guide

To add a new skill to the Black Glove agent:
1.  Create a new adapter file in `src/adapters/`.
2.  Inherit from `AdapterInterface`.
3.  Implement `execute`, `validate_params`, and `get_info`.
4.  Register the tool in `src/agent/agent_library/root.py`.
