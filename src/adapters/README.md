# Black Glove Adapters

This directory contains the "adapters" that allow the Black Glove agent to interact with various security tools and APIs.

## Adapter Types

The adapters are categorized by their dependencies:

### 🐍 Pure Python / Library Based
These adapters rely on Python packages installed via `pip` (managed by `uv` or `requirements.txt`). They work out-of-the-box once the environment is set up.

| Adapter | Dependency | Description |
|---------|------------|-------------|
| **DNS Lookup** (`dns_lookup.py`) | `dnspython` | Performs DNS queries (A, AAAA, MX, NS, TXT). |
| **SSL Check** (`ssl_check.py`) | `ssl`, `socket`, optional `cryptography` | Retrieves certificate metadata (not trust validation). Param: `host` (alias `target`). |
| **Whois** (`whois.py`) | `python-whois` | Retrieves domain registration information. |
| **Sublist3r** (`sublist3r.py`) | `sublist3r-lib` | Enumerates subdomains using OSINT. |
| **Wappalyzer** (`wappalyzer.py`) | `python-wappalyzer` | Identifies technologies used on websites. |
| **Public IP** (`public_ip.py`) | Standard Lib | Detects the agent's external IP address. |
| **Passive Recon** (`passive_recon.py`) | Standard Lib | Queries `crt.sh` and Wayback Machine for historical data. |
| **ViewDNS** (`viewdns.py`) | `requests`, API key | ViewDNS.info port scan API only. Param: `host` (alias `target`). |
| **Camera Security** (`camera_security.py`) | `requests` | Searches for exposed camera interfaces (OSINT). |
| **OSINT Harvester** (`osint_harvester.py`) | `beautifulsoup4` | Email & subdomain harvesting, metadata analysis. |
| **DNS Recon** (`dns_recon.py`) | `dnspython` | Zone transfer, subdomain brute-force, DNS resolution. |
| **Web Server Scanner** (`web_server_scanner.py`) | `requests` | Security headers, default files (content-validated), methods, version check. |
| **Web Vuln Scanner** (`web_vuln_scanner.py`) | `requests` | Active scanning for XSS, Path Traversal, SSTI (query params). |
| **SQLi Scanner** (`sqli_scanner.py`) | `requests` | Heuristic SQLi detection (error, boolean, time). Lightweight — not sqlmap. |
| **Credential Tester** (`credential_tester.py`) | `paramiko` | SSH, FTP, HTTP Basic brute-force (lab safe). |

### 📦 External Binary Required
These adapters require an external executable to be present on the system or in the project's `bin/` directory.

| Adapter | Binary Required | Installation Note |
|---------|-----------------|-------------------|
| Nmap (`nmap.py`) | `nmap` | **Auto-managed on Windows.** See note below. |
| Gobuster (`gobuster.py`) | `gobuster` | Must be installed manually (e.g., `choco install gobuster` or `apt install gobuster`). |

---

## 🚀 Nmap Setup (Windows)

The **Nmap Adapter** has a special setup process to ensure it works without requiring a system-wide installation.

1.  **Automatic Installation**: When you run `agent init` (or `python -m src.agent.cli init`), the system checks for Nmap.
2.  **Portable Binary**: If Nmap is not found, the agent automatically downloads a portable version of Nmap.
3.  **Location**: The binary is placed in `<project_root>/bin/nmap/nmap.exe`.
4.  **Usage**: The adapter is configured to look in this local `bin/` folder first.

**Note on Capabilities:**
Without the Npcap driver installed on the host Windows system, Nmap runs in **unprivileged mode**.
*   ✅ **Works**: TCP Connect Scans (`-sT`), Service Version Detection (`-sV`).
*   ❌ **Limited**: OS Detection (`-O`) and SYN Scans (`-sS`) require the Npcap driver.

## Adding New Adapters

To add a new tool:
1.  Create a new file in `src/adapters/`.
2.  Inherit from `BaseAdapter`.
3.  Implement `get_info()` (defining parameters) and `_execute_impl()`.
4.  If it requires a binary, add a check in `get_info()` to warn if it's missing.


### DNS Recon

Advanced DNS reconnaissance including zone transfers and subdomain brute-forcing.

```python
result = adapter.execute({
    "target": "example.com",
    "mode": "all" # Options: zone_transfer, brute_force, all
})
```

### Web Server Scanner

Nikto-like checks for headers, dangerous files, and server versions. Uses content
signatures and soft-404 baselines to reduce false positives.

**Parameter:** `target_url` (alias: `target`)

```python
result = adapter.execute({
    "target_url": "http://192.168.1.1",
    "checks": ["headers", "files", "methods", "versions"]  # Optional
})
```

**Limitations:** File probes require content validation; informational paths
(e.g. `robots.txt`) are excluded from file checks. HTTP 403 alone is not reported
as a confirmed finding.

### SQL Injection Scanner

Heuristic SQL injection detection. Severity varies by technique (error > time > boolean).

**Parameter:** `target_url` (alias: `target`)

```python
result = adapter.execute({
    "target_url": "http://example.com/page.php?id=1",
    "techniques": ["error", "boolean", "time"],  # Optional: default is all
    "params_to_test": ["id"]                     # Optional: strict filtering
})
```

**Limitations:** Not a replacement for sqlmap. Error-based checks ignore patterns
already present in the baseline response. Time-blind requires a confirmatory delay.

### Web Vulnerability Scanner

Lightweight active scanning for XSS, Path Traversal, and SSTI on URL query parameters.
Use `web_server_scanner` for security header analysis.

**Parameter:** `target_url` (alias: `target`)

```python
result = adapter.execute({
    "target_url": "http://testphp.vulnweb.com/listproducts.php?cat=1",
    "scans": ["xss", "lfi", "ssti"]  # Optional
})
```

**Limitations:** Query-string parameters only. SSTI requires two independent expression
evaluations. XSS/LFI use baseline comparison to reduce false positives.

See also: [`docs/web_tools_audit.md`](../../docs/web_tools_audit.md)

### Specialized Intelligence

Shared domain resolution lives in `domain_params.py` (`domain` / `target` aliases, URL stripping). Reporting uses `FindingsNormalizer._normalize_specialized_intel_output` in `src/agent/reporting.py`. See [`docs/specialized_intel_audit.md`](../../docs/specialized_intel_audit.md).

#### Passive Recon (`passive_recon.py`)

Certificate transparency (crt.sh) and Wayback Machine URL discovery with pattern-based secret indicators.

**Parameter:** `domain` (alias: `target`)

```python
result = adapter.execute({
    "domain": "example.com",
    "max_results": 100,  # optional
})
```

**Limitations:** Domains only (not IPs). `potential_secrets` are indicators from archived URLs; content is not downloaded or verified.

#### OSINT Harvester (`osint_harvester.py`)

Email, subdomain (crt.sh), and metadata harvesting.

**Parameter:** `target` (alias: `domain`)

```python
result = adapter.execute({
    "target": "example.com",
    "modules": ["emails", "subdomains", "metadata"],  # optional
})
```

**Limitations:** Email results are filtered to addresses containing the target domain string.

#### Camera Security (`camera_security.py`)

Heuristic checks for exposed IP camera services (RTSP/HTTP).

**Parameter:** `target` (hostname or IP)

```python
result = adapter.execute({"target": "192.168.1.100"})
```

**Limitations:** TCP/HTTP heuristics only; `findings` are human-readable strings with embedded severity tags.

### Credential Tester

Lab-safe brute-force testing for SSH, FTP, and HTTP Basic Auth. Requires `paramiko` for SSH.

**Parameter:** `target` (alias: `target_url`)

```python
result = adapter.execute({
    "target": "192.168.1.5",
    "protocol": "ssh",  # ssh | ftp | http_basic
    "usernames": ["root", "admin"],
    "passwords": ["toor", "admin123", "password"],
    "max_attempts": 10,
})
```

**Limitations:** HTTP Basic is skipped unless the target returns `401` with `WWW-Authenticate: Basic` on an unauthenticated GET. Valid HTTP credentials require a different response fingerprint than the unauthenticated challenge.

### Network & Infrastructure Reconnaissance

Shared helpers: `domain_params.resolve_domain`, `domain_params.resolve_host`. Reporting uses `_normalize_network_infra_output` and port-scan branch for `nmap`/`viewdns`. See [`docs/network_infra_audit.md`](../../docs/network_infra_audit.md).

| Adapter | Canonical param | Aliases |
|---------|-----------------|---------|
| `dns_lookup`, `whois`, `sublist3r` | `domain` | `target` |
| `dns_recon` | `target` | `domain` |
| `ssl_check`, `viewdns` | `host` | `target`, `domain` |
| `nmap` | `target` | `domain`, `host` |
| `gobuster` dir / dns | `url` / `domain` | `target_url`, `target` |
| `wappalyzer` | `url` | `target_url`, `target` |

### Operational: asset_manager

CRUD for engagement scope (`add`, `list`, `remove`). Uses shared SQLite DB (`init_db` + `DB_PATH`). Does **not** generate assessment reports — use the `generate_report` agent tool instead. See [`docs/operational_audit.md`](../../docs/operational_audit.md).

### Per-adapter configuration

`config.yaml` `adapters:` block is passed to adapters via `PluginManager._get_adapter_config`:

```yaml
adapters:
  sublist3r:
    threads: 20
  nmap:
    timeout: 300
```
