# Black Glove Adapters

This directory contains the "adapters" that allow the Black Glove agent to interact with various security tools and APIs.

## Adapter Types

The adapters are categorized by their dependencies:

### 🐍 Pure Python / Library Based
These adapters rely on Python packages installed via `pip` (managed by `uv` or `requirements.txt`). They work out-of-the-box once the environment is set up.

| Adapter | Dependency | Description |
|---------|------------|-------------|
| **DNS Lookup** (`dns_lookup.py`) | `dnspython` | Performs DNS queries (A, AAAA, MX, NS, TXT). |
| **SSL Check** (`ssl_check.py`) | `sslyze` | Analyzes SSL/TLS configuration and certificates. |
| **Whois** (`whois.py`) | `python-whois` | Retrieves domain registration information. |
| **Sublist3r** (`sublist3r.py`) | `sublist3r-lib` | Enumerates subdomains using OSINT. |
| **Wappalyzer** (`wappalyzer.py`) | `python-wappalyzer` | Identifies technologies used on websites. |
| **Public IP** (`public_ip.py`) | Standard Lib | Detects the agent's external IP address. |
| **Passive Recon** (`passive_recon.py`) | Standard Lib | Queries `crt.sh` and Wayback Machine for historical data. |
| **ViewDNS** (`viewdns.py`) | `requests` | Queries ViewDNS.info API for various tools. |
| **Camera Security** (`camera_security.py`) | `requests` | Searches for exposed camera interfaces (OSINT). |
| **OSINT Harvester** (`osint_harvester.py`) | `beautifulsoup4` | Email & subdomain harvesting, metadata analysis. |
| **DNS Recon** (`dns_recon.py`) | `dnspython` | Zone transfer, subdomain brute-force, DNS resolution. |
| **Web Server Scanner** (`web_server_scanner.py`) | `requests` | Security headers, default files, methods, version check. |
| **Web Vuln Scanner** (`web_vuln_scanner.py`) | `requests` | Active scanning for XSS, Path Traversal, SSTI, and headers. |
| **SQLi Scanner** (`sqli_scanner.py`) | `requests` | Detects SQL injection vulnerabilities. |
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


### OSINT Harvester

Passive OSINT gathering for emails, subdomains (via crt.sh), and web metadata.

```python
result = adapter.execute({
    "target": "example.com",
    "modules": ["emails", "subdomains", "metadata"] # Optional
})
```

### DNS Recon

Advanced DNS reconnaissance including zone transfers and subdomain brute-forcing.

```python
result = adapter.execute({
    "target": "example.com",
    "mode": "all" # Options: zone_transfer, brute_force, all
})
```

### Web Server Scanner

Nikto-like checks for headers, dangerous files, and server versions.

```python
result = adapter.execute({
    "target": "http://192.168.1.1",
    "checks": ["headers", "files", "methods", "versions"] # Optional
})
```

### SQL Injection Scanner

Detect SQL injection vulnerabilities using error-based, boolean-blind, and time-blind techniques.

```python
result = adapter.execute({
    "target_url": "http://example.com/page.php?id=1",
    "techniques": ["error", "boolean", "time"],  # Optional: default is all
    "params_to_test": ["id"]                     # Optional: strict filtering
})
```

### Web Vulnerability Scanner

Lightweight active scanning for XSS, Path Traversal, SSTI, and headers.

```python
result = adapter.execute({
    "target_url": "http://testphp.vulnweb.com/listproducts.php?cat=1",
    "scans": ["xss", "lfi", "ssti", "headers"] # Optional
})
```

### Credential Tester

Lab-safe brute-force testing for SSH, FTP, and HTTP Basic Auth. Requires `paramiko` for SSH.

```python
result = adapter.execute({
    "target": "192.168.1.5",
    "protocol": "ssh",
    "usernames": ["root", "admin"],
    "passwords": ["toor", "admin123", "password"],
    "max_attempts": 10 # Safety limit
})
```
