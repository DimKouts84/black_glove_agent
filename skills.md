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
| **ssl_check** | Certificate Analysis | `src/adapters/ssl_check.py` | Analyzes SSL/TLS certificates for validity, issuer, and expiration. |
| **viewdns** | Reverse Intelligence | `src/adapters/viewdns.py` | Performs Reverse IP lookups and port scanning via ViewDNS API. |

### 2. Web Application Intelligence

| Skill Name | Description | Responsible File | Key Capabilities |
|------------|-------------|------------------|------------------|
| **gobuster** | Directory Bruteforce | `src/adapters/gobuster.py` | Discovers hidden directories and files (URIs) on a web server. |
| **wappalyzer** | Tech Stack Detection | `src/adapters/wappalyzer.py` | Identifies technologies used on a website (CMS, Frameworks, Analytics). |
| **sublist3r** | Subdomain Enum | `src/adapters/sublist3r.py` | Aggregates subdomains from many public sources (Google, Yahoo, Bing, etc.). |
| **web_server_scanner**| Server Analysis | `src/adapters/web_server_scanner.py` | Nikto-like checks for headers, dangerous files, methods, and versions. |
| **sqli_scanner** | SQLi Detection | `src/adapters/sqli_scanner.py` | Detects SQL injection vulnerabilities using multiple techniques. |
| **web_vuln_scanner**| Web Vulnerability | `src/adapters/web_vuln_scanner.py` | Active scanning for XSS, Path Traversal, SSTI, and more. |

### 3. Specialized Intelligence

| Skill Name | Description | Responsible File | Key Capabilities |
|------------|-------------|------------------|------------------|
| **passive_recon** | Deep Passive Intel | `src/adapters/passive_recon.py` | **Enhanced Secret Scanning**: Automatically scans Wayback Machine snapshots for leaked API keys, `.env` files, and credentials. |
| **osint_harvester** | OSINT Discovery | `src/adapters/osint_harvester.py` | Email harvesting, crt.sh subdomains, and web metadata extraction. |
| **credential_tester**| Brute-force | `src/adapters/credential_tester.py` | Lab-safe credential testing for SSH, FTP, and HTTP Basic. |
| **camera_security**| IoT Exposure | `src/adapters/camera_security.py` | Checks for known vulnerabilities or exposures in IP cameras. |

### 4. Operational Skills

| Skill Name | Description | Responsible File | Key Capabilities |
|------------|-------------|------------------|------------------|
| **asset_manager** | Target Management | `src/adapters/asset_manager.py` | CRUD operations for managing the scope of engagement (adding/removing targets). |

---

## Integration Guide

To add a new skill to the Black Glove agent:
1.  Create a new adapter file in `src/adapters/`.
2.  Inherit from `AdapterInterface`.
3.  Implement `execute`, `validate_params`, and `get_info`.
4.  Register the tool in `src/agent/agent_library/root.py`.
