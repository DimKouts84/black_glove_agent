# Pentest Report

**Date:** 2026-02-11
**Target:** example.com

## Executive Summary

Security assessment conducted on 2 assets. Found 4 issues.

### Key Findings

- **Open SQL Injection Vulnerability** (CRITICAL)

- **Outdated SSL Certificate** (HIGH)


### Risk Score: 2.0/10

### Recommendations

- Remediate critical vulnerabilities immediately.

- Review high severity findings within 48 hours.


---

## Scanned Assets

| Target | IP Addresses | Tech Stack |
| :--- | :--- | :--- |

| example.com | 192.168.1.10 |  |

| api.example.com | 192.168.1.11 |  |


---

## Detailed Findings


### Open SQL Injection Vulnerability

- **Severity:** CRITICAL
- **Affected Assets:** api.example.com

**Description**
SQL injection vulnerability detected in /api/login parameter 'username'. This allows an attacker to manipulate SQL queries.


**Remediation**
Use parameterized queries or prepared statements.



**Evidence**

- `evidence/sqli_poc.txt`



---

### Outdated SSL Certificate

- **Severity:** HIGH
- **Affected Assets:** example.com

**Description**
The SSL certificate for example.com expired on 2025-01-01.


**Remediation**
Renew the SSL certificate.



**Evidence**

- `evidence/ssl_cert.txt`



---

### Open Port 21 (FTP)

- **Severity:** MEDIUM
- **Affected Assets:** example.com

**Description**
FTP service is running on port 21. FTP transmits credentials in cleartext.


**Remediation**
Disable FTP and use SFTP/SCP instead.




---

### Server Header Disclosure

- **Severity:** INFO
- **Affected Assets:** example.com

**Description**
Server header reveals 'nginx/1.18.0'.


**Remediation**
Configure server to suppress version information.




---
