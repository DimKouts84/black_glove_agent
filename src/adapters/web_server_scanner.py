"""
Web Server Scanner Adapter for Black Glove Pentest Agent

Nikto-like pure-Python scanner that checks for:
- Missing security headers (X-Frame-Options, CSP, HSTS, etc.)
- Default / dangerous files & paths (phpinfo, .env, .git, admin panels)
- Dangerous HTTP methods enabled (PUT, DELETE, TRACE)
- Server version disclosure via the Server header
"""

import logging
import time
import re
from typing import Any, Dict, List, Optional
from urllib.parse import urlparse, urljoin

import requests

from .base import BaseAdapter
from .interface import AdapterResult, AdapterResultStatus

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Security headers to check (header_name, description, severity)
# ---------------------------------------------------------------------------
SECURITY_HEADERS = [
    ("X-Frame-Options", "Prevents clickjacking by disabling framing", "MEDIUM"),
    ("Content-Security-Policy", "Mitigates XSS and data injection attacks", "HIGH"),
    ("Strict-Transport-Security", "Enforces HTTPS connections (HSTS)", "HIGH"),
    ("X-Content-Type-Options", "Prevents MIME-type sniffing", "LOW"),
    ("Permissions-Policy", "Controls browser feature permissions", "LOW"),
    ("Referrer-Policy", "Controls referrer information leakage", "LOW"),
    ("X-XSS-Protection", "Legacy XSS filter (defense-in-depth)", "INFO"),
]

# ---------------------------------------------------------------------------
# Default / dangerous paths to probe
# ---------------------------------------------------------------------------
DANGEROUS_PATHS = [
    # Server info
    ("/phpinfo.php", "PHP configuration disclosure", "HIGH"),
    ("/server-status", "Apache server status page", "HIGH"),
    ("/server-info", "Apache server info page", "HIGH"),
    ("/nginx_status", "Nginx status page", "HIGH"),
    # Admin panels
    ("/admin/", "Admin panel", "MEDIUM"),
    ("/administrator/", "Administrator panel", "MEDIUM"),
    ("/wp-admin/", "WordPress admin panel", "MEDIUM"),
    ("/wp-login.php", "WordPress login page", "MEDIUM"),
    ("/phpmyadmin/", "phpMyAdmin database management", "HIGH"),
    ("/adminer.php", "Adminer database tool", "HIGH"),
    # Configuration / secrets
    ("/.env", "Environment configuration file (may contain secrets)", "CRITICAL"),
    ("/.git/HEAD", "Git repository metadata exposed", "CRITICAL"),
    ("/.git/config", "Git config file (may reveal remote URLs)", "CRITICAL"),
    ("/.svn/entries", "SVN repository metadata exposed", "HIGH"),
    ("/.htaccess", "Apache .htaccess file", "MEDIUM"),
    ("/.htpasswd", "Apache password file", "CRITICAL"),
    ("/web.config", "IIS/ASP.NET configuration file", "HIGH"),
    ("/wp-config.php", "WordPress configuration (may leak DB credentials)", "CRITICAL"),
    ("/config.php", "PHP configuration file", "HIGH"),
    ("/config.yml", "YAML configuration file", "MEDIUM"),
    ("/config.json", "JSON configuration file", "MEDIUM"),
    # Backup files
    ("/backup.sql", "SQL database backup", "CRITICAL"),
    ("/backup.zip", "Backup archive", "HIGH"),
    ("/backup.tar.gz", "Backup archive", "HIGH"),
    ("/database.sql", "Database dump", "CRITICAL"),
    ("/dump.sql", "Database dump", "CRITICAL"),
    ("/db.sql", "Database dump", "CRITICAL"),
    # Debug / development
    ("/debug/", "Debug page", "HIGH"),
    ("/test/", "Test directory", "LOW"),
    ("/test.php", "Test PHP file", "MEDIUM"),
    ("/info.php", "PHP info file", "HIGH"),
    ("/elmah.axd", ".NET error log", "HIGH"),
    ("/trace.axd", ".NET trace log", "HIGH"),
    # Common files with info
    ("/robots.txt", "Robots exclusion file (may reveal hidden paths)", "INFO"),
    ("/sitemap.xml", "XML sitemap", "INFO"),
    ("/crossdomain.xml", "Flash cross-domain policy", "LOW"),
    ("/clientaccesspolicy.xml", "Silverlight cross-domain policy", "LOW"),
    ("/humans.txt", "Humans.txt (team/tech info)", "INFO"),
    ("/security.txt", "Security contact info", "INFO"),
    ("/.well-known/security.txt", "Security contact info (standard path)", "INFO"),
    # Package manager / dependency files
    ("/package.json", "Node.js package manifest", "MEDIUM"),
    ("/composer.json", "PHP Composer manifest", "MEDIUM"),
    ("/Gemfile", "Ruby Bundler manifest", "MEDIUM"),
    ("/requirements.txt", "Python requirements file", "MEDIUM"),
    # Miscellaneous
    ("/.DS_Store", "macOS directory metadata", "LOW"),
    ("/Thumbs.db", "Windows thumbnail cache", "LOW"),
    ("/error_log", "Error log file", "MEDIUM"),
    ("/access_log", "Access log file", "MEDIUM"),
    ("/cgi-bin/", "CGI scripts directory", "MEDIUM"),
]

# ---------------------------------------------------------------------------
# HTTP methods to test
# ---------------------------------------------------------------------------
DANGEROUS_METHODS = ["PUT", "DELETE", "TRACE", "CONNECT"]
INFORMATIONAL_METHODS = ["OPTIONS"]

# ---------------------------------------------------------------------------
# Server version patterns
# ---------------------------------------------------------------------------
VERSION_PATTERN = re.compile(
    r"(?:Apache|nginx|Microsoft-IIS|LiteSpeed|Caddy|Tomcat|Jetty|lighttpd)"
    r"[/ ]*(\d+[\.\d]*\S*)",
    re.IGNORECASE,
)


class WebServerScannerAdapter(BaseAdapter):
    """
    Nikto-like web server scanner.

    Performs passive and semi-active checks against a target web server
    to identify misconfigurations, missing security headers, exposed
    default files, dangerous HTTP methods, and server version disclosure.
    """

    def __init__(self, config: Dict[str, Any] = None):
        super().__init__(config or {})
        self.name = "WebServerScannerAdapter"
        self.version = "1.0.0"
        self.description = (
            "Nikto-like web server checks: security headers, default files, "
            "HTTP methods, server version disclosure"
        )
        # Config tunables
        self._timeout: float = self.config.get("timeout", 10.0)
        self._user_agent: str = self.config.get(
            "user_agent",
            "Mozilla/5.0 (compatible; BlackGloveScanner/1.0; +https://github.com/black-glove)",
        )
        self._max_workers: int = self.config.get("max_workers", 5)
        self._follow_redirects: bool = self.config.get("follow_redirects", True)

    # -- validation ---------------------------------------------------------

    def validate_params(self, params: Dict[str, Any]) -> None:
        if "target" not in params or not params["target"]:
            raise ValueError("Target URL or hostname is required")

        checks = params.get("checks", ["headers", "files", "methods", "versions"])
        valid_checks = {"headers", "files", "methods", "versions"}
        invalid = set(checks) - valid_checks
        if invalid:
            raise ValueError(
                f"Invalid check(s): {invalid}. Valid: {valid_checks}"
            )

    # -- helpers ------------------------------------------------------------

    def _normalise_target(self, target: str) -> str:
        """Ensure target has a scheme and return a clean base URL."""
        if not target.startswith(("http://", "https://")):
            target = f"http://{target}"
        parsed = urlparse(target)
        # Strip trailing path — we build paths ourselves
        return f"{parsed.scheme}://{parsed.netloc}"

    def _request(
        self,
        method: str,
        url: str,
        *,
        allow_redirects: bool = True,
        timeout: Optional[float] = None,
    ) -> Optional[requests.Response]:
        """Fire an HTTP request; return None on connection failure."""
        try:
            resp = requests.request(
                method,
                url,
                headers={"User-Agent": self._user_agent},
                timeout=timeout or self._timeout,
                allow_redirects=allow_redirects,
                verify=False,  # pentest — accept self-signed certs
            )
            return resp
        except requests.RequestException as exc:
            logger.debug(f"{method} {url} failed: {exc}")
            return None

    # -- check modules ------------------------------------------------------

    def _check_security_headers(self, base_url: str) -> List[Dict[str, Any]]:
        """Check for missing security headers on the root page."""
        findings: List[Dict[str, Any]] = []
        resp = self._request("GET", base_url)
        if resp is None:
            findings.append({
                "check": "headers",
                "title": "Connection failed",
                "detail": f"Could not connect to {base_url}",
                "severity": "ERROR",
            })
            return findings

        for header_name, description, severity in SECURITY_HEADERS:
            value = resp.headers.get(header_name)
            if value is None:
                findings.append({
                    "check": "headers",
                    "title": f"Missing {header_name}",
                    "detail": description,
                    "severity": severity,
                })
            else:
                # Report present headers at INFO level
                findings.append({
                    "check": "headers",
                    "title": f"{header_name} present",
                    "detail": f"Value: {value}",
                    "severity": "OK",
                })
        return findings

    def _check_default_files(self, base_url: str) -> List[Dict[str, Any]]:
        """Probe for default / dangerous files and paths."""
        findings: List[Dict[str, Any]] = []

        for path, description, severity in DANGEROUS_PATHS:
            url = urljoin(base_url + "/", path.lstrip("/"))
            resp = self._request("GET", url, allow_redirects=False)
            if resp is None:
                continue

            status = resp.status_code
            # Consider 200 and 403 interesting (403 = exists but forbidden)
            if status == 200:
                content_len = len(resp.content)
                findings.append({
                    "check": "files",
                    "title": f"Found: {path}",
                    "detail": f"{description} — HTTP {status}, {content_len} bytes",
                    "severity": severity,
                    "url": url,
                    "status_code": status,
                })
            elif status == 403:
                findings.append({
                    "check": "files",
                    "title": f"Forbidden (exists): {path}",
                    "detail": f"{description} — HTTP 403 (access denied but resource exists)",
                    "severity": "LOW",
                    "url": url,
                    "status_code": status,
                })
        return findings

    def _check_http_methods(self, base_url: str) -> List[Dict[str, Any]]:
        """Test for dangerous HTTP methods enabled on the server."""
        findings: List[Dict[str, Any]] = []

        # First try OPTIONS to see what the server advertises
        resp = self._request("OPTIONS", base_url)
        if resp is not None:
            allow_header = resp.headers.get("Allow", "")
            if allow_header:
                advertised = [m.strip().upper() for m in allow_header.split(",")]
                findings.append({
                    "check": "methods",
                    "title": "OPTIONS: Advertised methods",
                    "detail": f"Server advertises: {', '.join(advertised)}",
                    "severity": "INFO",
                })
                # Flag dangerous ones
                for method in DANGEROUS_METHODS:
                    if method in advertised:
                        findings.append({
                            "check": "methods",
                            "title": f"Dangerous method advertised: {method}",
                            "detail": f"Server Allow header includes {method}",
                            "severity": "HIGH" if method in ("PUT", "DELETE") else "MEDIUM",
                        })

        # Active test: TRACE (should be disabled)
        resp = self._request("TRACE", base_url)
        if resp is not None and resp.status_code == 200:
            findings.append({
                "check": "methods",
                "title": "TRACE method is enabled",
                "detail": "TRACE can be used in cross-site tracing (XST) attacks",
                "severity": "MEDIUM",
            })

        # Active test: PUT with small body (should fail on well-configured servers)
        try:
            resp = requests.request(
                "PUT",
                urljoin(base_url + "/", "black_glove_test_put.tmp"),
                headers={"User-Agent": self._user_agent},
                data="black_glove_test",
                timeout=self._timeout,
                verify=False,
            )
            if resp.status_code in (200, 201, 204):
                findings.append({
                    "check": "methods",
                    "title": "PUT method accepted",
                    "detail": f"PUT returned {resp.status_code} — may allow file upload",
                    "severity": "CRITICAL",
                })
        except requests.RequestException:
            pass  # connection failure, nothing to report

        return findings

    def _check_server_version(self, base_url: str) -> List[Dict[str, Any]]:
        """Check Server header for version disclosure."""
        findings: List[Dict[str, Any]] = []
        resp = self._request("HEAD", base_url)
        if resp is None:
            resp = self._request("GET", base_url)
        if resp is None:
            return findings

        server_header = resp.headers.get("Server", "")
        x_powered = resp.headers.get("X-Powered-By", "")

        if server_header:
            match = VERSION_PATTERN.search(server_header)
            if match:
                findings.append({
                    "check": "versions",
                    "title": "Server version disclosed",
                    "detail": f"Server header: {server_header}",
                    "severity": "MEDIUM",
                })
            elif server_header:
                findings.append({
                    "check": "versions",
                    "title": "Server header present (no version)",
                    "detail": f"Server: {server_header}",
                    "severity": "LOW",
                })

        if x_powered:
            findings.append({
                "check": "versions",
                "title": "X-Powered-By header disclosed",
                "detail": f"X-Powered-By: {x_powered}",
                "severity": "MEDIUM",
            })

        return findings

    # -- main execution -----------------------------------------------------

    def _execute_impl(self, params: Dict[str, Any]) -> AdapterResult:
        target = params["target"]
        checks = params.get("checks", ["headers", "files", "methods", "versions"])

        base_url = self._normalise_target(target)
        logger.info(f"Starting web server scan on {base_url}")

        all_findings: List[Dict[str, Any]] = []
        errors: List[str] = []

        # Run selected checks
        check_map = {
            "headers": self._check_security_headers,
            "files": self._check_default_files,
            "methods": self._check_http_methods,
            "versions": self._check_server_version,
        }

        for check_name in checks:
            try:
                logger.info(f"Running check: {check_name}")
                results = check_map[check_name](base_url)
                all_findings.extend(results)
            except Exception as exc:
                msg = f"Check '{check_name}' failed: {exc}"
                logger.error(msg)
                errors.append(msg)

        # Build severity summary
        severity_counts: Dict[str, int] = {}
        for f in all_findings:
            sev = f.get("severity", "UNKNOWN")
            severity_counts[sev] = severity_counts.get(sev, 0) + 1

        result_data = {
            "target": base_url,
            "checks_run": checks,
            "findings": all_findings,
            "summary": {
                "total_findings": len(all_findings),
                "severity_counts": severity_counts,
            },
            "errors": errors,
        }

        # Determine status
        if errors and not all_findings:
            status = AdapterResultStatus.FAILURE
        elif errors:
            status = AdapterResultStatus.PARTIAL
        else:
            status = AdapterResultStatus.SUCCESS

        return AdapterResult(
            status=status,
            data=result_data,
            metadata={},
        )

    # -- info ---------------------------------------------------------------

    def interpret_result(self, result: AdapterResult) -> str:
        if result.status != AdapterResultStatus.SUCCESS:
            return f"Web Server scan failed: {result.error_message}"
        
        data = result.data
        if not data:
            return "No Web Server scan data."
            
        target = data.get("target", "unknown")
        findings = data.get("findings", [])
        summary_stats = data.get("summary", {})
        severity_counts = summary_stats.get("severity_counts", {})
        
        high = severity_counts.get("HIGH", 0)
        medium = severity_counts.get("MEDIUM", 0)
        low = severity_counts.get("LOW", 0)
        info = severity_counts.get("INFO", 0)
        
        header = f"Web Server Scan for {target}:\n"
        header += f"Risk Summary: {high} High, {medium} Medium, {low} Low, {info} Info\n"
        
        if not findings:
            return header + "No specific findings reported."
            
        details = ""
        # Group by severity
        findings_by_sev = {"HIGH": [], "MEDIUM": [], "LOW": [], "INFO": []}
        
        for f in findings:
            sev = f.get("severity", "INFO").upper()
            if sev not in findings_by_sev: sev = "INFO"
            findings_by_sev[sev].append(f)
            
        for sev in ["HIGH", "MEDIUM", "LOW", "INFO"]:
            items = findings_by_sev[sev]
            if items:
                details += f"\n[{sev}] Findings:\n"
                for item in items:
                    cat = item.get("category", "")
                    title = item.get("title", "")
                    desc = item.get("detail", "")
                    details += f"  - {title}: {desc}\n"
                    
        return header + details

    def get_info(self) -> Dict[str, Any]:
        return {
            "name": self.name,
            "version": self.version,
            "description": self.description,
            "capabilities": [
                "security_header_analysis",
                "default_file_probing",
                "http_method_testing",
                "server_version_detection",
            ],
            "requirements": ["requests"],
            "parameters": {
                "type": "object",
                "properties": {
                    "target": {
                        "type": "string",
                        "description": "Target URL or hostname",
                    },
                    "checks": {
                        "type": "array",
                        "items": {"type": "string"},
                        "description": "Checks to run: headers, files, methods, versions",
                        "default": ["headers", "files", "methods", "versions"],
                    },
                },
                "required": ["target"],
            },
        }


# Factory function
def create_web_server_scanner_adapter(
    config: Dict[str, Any] = None,
) -> WebServerScannerAdapter:
    """
    Factory function to create a Web Server Scanner adapter instance.

    Args:
        config: Optional configuration dictionary

    Returns:
        WebServerScannerAdapter: Configured adapter instance
    """
    return WebServerScannerAdapter(config or {})
