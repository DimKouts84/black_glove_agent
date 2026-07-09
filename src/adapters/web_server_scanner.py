"""
Web Server Scanner Adapter for Black Glove Pentest Agent

Nikto-like pure-Python scanner that checks for:
- Missing security headers (X-Frame-Options, CSP, HSTS, etc.)
- Default / dangerous files & paths (phpinfo, .env, .git, admin panels)
- Dangerous HTTP methods enabled (PUT, DELETE, TRACE)
- Server version disclosure via the Server header
"""

import logging
import re
from typing import Any, Callable, Dict, List, Optional, Tuple
from urllib.parse import urlparse, urljoin

import requests

from .base import BaseAdapter
from .interface import AdapterResult, AdapterResultStatus
from .url_params import resolve_target_url

logger = logging.getLogger(__name__)

SECURITY_HEADERS = [
    ("X-Frame-Options", "Prevents clickjacking by disabling framing", "MEDIUM"),
    ("Content-Security-Policy", "Mitigates XSS and data injection attacks", "HIGH"),
    ("Strict-Transport-Security", "Enforces HTTPS connections (HSTS)", "HIGH"),
    ("X-Content-Type-Options", "Prevents MIME-type sniffing", "LOW"),
    ("Permissions-Policy", "Controls browser feature permissions", "LOW"),
    ("Referrer-Policy", "Controls referrer information leakage", "LOW"),
    ("X-XSS-Protection", "Legacy XSS filter (defense-in-depth)", "INFO"),
]

INFORMATIONAL_PATHS = {
    "/robots.txt",
    "/sitemap.xml",
    "/humans.txt",
    "/security.txt",
    "/.well-known/security.txt",
}

DANGEROUS_PATHS = [
    ("/phpinfo.php", "PHP configuration disclosure", "HIGH"),
    ("/server-status", "Apache server status page", "HIGH"),
    ("/server-info", "Apache server info page", "HIGH"),
    ("/nginx_status", "Nginx status page", "HIGH"),
    ("/admin/", "Admin panel", "MEDIUM"),
    ("/administrator/", "Administrator panel", "MEDIUM"),
    ("/wp-admin/", "WordPress admin panel", "MEDIUM"),
    ("/wp-login.php", "WordPress login page", "MEDIUM"),
    ("/phpmyadmin/", "phpMyAdmin database management", "HIGH"),
    ("/adminer.php", "Adminer database tool", "HIGH"),
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
    ("/backup.sql", "SQL database backup", "CRITICAL"),
    ("/backup.zip", "Backup archive", "HIGH"),
    ("/backup.tar.gz", "Backup archive", "HIGH"),
    ("/database.sql", "Database dump", "CRITICAL"),
    ("/dump.sql", "Database dump", "CRITICAL"),
    ("/db.sql", "Database dump", "CRITICAL"),
    ("/debug/", "Debug page", "HIGH"),
    ("/test/", "Test directory", "LOW"),
    ("/test.php", "Test PHP file", "MEDIUM"),
    ("/info.php", "PHP info file", "HIGH"),
    ("/elmah.axd", ".NET error log", "HIGH"),
    ("/trace.axd", ".NET trace log", "HIGH"),
    ("/robots.txt", "Robots exclusion file (may reveal hidden paths)", "INFO"),
    ("/sitemap.xml", "XML sitemap", "INFO"),
    ("/crossdomain.xml", "Flash cross-domain policy", "LOW"),
    ("/clientaccesspolicy.xml", "Silverlight cross-domain policy", "LOW"),
    ("/humans.txt", "Humans.txt (team/tech info)", "INFO"),
    ("/security.txt", "Security contact info", "INFO"),
    ("/.well-known/security.txt", "Security contact info (standard path)", "INFO"),
    ("/package.json", "Node.js package manifest", "MEDIUM"),
    ("/composer.json", "PHP Composer manifest", "MEDIUM"),
    ("/Gemfile", "Ruby Bundler manifest", "MEDIUM"),
    ("/requirements.txt", "Python requirements file", "MEDIUM"),
    ("/.DS_Store", "macOS directory metadata", "LOW"),
    ("/Thumbs.db", "Windows thumbnail cache", "LOW"),
    ("/error_log", "Error log file", "MEDIUM"),
    ("/access_log", "Access log file", "MEDIUM"),
    ("/cgi-bin/", "CGI scripts directory", "MEDIUM"),
]

PATH_CONTENT_VALIDATORS: Dict[str, Callable[[bytes], bool]] = {
    "/.env": lambda b: b"=" in b and len(b) < 50000,
    "/.git/HEAD": lambda b: b.strip().startswith(b"ref:"),
    "/.git/config": lambda b: b"[core]" in b or b"[remote" in b,
    "/phpinfo.php": lambda b: b"phpinfo()" in b.lower() or b"php version" in b.lower(),
    "/info.php": lambda b: b"phpinfo()" in b.lower() or b"php version" in b.lower(),
    "/wp-config.php": lambda b: b"DB_NAME" in b or b"define(" in b,
    "/backup.sql": lambda b: b"insert into" in b.lower() or b"create table" in b.lower(),
    "/database.sql": lambda b: b"insert into" in b.lower() or b"create table" in b.lower(),
    "/dump.sql": lambda b: b"insert into" in b.lower() or b"create table" in b.lower(),
    "/db.sql": lambda b: b"insert into" in b.lower() or b"create table" in b.lower(),
    "/package.json": lambda b: b'"name"' in b and b"{" in b,
    "/composer.json": lambda b: b'"name"' in b or b'"require"' in b,
}

RISK_SEVERITIES = {"CRITICAL", "HIGH", "MEDIUM", "LOW", "ERROR"}

DANGEROUS_METHODS = ["PUT", "DELETE", "TRACE", "CONNECT"]

VERSION_PATTERN = re.compile(
    r"(?:Apache|nginx|Microsoft-IIS|LiteSpeed|Caddy|Tomcat|Jetty|lighttpd)"
    r"[/ ]*(\d+[\.\d]*\S*)",
    re.IGNORECASE,
)


class WebServerScannerAdapter(BaseAdapter):
    """Nikto-like web server scanner."""

    def __init__(self, config: Dict[str, Any] = None):
        super().__init__(config or {})
        self.name = "WebServerScannerAdapter"
        self.version = "1.1.0"
        self.description = (
            "Nikto-like web server checks: security headers, default files, "
            "HTTP methods, server version disclosure"
        )
        self._timeout: float = self.config.get("timeout", 10.0)
        self._user_agent: str = self.config.get(
            "user_agent",
            "Mozilla/5.0 (compatible; BlackGloveScanner/1.0; +https://github.com/black-glove)",
        )
        self._follow_redirects: bool = self.config.get("follow_redirects", True)

    def validate_params(self, params: Dict[str, Any]) -> None:
        resolve_target_url(params)

        checks = params.get("checks", ["headers", "files", "methods", "versions"])
        valid_checks = {"headers", "files", "methods", "versions"}
        invalid = set(checks) - valid_checks
        if invalid:
            raise ValueError(f"Invalid check(s): {invalid}. Valid: {valid_checks}")

    def _normalise_target(self, target: str) -> str:
        parsed = urlparse(target)
        return f"{parsed.scheme}://{parsed.netloc}"

    def _request(
        self,
        method: str,
        url: str,
        *,
        allow_redirects: bool = True,
        timeout: Optional[float] = None,
    ) -> Optional[requests.Response]:
        try:
            return requests.request(
                method,
                url,
                headers={"User-Agent": self._user_agent},
                timeout=timeout or self._timeout,
                allow_redirects=allow_redirects,
                verify=False,
            )
        except requests.RequestException as exc:
            logger.debug(f"{method} {url} failed: {exc}")
            return None

    def _probe_not_found_baseline(self, base_url: str) -> Optional[int]:
        """Fetch a random path to estimate soft-404 response size."""
        probe_url = urljoin(base_url + "/", "black_glove_probe_not_found_xyz123")
        resp = self._request("GET", probe_url, allow_redirects=False)
        if resp and resp.status_code in (404, 403, 200):
            return len(resp.content)
        return None

    def _content_matches_path(self, path: str, body: bytes, not_found_len: Optional[int]) -> bool:
        validator = PATH_CONTENT_VALIDATORS.get(path)
        if validator:
            return validator(body)

        if not_found_len is not None and abs(len(body) - not_found_len) < 50:
            return False

        if len(body) < 20:
            return False

        return True

    def _check_security_headers(self, base_url: str) -> List[Dict[str, Any]]:
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
        return findings

    def _check_default_files(self, base_url: str) -> List[Dict[str, Any]]:
        findings: List[Dict[str, Any]] = []
        not_found_len = self._probe_not_found_baseline(base_url)

        for path, description, severity in DANGEROUS_PATHS:
            if path in INFORMATIONAL_PATHS:
                continue

            url = urljoin(base_url + "/", path.lstrip("/"))
            resp = self._request("GET", url, allow_redirects=False)
            if resp is None or resp.status_code != 200:
                continue

            if not self._content_matches_path(path, resp.content, not_found_len):
                logger.debug(f"Skipping likely soft-404 for {path}")
                continue

            findings.append({
                "check": "files",
                "title": f"Found: {path}",
                "detail": f"{description} — HTTP 200, {len(resp.content)} bytes (content validated)",
                "severity": severity,
                "url": url,
                "status_code": resp.status_code,
                "confidence": 0.85 if path in PATH_CONTENT_VALIDATORS else 0.65,
            })
        return findings

    def _check_http_methods(self, base_url: str) -> List[Dict[str, Any]]:
        findings: List[Dict[str, Any]] = []

        resp = self._request("OPTIONS", base_url)
        if resp is not None:
            allow_header = resp.headers.get("Allow", "")
            if allow_header:
                advertised = [m.strip().upper() for m in allow_header.split(",")]
                for method in DANGEROUS_METHODS:
                    if method in advertised:
                        findings.append({
                            "check": "methods",
                            "title": f"Dangerous method advertised: {method}",
                            "detail": f"Server Allow header includes {method}",
                            "severity": "HIGH" if method in ("PUT", "DELETE") else "MEDIUM",
                        })

        resp = self._request("TRACE", base_url)
        if resp is not None and resp.status_code == 200:
            findings.append({
                "check": "methods",
                "title": "TRACE method is enabled",
                "detail": "TRACE can be used in cross-site tracing (XST) attacks",
                "severity": "MEDIUM",
            })

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
            pass

        return findings

    def _check_server_version(self, base_url: str) -> List[Dict[str, Any]]:
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
            else:
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

    def _execute_impl(self, params: Dict[str, Any]) -> AdapterResult:
        target = resolve_target_url(params)
        checks = params.get("checks", ["headers", "files", "methods", "versions"])

        base_url = self._normalise_target(target)
        logger.info(f"Starting web server scan on {base_url}")

        all_findings: List[Dict[str, Any]] = []
        errors: List[str] = []

        check_map = {
            "headers": self._check_security_headers,
            "files": self._check_default_files,
            "methods": self._check_http_methods,
            "versions": self._check_server_version,
        }

        for check_name in checks:
            try:
                results = check_map[check_name](base_url)
                all_findings.extend(results)
            except Exception as exc:
                msg = f"Check '{check_name}' failed: {exc}"
                logger.error(msg)
                errors.append(msg)

        risk_findings = [
            f for f in all_findings if f.get("severity", "").upper() in RISK_SEVERITIES
        ]
        severity_counts: Dict[str, int] = {}
        for f in risk_findings:
            sev = f.get("severity", "UNKNOWN").upper()
            severity_counts[sev] = severity_counts.get(sev, 0) + 1

        result_data = {
            "target": base_url,
            "checks_run": checks,
            "findings": all_findings,
            "summary": {
                "total_findings": len(risk_findings),
                "severity_counts": severity_counts,
            },
            "errors": errors,
        }

        if errors and not all_findings:
            status = AdapterResultStatus.FAILURE
        elif errors:
            status = AdapterResultStatus.PARTIAL
        else:
            status = AdapterResultStatus.SUCCESS

        return AdapterResult(status=status, data=result_data, metadata={})

    def interpret_result(self, result: AdapterResult) -> str:
        if result.status not in (
            AdapterResultStatus.SUCCESS,
            AdapterResultStatus.PARTIAL,
        ):
            return f"Web Server scan failed: {result.error_message}"

        data = result.data
        if not data:
            return "No Web Server scan data."

        target = data.get("target", "unknown")
        findings = data.get("findings", [])
        summary_stats = data.get("summary", {})
        severity_counts = summary_stats.get("severity_counts", {})

        risk_findings = [
            f for f in findings if f.get("severity", "").upper() in RISK_SEVERITIES
        ]

        high = severity_counts.get("HIGH", 0) + severity_counts.get("CRITICAL", 0)
        medium = severity_counts.get("MEDIUM", 0)
        low = severity_counts.get("LOW", 0)

        header = f"Web Server Scan for {target}:\n"
        header += f"Risk Summary: {high} High/Critical, {medium} Medium, {low} Low\n"

        if not risk_findings:
            return header + "No security issues reported."

        details = ""
        findings_by_sev: Dict[str, List[Dict[str, Any]]] = {
            "CRITICAL": [],
            "HIGH": [],
            "MEDIUM": [],
            "LOW": [],
            "ERROR": [],
        }

        for f in risk_findings:
            sev = f.get("severity", "LOW").upper()
            if sev not in findings_by_sev:
                sev = "LOW"
            findings_by_sev[sev].append(f)

        for sev in ["CRITICAL", "HIGH", "MEDIUM", "LOW", "ERROR"]:
            items = findings_by_sev[sev]
            if items:
                details += f"\n[{sev}] Findings:\n"
                for item in items:
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
                    "target_url": {
                        "type": "string",
                        "description": "Target URL or hostname (alias: target)",
                    },
                    "target": {
                        "type": "string",
                        "description": "Alias for target_url",
                    },
                    "checks": {
                        "type": "array",
                        "items": {"type": "string"},
                        "description": "Checks to run: headers, files, methods, versions",
                        "default": ["headers", "files", "methods", "versions"],
                    },
                },
                "required": ["target_url"],
            },
        }


def create_web_server_scanner_adapter(
    config: Dict[str, Any] = None,
) -> WebServerScannerAdapter:
    return WebServerScannerAdapter(config or {})
