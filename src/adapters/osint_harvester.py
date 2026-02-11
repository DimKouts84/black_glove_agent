"""
OSINT Harvester Adapter for Black Glove Pentest Agent

This adapter performs Open Source Intelligence (OSINT) harvesting:
- Email address discovery from web pages and public sources
- Enhanced subdomain enumeration via certificate transparency (crt.sh)
- Metadata extraction (technologies, contact info patterns)

It aggregates data from multiple passive sources without requiring
any API keys or external services beyond public web endpoints.
"""

import re
import time
import json
import logging
from typing import Any, Dict, List, Optional
from concurrent.futures import ThreadPoolExecutor, as_completed

import requests
from bs4 import BeautifulSoup

from .base import BaseAdapter
from .interface import AdapterResult, AdapterResultStatus


class OSINTHarvesterAdapter(BaseAdapter):
    """
    OSINT Harvester adapter for email and subdomain discovery
    from public sources.

    Techniques:
    - Email pattern extraction from web pages (regex-based)
    - Certificate Transparency (crt.sh) for subdomain enumeration
    - Web page metadata scraping for technology and contact info
    """

    def __init__(self, config: Dict[str, Any]):
        """
        Initialize the OSINT Harvester adapter.

        Config options (all optional):
          - timeout: HTTP request timeout in seconds (default 15)
          - max_pages: Maximum number of web pages to scrape for emails (default 10)
          - max_workers: Concurrent workers for page scraping (default 5)
          - user_agent: Custom User-Agent string
          - crt_sh_url: Base URL for crt.sh (default "https://crt.sh/")
        """
        super().__init__(config)
        self._required_config_fields = []
        self._required_params = ["target"]
        self.version = "1.0.0"

        self._defaults = {
            "timeout": 15,
            "max_pages": 10,
            "max_workers": 5,
            "user_agent": "BlackGloveOSINT/1.0 (+https://example.invalid)",
            "crt_sh_url": "https://crt.sh/",
        }

        # Common email patterns to exclude (false positives)
        self._email_blacklist_patterns = [
            r".*@example\.(com|org|net)$",
            r".*@test\..*$",
            r".*@localhost$",
            r".*\.(png|jpg|gif|svg|css|js)$",  # file extensions misidentified
            r"^noreply@.*$",
            r"^no-reply@.*$",
        ]

        # Starting URLs to scrape for emails (relative to the target domain)
        self._seed_paths = [
            "/",
            "/about",
            "/about-us",
            "/contact",
            "/contact-us",
            "/team",
            "/people",
            "/staff",
            "/impressum",
            "/privacy",
            "/legal",
        ]

    # ---- Validation ----

    def validate_config(self) -> bool:
        super().validate_config()
        cfg = self.config or {}

        if "timeout" in cfg:
            if not isinstance(cfg["timeout"], (int, float)) or cfg["timeout"] <= 0:
                raise ValueError("timeout must be a positive number")

        if "max_pages" in cfg:
            if not isinstance(cfg["max_pages"], int) or cfg["max_pages"] <= 0:
                raise ValueError("max_pages must be a positive integer")

        if "max_workers" in cfg:
            if not isinstance(cfg["max_workers"], int) or cfg["max_workers"] <= 0:
                raise ValueError("max_workers must be a positive integer")

        return True

    def validate_params(self, params: Dict[str, Any]) -> bool:
        super().validate_params(params)

        target = params.get("target")
        if not isinstance(target, str) or not target.strip():
            raise ValueError("target must be a non-empty string (domain name)")

        domain = target.strip().lower()
        if not self._is_valid_domain(domain):
            raise ValueError(f"Invalid domain: {domain}")

        # Validate optional modules list
        modules = params.get("modules")
        if modules is not None:
            valid_modules = {"emails", "subdomains", "metadata"}
            if not isinstance(modules, list):
                raise ValueError("modules must be a list")
            for m in modules:
                if m not in valid_modules:
                    raise ValueError(
                        f"Invalid module '{m}'. Valid: {valid_modules}"
                    )

        return True

    # ---- Core execution ----

    def _execute_impl(self, params: Dict[str, Any]) -> AdapterResult:
        domain = params["target"].strip().lower()
        modules = params.get("modules", ["emails", "subdomains", "metadata"])
        timeout = self.config.get("timeout", self._defaults["timeout"])

        self.logger.info(f"OSINT harvesting for domain={domain}, modules={modules}")

        results = {
            "domain": domain,
            "emails": [],
            "subdomains": [],
            "metadata": {},
        }
        errors = {}
        timings = {}

        # --- Module: Subdomains via crt.sh ---
        if "subdomains" in modules:
            try:
                t0 = time.time()
                subdomains = self._harvest_subdomains_crtsh(domain, timeout)
                timings["subdomains_time"] = round(time.time() - t0, 3)
                results["subdomains"] = subdomains
                self.logger.info(f"Found {len(subdomains)} subdomains via crt.sh")
            except Exception as e:
                errors["subdomains"] = str(e)
                self.logger.warning(f"Subdomain harvesting failed: {e}")

        # --- Module: Emails from web pages ---
        if "emails" in modules:
            try:
                t0 = time.time()
                emails = self._harvest_emails(domain, timeout)
                timings["emails_time"] = round(time.time() - t0, 3)
                results["emails"] = emails
                self.logger.info(f"Found {len(emails)} email addresses")
            except Exception as e:
                errors["emails"] = str(e)
                self.logger.warning(f"Email harvesting failed: {e}")

        # --- Module: Metadata from web pages ---
        if "metadata" in modules:
            try:
                t0 = time.time()
                metadata = self._harvest_metadata(domain, timeout)
                timings["metadata_time"] = round(time.time() - t0, 3)
                results["metadata"] = metadata
                self.logger.info(f"Extracted metadata: {list(metadata.keys())}")
            except Exception as e:
                errors["metadata"] = str(e)
                self.logger.warning(f"Metadata extraction failed: {e}")

        # Add errors and timings to results
        results["errors"] = errors
        results["timings"] = timings

        # Determine overall status
        has_data = (
            len(results["emails"]) > 0
            or len(results["subdomains"]) > 0
            or bool(results["metadata"])
        )

        if errors and has_data:
            status = AdapterResultStatus.PARTIAL
        elif errors and not has_data:
            status = AdapterResultStatus.FAILURE
        else:
            status = AdapterResultStatus.SUCCESS

        # Build human-readable summary for the LLM
        summary_lines = [f"OSINT Harvester Results for {domain}:"]
        summary_lines.append(f"  Emails found: {len(results['emails'])}")
        if results["emails"]:
            for email in results["emails"][:20]:
                summary_lines.append(f"    - {email}")
            if len(results["emails"]) > 20:
                summary_lines.append(
                    f"    ... and {len(results['emails']) - 20} more"
                )

        summary_lines.append(f"  Subdomains found: {len(results['subdomains'])}")
        if results["subdomains"]:
            for sub in results["subdomains"][:30]:
                summary_lines.append(f"    - {sub}")
            if len(results["subdomains"]) > 30:
                summary_lines.append(
                    f"    ... and {len(results['subdomains']) - 30} more"
                )

        if results["metadata"]:
            summary_lines.append("  Metadata:")
            meta = results["metadata"]
            if meta.get("title"):
                summary_lines.append(f"    Title: {meta['title']}")
            if meta.get("technologies"):
                summary_lines.append(
                    f"    Technologies: {', '.join(meta['technologies'][:10])}"
                )
            if meta.get("social_links"):
                summary_lines.append(
                    f"    Social links: {len(meta['social_links'])} found"
                )

        if errors:
            summary_lines.append(f"  Errors: {errors}")

        results["summary"] = "\n".join(summary_lines)

        # Store evidence
        evidence_filename = (
            f"osint_harvest_{domain.replace('.', '_')}_{int(time.time())}.json"
        )
        evidence_path = self._store_evidence(results, evidence_filename)

        return AdapterResult(
            status=status,
            data=results,
            metadata={
                "adapter": self.name,
                "domain": domain,
                "modules": modules,
                "email_count": len(results["emails"]),
                "subdomain_count": len(results["subdomains"]),
                "timestamp": time.time(),
            },
            evidence_path=evidence_path,
        )

    # ---- Harvesting methods ----

    def _harvest_subdomains_crtsh(
        self, domain: str, timeout: float
    ) -> List[str]:
        """
        Query crt.sh Certificate Transparency logs for subdomains.

        Returns a deduplicated, sorted list of subdomains.
        """
        crt_url = self.config.get("crt_sh_url", self._defaults["crt_sh_url"])
        # url = f"{crt_url.rstrip('/')}/?q=%.{domain}&output=json" # Replaced with params

        headers = {
            "User-Agent": self.config.get(
                "user_agent", self._defaults["user_agent"]
            ),
            "Accept": "application/json",
        }
        
        params = {
            "q": f"%.{domain}",
            "output": "json"
        }

        response = requests.get(crt_url, headers=headers, params=params, timeout=timeout)
        response.raise_for_status()

        subdomains = set()
        try:
            entries = response.json()
            if isinstance(entries, list):
                for entry in entries:
                    name_value = entry.get("name_value", "")
                    if isinstance(name_value, str):
                        for name in name_value.splitlines():
                            name = name.strip().lower()
                            # Remove wildcard prefix
                            if name.startswith("*."):
                                name = name[2:]
                            # Only keep names belonging to target domain
                            if name and (
                                name == domain or name.endswith(f".{domain}")
                            ):
                                subdomains.add(name)
        except (json.JSONDecodeError, ValueError):
            self.logger.warning("Failed to parse crt.sh JSON response")

        return sorted(subdomains)

    def _harvest_emails(self, domain: str, timeout: float) -> List[str]:
        """
        Scrape web pages for email addresses belonging to the target domain.

        Crawls seed paths on the target domain and extracts email patterns.
        """
        max_pages = self.config.get("max_pages", self._defaults["max_pages"])
        max_workers = self.config.get(
            "max_workers", self._defaults["max_workers"]
        )
        user_agent = self.config.get(
            "user_agent", self._defaults["user_agent"]
        )

        all_emails = set()
        urls_to_scrape = []

        # Build URLs from seed paths
        for path in self._seed_paths[:max_pages]:
            urls_to_scrape.append(f"https://{domain}{path}")

        # Scrape pages concurrently
        with ThreadPoolExecutor(max_workers=max_workers) as executor:
            futures = {
                executor.submit(
                    self._scrape_page_for_emails, url, domain, timeout, user_agent
                ): url
                for url in urls_to_scrape
            }
            for future in as_completed(futures):
                url = futures[future]
                try:
                    emails = future.result()
                    all_emails.update(emails)
                except Exception as e:
                    self.logger.debug(f"Failed to scrape {url}: {e}")

        # Filter out blacklisted patterns
        filtered = [
            email
            for email in all_emails
            if not self._is_blacklisted_email(email)
        ]

        return sorted(filtered)

    def _scrape_page_for_emails(
        self, url: str, domain: str, timeout: float, user_agent: str
    ) -> set:
        """
        Scrape a single page for email addresses.
        """
        headers = {"User-Agent": user_agent}

        try:
            response = requests.get(
                url, headers=headers, timeout=timeout, allow_redirects=True
            )
            if response.status_code != 200:
                return set()
        except requests.RequestException:
            return set()

        content = response.text
        emails = set()

        # Regex for email addresses
        email_pattern = re.compile(
            r"[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}",
            re.IGNORECASE,
        )

        # Extract from raw HTML
        raw_matches = email_pattern.findall(content)
        for email in raw_matches:
            email = email.lower().strip()
            # Only keep emails belonging to the target domain
            if email.endswith(f"@{domain}") or domain in email:
                emails.add(email)

        # Also check mailto: links
        try:
            soup = BeautifulSoup(content, "html.parser")
            for link in soup.find_all("a", href=True):
                href = link["href"]
                if href.startswith("mailto:"):
                    email = href.replace("mailto:", "").split("?")[0].strip().lower()
                    if email_pattern.match(email):
                        if email.endswith(f"@{domain}") or domain in email:
                            emails.add(email)
        except Exception:
            pass

        return emails

    def _harvest_metadata(self, domain: str, timeout: float) -> Dict[str, Any]:
        """
        Extract metadata from the target domain's main page.

        Includes: title, description, technologies (from headers/meta),
        social media links, contact info patterns.
        """
        user_agent = self.config.get(
            "user_agent", self._defaults["user_agent"]
        )
        headers = {"User-Agent": user_agent}
        url = f"https://{domain}/"

        metadata = {}

        try:
            response = requests.get(
                url, headers=headers, timeout=timeout, allow_redirects=True
            )
        except requests.RequestException as e:
            self.logger.debug(f"Failed to fetch {url}: {e}")
            return metadata

        # Extract from response headers
        server = response.headers.get("Server", "")
        if server:
            metadata["server"] = server

        powered_by = response.headers.get("X-Powered-By", "")
        if powered_by:
            metadata["powered_by"] = powered_by

        # Parse HTML
        try:
            soup = BeautifulSoup(response.text, "html.parser")

            # Title
            title_tag = soup.find("title")
            if title_tag and title_tag.string:
                metadata["title"] = title_tag.string.strip()

            # Meta description
            desc_tag = soup.find("meta", attrs={"name": "description"})
            if desc_tag and desc_tag.get("content"):
                metadata["description"] = desc_tag["content"].strip()

            # Meta generator (CMS detection)
            gen_tag = soup.find("meta", attrs={"name": "generator"})
            if gen_tag and gen_tag.get("content"):
                metadata["generator"] = gen_tag["content"].strip()

            # Technologies detection from meta tags and scripts
            technologies = set()

            if metadata.get("server"):
                technologies.add(metadata["server"].split("/")[0])
            if metadata.get("powered_by"):
                technologies.add(metadata["powered_by"])
            if metadata.get("generator"):
                technologies.add(metadata["generator"])

            # Detect from script sources
            for script in soup.find_all("script", src=True):
                src = script["src"].lower()
                if "jquery" in src:
                    technologies.add("jQuery")
                elif "react" in src:
                    technologies.add("React")
                elif "angular" in src:
                    technologies.add("Angular")
                elif "vue" in src:
                    technologies.add("Vue.js")
                elif "bootstrap" in src:
                    technologies.add("Bootstrap")
                elif "wordpress" in src or "wp-" in src:
                    technologies.add("WordPress")
                elif "drupal" in src:
                    technologies.add("Drupal")
                elif "joomla" in src:
                    technologies.add("Joomla")

            if technologies:
                metadata["technologies"] = sorted(technologies)

            # Social media links
            social_domains = {
                "twitter.com": "Twitter/X",
                "x.com": "Twitter/X",
                "facebook.com": "Facebook",
                "linkedin.com": "LinkedIn",
                "github.com": "GitHub",
                "instagram.com": "Instagram",
                "youtube.com": "YouTube",
            }
            social_links = []
            for link in soup.find_all("a", href=True):
                href = link["href"].lower()
                for social_domain, platform in social_domains.items():
                    if social_domain in href:
                        social_links.append(
                            {"platform": platform, "url": link["href"]}
                        )
                        break

            # Deduplicate social links by URL
            seen_urls = set()
            unique_social = []
            for sl in social_links:
                if sl["url"] not in seen_urls:
                    seen_urls.add(sl["url"])
                    unique_social.append(sl)
            if unique_social:
                metadata["social_links"] = unique_social[:20]

            # Phone number patterns (from visible text only, not raw HTML)
            # Strip scripts and styles to avoid SVG path data false positives
            for tag in soup(["script", "style", "svg", "path"]):
                tag.decompose()
            visible_text = soup.get_text(separator=" ")

            phone_pattern = re.compile(
                r"(?:[\+][(]?[0-9]{1,4}[)]?[-\s\./0-9]{7,15}"
                r"|[(][0-9]{1,4}[)][-\s\./0-9]{7,15}"
                r"|(?<![0-9.\-/])(?:[0-9]{1,4}[-.\s][0-9]{2,4}[-.\s][0-9]{3,10}))"
            )
            phones = phone_pattern.findall(visible_text)
            if phones:
                # Filter: must have 7-15 digits total
                valid_phones = [
                    p.strip()
                    for p in phones
                    if 7 <= len(re.sub(r"[^\d]", "", p)) <= 15
                ]
                if valid_phones:
                    metadata["phone_numbers"] = list(set(valid_phones))[:10]

        except Exception as e:
            self.logger.debug(f"HTML parsing error: {e}")

        return metadata

    # ---- Helpers ----

    def _is_valid_domain(self, domain: str) -> bool:
        """Validate domain format."""
        if len(domain) > 253:
            return False
        pattern = re.compile(
            r"^(?=.{1,253}$)(?:[A-Za-z0-9](?:[A-Za-z0-9\-]{0,61}[A-Za-z0-9])?\.)+[A-Za-z0-9\-]{2,63}$"
        )
        return bool(pattern.match(domain))

    def _is_blacklisted_email(self, email: str) -> bool:
        """Check if an email matches any blacklist pattern."""
        for pattern in self._email_blacklist_patterns:
            if re.match(pattern, email, re.IGNORECASE):
                return True
        return False

    def get_info(self) -> Dict[str, Any]:
        base_info = super().get_info()
        base_info.update(
            {
                "name": "OSINTHarvesterAdapter",
                "version": self.version,
                "description": (
                    "OSINT Harvester for email discovery, subdomain enumeration "
                    "(via crt.sh), and web metadata extraction. Requires a valid "
                    "domain name (e.g. 'microsoft.com'). All passive — no active "
                    "scanning, no API keys required."
                ),
                "capabilities": base_info["capabilities"]
                + [
                    "email_harvesting",
                    "subdomain_enumeration",
                    "metadata_extraction",
                    "certificate_transparency",
                    "evidence_storage",
                ],
                "requirements": ["requests", "beautifulsoup4"],
                "parameters": {
                    "type": "object",
                    "properties": {
                        "target": {
                            "type": "string",
                            "description": (
                                "The domain to harvest OSINT from "
                                "(e.g. 'microsoft.com'). NOT an IP address."
                            ),
                        },
                        "modules": {
                            "type": "array",
                            "items": {"type": "string"},
                            "description": (
                                "Which modules to run. Options: "
                                "'emails', 'subdomains', 'metadata'. "
                                "Default: all three."
                            ),
                        },
                    },
                    "required": ["target"],
                },
                "example_usage": {
                    "target": "example.com",
                    "modules": ["emails", "subdomains", "metadata"],
                },
            }
        )
        return base_info


# Factory function
def create_osint_harvester_adapter(
    config: Dict[str, Any] = None,
) -> OSINTHarvesterAdapter:
    """
    Factory function to create an OSINT Harvester adapter instance.

    Args:
        config: Optional configuration dictionary

    Returns:
        OSINTHarvesterAdapter: Configured adapter instance
    """
    if config is None:
        config = {}
    return OSINTHarvesterAdapter(config)
