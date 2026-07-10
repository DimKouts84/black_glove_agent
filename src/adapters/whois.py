"""

WHOIS Adapter for Black Glove Pentest Agent



RDAP-first domain registration lookup with legacy python-whois fallback.

"""



import datetime

import time

import whois

from typing import Any, Dict, List, Optional



from .base import BaseAdapter

from .interface import AdapterResult, AdapterResultStatus

from .domain_params import resolve_domain

from .rdap_client import GOOGLE_TLDS, fetch_rdap_domain





class WhoisAdapter(BaseAdapter):

    """

    WHOIS adapter for domain information lookup.



    For Google Registry TLDs (.dev, .app, etc.) RDAP is authoritative because

    legacy WHOIS port 43 is discontinued. Other TLDs use IANA bootstrap RDAP

    with python-whois fallback.

    """



    def __init__(self, config: Dict[str, Any]):

        super().__init__(config)

        self._required_config_fields = []

        self._required_params = ["domain"]

        self.version = "1.1.0"

        self._timeout = float(self.config.get("timeout", 10.0))



    def validate_config(self) -> bool:

        super().validate_config()

        return True



    def validate_params(self, params: Dict[str, Any]) -> bool:

        if not isinstance(params, dict):

            raise ValueError("Parameters must be a dictionary")



        if "domain" not in params:

            try:

                params["domain"] = resolve_domain(params)

            except ValueError:

                pass



        super().validate_params(params)

        if "domain" in params:

            if not isinstance(params["domain"], str) or not params["domain"].strip():

                raise ValueError("Domain must be a non-empty string")



        return True



    def _execute_impl(self, params: Dict[str, Any]) -> AdapterResult:

        domain = params["domain"].strip().lower()

        self.logger.info("Performing registration lookup for domain: %s", domain)



        start_time = time.time()

        warnings: List[str] = []

        tld = domain.rsplit(".", 1)[-1].lower()

        rdap_first = tld in GOOGLE_TLDS



        registrar = None

        creation = None

        expiration = None

        name_servers = None

        emails = None

        org = None

        status_values = None

        rdap_used = False

        whois_raw = None



        if rdap_first:

            rdap_data, rdap_warnings = fetch_rdap_domain(domain, timeout=self._timeout)

            warnings.extend(rdap_warnings)

            if rdap_data:

                rdap_used = True

                registrar = rdap_data.get("registrar")

                creation = rdap_data.get("creation_date")

                expiration = rdap_data.get("expiration_date")

                name_servers = rdap_data.get("name_servers")

                status_values = rdap_data.get("status")

                whois_raw = rdap_data



        if not any((registrar, creation, expiration)) and not rdap_first:

            try:

                whois_info = whois.whois(domain)

                whois_raw = str(whois_info)



                def _first(val):

                    if isinstance(val, list) and val:

                        return val[0]

                    return val



                registrar = _first(getattr(whois_info, "registrar", None))

                creation = _first(getattr(whois_info, "creation_date", None))

                expiration = _first(getattr(whois_info, "expiration_date", None))

                name_servers = getattr(whois_info, "name_servers", None)

                emails = getattr(whois_info, "emails", None)

                org = getattr(whois_info, "org", None)

            except whois.WhoisError as exc:

                warnings.append(f"Legacy WHOIS failed: {exc}")

            except Exception as exc:

                warnings.append(f"Legacy WHOIS error: {exc}")



        if not any((registrar, creation, expiration)):

            rdap_data, rdap_warnings = fetch_rdap_domain(domain, timeout=self._timeout)

            warnings.extend(rdap_warnings)

            if rdap_data:

                rdap_used = True

                registrar = rdap_data.get("registrar") or registrar

                creation = rdap_data.get("creation_date") or creation

                expiration = rdap_data.get("expiration_date") or expiration

                name_servers = rdap_data.get("name_servers") or name_servers

                status_values = rdap_data.get("status") or status_values

                whois_raw = rdap_data



        execution_time = time.time() - start_time

        expires_in_days = self._expires_in_days(expiration)

        has_core = any((registrar, creation, expiration))



        evidence_filename = f"whois_{domain.replace('.', '_')}_{int(time.time())}.txt"

        evidence_payload = {

            "domain": domain,

            "registrar": registrar,

            "creation_date": creation,

            "expiration_date": expiration,

            "expires_in_days": expires_in_days,

            "name_servers": name_servers,

            "emails": emails,

            "org": org,

            "status": status_values,

            "rdap_used": rdap_used,

            "warnings": warnings,

            "raw": whois_raw,

        }

        evidence_path = self._store_evidence(
            self._json_safe(evidence_payload), evidence_filename
        )



        result_status = (

            AdapterResultStatus.SUCCESS if has_core else AdapterResultStatus.PARTIAL

        )



        return AdapterResult(

            status=result_status,

            data={

                "domain": domain,

                "registrar": registrar,

                "creation_date": creation,

                "expiration_date": expiration,

                "expires_in_days": expires_in_days,

                "name_servers": name_servers,

                "emails": emails,

                "org": org,

                "status": status_values,

                "rdap_used": rdap_used,

                "warnings": warnings,

                "coverage": {

                    "has_core_fields": has_core,

                    "rdap_used": rdap_used,

                },

            },

            metadata={

                "adapter": self.name,

                "domain": domain,

                "timestamp": time.time(),

                "execution_time": execution_time,

                "warnings": warnings,

            },

            execution_time=execution_time,

            evidence_path=evidence_path,

        )



    @staticmethod
    def _json_safe(value: Any) -> Any:
        """Recursively convert values to JSON-serializable forms for evidence storage."""
        if isinstance(value, datetime.datetime):
            return value.isoformat()
        if isinstance(value, dict):
            return {k: WhoisAdapter._json_safe(v) for k, v in value.items()}
        if isinstance(value, (list, tuple)):
            return [WhoisAdapter._json_safe(v) for v in value]
        return value

    @staticmethod

    def _expires_in_days(expiration: Any) -> Optional[int]:

        if not expiration or not hasattr(expiration, "timestamp"):

            return None

        if isinstance(expiration, list) and expiration:

            expiration = expiration[0]

        now = datetime.datetime.now(datetime.timezone.utc)

        if expiration.tzinfo is None:

            exp = expiration.replace(tzinfo=datetime.timezone.utc)

        else:

            exp = expiration.astimezone(datetime.timezone.utc)

        return (exp - now).days



    def interpret_result(self, result: AdapterResult) -> str:

        if result.status not in (

            AdapterResultStatus.SUCCESS,

            AdapterResultStatus.PARTIAL,

        ):

            return f"Whois lookup failed: {result.error_message}"



        data = result.data

        if not data:

            return "No Whois data."



        domain = data.get("domain")

        registrar = data.get("registrar")

        creation_date = data.get("creation_date")

        expiration_date = data.get("expiration_date")

        emails = data.get("emails")

        warnings = data.get("warnings") or []



        if isinstance(domain, list):

            domain = domain[0]

        if isinstance(registrar, list):

            registrar = registrar[0]



        def fmt_date(d):

            if isinstance(d, list):

                return str(d[0])

            return str(d)



        if not any((registrar, creation_date, expiration_date)):

            summary = (

                f"WHOIS/RDAP lookup for {domain} returned no registration data.\n"

            )

            if warnings:

                summary += "Warnings:\n" + "\n".join(f"- {w}" for w in warnings[:5])

            return summary



        summary = f"Whois Registration Info for {domain}:\n"

        summary += f"- Registrar: {registrar}\n"

        summary += f"- Created: {fmt_date(creation_date)}\n"

        summary += f"- Expires: {fmt_date(expiration_date)}\n"

        if data.get("rdap_used"):

            summary += "- Source: RDAP\n"



        if emails:

            if isinstance(emails, list):

                summary += f"- Emails: {', '.join(emails[:3])}\n"

            else:

                summary += f"- Email: {emails}\n"



        if warnings:

            summary += "Warnings:\n" + "\n".join(f"- {w}" for w in warnings[:3]) + "\n"



        return summary



    def get_info(self) -> Dict[str, Any]:

        base_info = super().get_info()

        base_info.update({

            "name": "WhoisAdapter",

            "version": self.version,

            "description": (

                "Domain registration lookup via RDAP (IANA bootstrap / Google Registry) "

                "with legacy WHOIS fallback. Use for domain names, not IP addresses."

            ),

            "capabilities": base_info["capabilities"] + ["domain_lookup", "registration_info"],

            "requirements": ["python-whois", "requests"],

            "parameters": {

                "type": "object",

                "properties": {

                    "domain": {

                        "type": "string",

                        "description": "The domain name to lookup (e.g., 'example.com'). NOT an IP address."

                    }

                },

                "required": ["domain"]

            },

            "example_usage": {

                "domain": "example.com"

            }

        })

        return base_info





def create_whois_adapter(config: Dict[str, Any] = None) -> WhoisAdapter:

    if config is None:

        config = {}

    return WhoisAdapter(config)


