"""Tests for RDAP client bootstrap and parsing."""

import json
from datetime import datetime
from unittest.mock import MagicMock, patch

import pytest

from src.adapters.rdap_client import (
    fetch_rdap_domain,
    parse_rdap_payload,
    resolve_rdap_url,
)


SAMPLE_RDAP = {
    "ldhName": "dimkouts.dev",
    "status": ["client delete prohibited", "client transfer prohibited"],
    "entities": [
        {
            "roles": ["registrar"],
            "vcardArray": [
                "vcard",
                [["fn", {}, "text", "Porkbun LLC"]],
            ],
        }
    ],
    "events": [
        {"eventAction": "registration", "eventDate": "2026-04-05T00:00:00Z"},
        {"eventAction": "expiration", "eventDate": "2027-04-05T00:00:00Z"},
    ],
    "nameservers": [
        {"ldhName": "cloe.ns.cloudflare.com"},
        {"ldhName": "mustafa.ns.cloudflare.com"},
    ],
}


class TestRdapClient:
    def test_parse_rdap_payload_google_style(self):
        parsed = parse_rdap_payload(SAMPLE_RDAP)
        assert parsed["registrar"] == "Porkbun LLC"
        assert parsed["creation_date"].year == 2026
        assert parsed["expiration_date"].year == 2027
        assert "cloe.ns.cloudflare.com" in parsed["name_servers"]

    @patch("src.adapters.rdap_client._load_bootstrap_services")
    def test_resolve_rdap_url_google_tld(self, mock_bootstrap):
        mock_bootstrap.return_value = {"dev": "https://pubapi.registry.google/rdap/domain/"}
        url = resolve_rdap_url("dimkouts.dev")
        assert url == "https://pubapi.registry.google/rdap/domain/dimkouts.dev"

    @patch("src.adapters.rdap_client.requests.get")
    @patch("src.adapters.rdap_client.resolve_rdap_url")
    def test_fetch_rdap_domain_success(self, mock_resolve, mock_get):
        mock_resolve.return_value = "https://pubapi.registry.google/rdap/domain/dimkouts.dev"
        response = MagicMock()
        response.status_code = 200
        response.json.return_value = SAMPLE_RDAP
        mock_get.return_value = response

        data, warnings = fetch_rdap_domain("dimkouts.dev")
        assert data is not None
        assert data["registrar"] == "Porkbun LLC"
        assert warnings == []

    @patch("src.adapters.rdap_client.requests.get")
    @patch("src.adapters.rdap_client.resolve_rdap_url")
    def test_fetch_rdap_domain_http_failure(self, mock_resolve, mock_get):
        mock_resolve.return_value = "https://pubapi.registry.google/rdap/domain/dimkouts.dev"
        response = MagicMock()
        response.status_code = 503
        mock_get.return_value = response

        data, warnings = fetch_rdap_domain("dimkouts.dev")
        assert data is None
        assert any("503" in w for w in warnings)

    @patch("src.adapters.rdap_client.requests.get")
    @patch("src.adapters.rdap_client.resolve_rdap_url")
    def test_fetch_rdap_domain_malformed_json(self, mock_resolve, mock_get):
        mock_resolve.return_value = "https://pubapi.registry.google/rdap/domain/dimkouts.dev"
        response = MagicMock()
        response.status_code = 200
        response.json.side_effect = ValueError("bad json")
        mock_get.return_value = response

        data, warnings = fetch_rdap_domain("dimkouts.dev")
        assert data is None
        assert any("JSON" in w for w in warnings)

    @patch("src.adapters.rdap_client.resolve_rdap_url")
    def test_fetch_rdap_domain_no_service(self, mock_resolve):
        mock_resolve.return_value = None
        data, warnings = fetch_rdap_domain("example.invalidtld")
        assert data is None
        assert warnings
