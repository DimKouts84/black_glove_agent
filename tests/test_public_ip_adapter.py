import pytest
from unittest.mock import MagicMock, patch

from src.adapters.public_ip import PublicIpAdapter
from src.adapters.interface import AdapterResultStatus


class TestPublicIpAdapter:
    @patch("src.adapters.public_ip.requests.get")
    def test_ipv4_and_ipv6_success(self, mock_get, tmp_path):
        adapter = PublicIpAdapter({})
        adapter._store_evidence = lambda data, name: str(tmp_path / name)

        responses = {
            "https://api.ipify.org?format=json": MagicMock(
                json=lambda: {"ip": "203.0.113.1"},
                text="203.0.113.1",
                raise_for_status=MagicMock(),
            ),
            "https://api64.ipify.org?format=json": MagicMock(
                json=lambda: {"ip": "2001:db8::1"},
                text="2001:db8::1",
                raise_for_status=MagicMock(),
            ),
        }

        def side_effect(url, timeout=10):
            return responses[url]

        mock_get.side_effect = side_effect

        result = adapter.execute({})

        assert result.status == AdapterResultStatus.SUCCESS
        assert result.data["ipv4"] == "203.0.113.1"
        assert result.data["ipv6"] == "2001:db8::1"
        assert "api.ipify.org" in result.data["services_used"]

    @patch("src.adapters.public_ip.requests.get")
    def test_api64_ipv4_mislabel_fixed(self, mock_get, tmp_path):
        adapter = PublicIpAdapter({})
        adapter._store_evidence = lambda data, name: str(tmp_path / name)

        responses = {
            "https://api.ipify.org?format=json": MagicMock(
                json=lambda: {"ip": "203.0.113.2"},
                raise_for_status=MagicMock(),
            ),
            "https://api64.ipify.org?format=json": MagicMock(
                json=lambda: {"ip": "203.0.113.2"},
                raise_for_status=MagicMock(),
            ),
        }
        mock_get.side_effect = lambda url, timeout=10: responses[url]

        result = adapter.execute({})

        assert result.data.get("ipv6") is None
        assert result.data["ipv4"] == "203.0.113.2"

    @patch("src.adapters.public_ip.requests.get")
    def test_fallback_chain_on_primary_failure(self, mock_get, tmp_path):
        adapter = PublicIpAdapter({})
        adapter._store_evidence = lambda data, name: str(tmp_path / name)

        def side_effect(url, timeout=10):
            if "api.ipify.org" in url and "api64" not in url:
                raise ConnectionError("primary down")
            if "api64" in url:
                raise ConnectionError("ipv6 unavailable")
            if "icanhazip.com" in url:
                resp = MagicMock()
                resp.text = "198.51.100.1"
                resp.raise_for_status = MagicMock()
                return resp
            raise ConnectionError("unreachable")

        mock_get.side_effect = side_effect

        result = adapter.execute({})

        assert result.status == AdapterResultStatus.SUCCESS
        assert result.data["ipv4"] == "198.51.100.1"
        assert any("icanhazip" in s for s in result.data["services_used"])
