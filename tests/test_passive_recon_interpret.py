import pytest
from src.adapters.interface import AdapterResult, AdapterResultStatus
from src.adapters.passive_recon import create_passive_recon_adapter


class TestPassiveReconInterpretResult:
    @pytest.fixture
    def adapter(self):
        return create_passive_recon_adapter()

    def test_interpret_partial_with_data(self, adapter):
        result = AdapterResult(
            status=AdapterResultStatus.PARTIAL,
            data={
                "domain": "example.com",
                "crt_sh": {
                    "certificates": [{"name_value": ["www.example.com", "api.example.com"]}],
                    "count": 1,
                },
                "wayback": {"snapshots": [{"url": "http://example.com/"}], "count": 1},
                "potential_secrets": [],
                "errors": {"wayback": "timeout"},
            },
            metadata={},
        )

        text = adapter.interpret_result(result)
        assert "partially completed" in text
        assert "1 certificates" in text
        assert "timeout" in text

    def test_interpret_secrets_use_severity_not_blanket_critical(self, adapter):
        result = AdapterResult(
            status=AdapterResultStatus.SUCCESS,
            data={
                "domain": "example.com",
                "crt_sh": {"certificates": [], "count": 0},
                "wayback": {"snapshots": [], "count": 0},
                "potential_secrets": [
                    {
                        "type": "sensitive_keyword",
                        "match": "key=",
                        "url": "http://example.com/x",
                        "severity": "low",
                        "confidence": 0.45,
                    }
                ],
                "errors": {},
            },
            metadata={},
        )

        text = adapter.interpret_result(result)
        assert "[LOW]" in text
        assert "[CRITICAL]" not in text

    def test_scan_for_secrets_ignores_benign_json_url(self, adapter):
        snapshots = [{"url": "http://example.com/static/app.json", "timestamp": "20200101"}]
        secrets = adapter._scan_for_secrets(snapshots)
        assert len(secrets) == 0

    def test_scan_for_secrets_finds_env_path(self, adapter):
        snapshots = [{"url": "http://example.com/.env", "timestamp": "20200101"}]
        secrets = adapter._scan_for_secrets(snapshots)
        assert len(secrets) == 1
        assert secrets[0]["severity"] == "high"
