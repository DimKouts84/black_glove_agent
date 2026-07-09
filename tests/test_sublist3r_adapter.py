import pytest
from unittest.mock import patch, MagicMock
import src.adapters.sublist3r as sublist3r_module

from src.adapters.sublist3r import Sublist3rAdapter
from src.adapters.interface import AdapterResultStatus


class TestSublist3rAdapter:
    def test_target_alias(self):
        with patch("src.adapters.sublist3r.sublist3r", MagicMock()):
            adapter = Sublist3rAdapter({})
            params = {"target": "example.com"}
            adapter.validate_params(params)
            assert params["domain"] == "example.com"

    @patch("src.adapters.sublist3r.sublist3r")
    def test_execute_flat_list_and_max_results(self, mock_sublist3r, tmp_path):
        mock_sublist3r.main.return_value = [
            "www.example.com",
            "dev.example.com",
            "www.example.com",
            "not-in-zone.com",
        ]

        adapter = Sublist3rAdapter({})
        adapter._store_evidence = lambda data, name: str(tmp_path / name)

        result = adapter.execute({"domain": "example.com", "max_results": 1})

        assert result.status == AdapterResultStatus.SUCCESS
        assert result.data["count"] == 1
        assert len(result.data["subdomains"]) == 1
        assert result.data["subdomains"][0].endswith("example.com")

    @patch("src.adapters.sublist3r.sublist3r")
    def test_execute_dict_per_engine_format(self, mock_sublist3r, tmp_path):
        mock_sublist3r.main.return_value = [
            {"google": ["api.example.com"]},
        ]

        adapter = Sublist3rAdapter({})
        adapter._store_evidence = lambda data, name: str(tmp_path / name)

        result = adapter.execute({"domain": "example.com"})
        assert "api.example.com" in result.data["subdomains"]

    def test_import_guard_validate_config(self):
        with patch.object(sublist3r_module, "sublist3r", None):
            adapter = Sublist3rAdapter({})
            with pytest.raises(ValueError, match="not installed"):
                adapter.validate_config()

    @patch("src.adapters.sublist3r.sublist3r", None)
    def test_execute_when_not_installed(self):
        adapter = Sublist3rAdapter({})
        with pytest.raises(ValueError, match="not installed"):
            adapter.validate_params({"domain": "example.com"})

    @patch("src.adapters.sublist3r.sublist3r")
    def test_threads_from_config(self, mock_sublist3r, tmp_path):
        mock_sublist3r.main.return_value = ["www.example.com"]

        adapter = Sublist3rAdapter({"threads": 20})
        adapter._store_evidence = lambda data, name: str(tmp_path / name)

        adapter.execute({"domain": "example.com"})

        assert mock_sublist3r.main.call_args[0][1] == 20
