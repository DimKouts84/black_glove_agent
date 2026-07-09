import pytest
from unittest.mock import MagicMock, patch
from src.adapters.interface import AdapterResultStatus
from src.adapters.credential_tester import create_credential_tester_adapter


class TestCredentialTesterAdapter:

    @pytest.fixture
    def adapter(self):
        return create_credential_tester_adapter()

    def test_validate_params(self, adapter, monkeypatch):
        monkeypatch.setattr("src.adapters.credential_tester.paramiko", MagicMock())

        with pytest.raises(ValueError):
            adapter.validate_params({"protocol": "ssh", "usernames": ["u"], "passwords": ["p"]})

        with pytest.raises(ValueError):
            adapter.validate_params({"target": "host", "usernames": ["u"], "passwords": ["p"]})

        with pytest.raises(ValueError):
            adapter.validate_params({"target": "host", "protocol": "telnet", "usernames": ["u"], "passwords": ["p"]})

        adapter.validate_params({
            "target": "host",
            "protocol": "ssh",
            "usernames": ["root"],
            "passwords": ["toor"],
        })

    def _basic_challenge_response(self, body: str = "Unauthorized") -> MagicMock:
        resp = MagicMock()
        resp.status_code = 401
        resp.headers = {"WWW-Authenticate": 'Basic realm="test"'}
        resp.text = body
        return resp

    @patch("src.adapters.credential_tester.requests.get")
    def test_http_basic_success(self, mock_get, adapter):
        precheck = self._basic_challenge_response()
        unauth = self._basic_challenge_response()
        auth_ok = MagicMock()
        auth_ok.status_code = 200
        auth_ok.text = "Welcome admin"
        mock_get.side_effect = [precheck, unauth, auth_ok]

        result = adapter.execute({
            "target": "http://example.com",
            "protocol": "http_basic",
            "usernames": ["admin"],
            "passwords": ["admin123"],
        })

        assert result.status == AdapterResultStatus.SUCCESS
        creds = result.data["valid_credentials"]
        assert len(creds) == 1
        assert creds[0] == {"username": "admin", "password": "admin123"}

    @patch("src.adapters.credential_tester.requests.get")
    def test_http_basic_failure(self, mock_get, adapter):
        precheck = self._basic_challenge_response()
        unauth = self._basic_challenge_response()
        auth_fail = MagicMock()
        auth_fail.status_code = 401
        auth_fail.text = "Unauthorized"
        mock_get.side_effect = [precheck, unauth, auth_fail]

        result = adapter.execute({
            "target": "http://example.com",
            "protocol": "http_basic",
            "usernames": ["admin"],
            "passwords": ["wrong"],
        })

        assert result.status == AdapterResultStatus.SUCCESS
        assert result.data["valid_credentials"] == []

    @patch("src.adapters.credential_tester.requests.get")
    def test_http_basic_public_page_skipped(self, mock_get, adapter):
        public_page = MagicMock()
        public_page.status_code = 200
        public_page.headers = {}
        public_page.text = "Hello world"
        mock_get.return_value = public_page

        result = adapter.execute({
            "target": "http://example.com",
            "protocol": "http_basic",
            "usernames": ["admin"],
            "passwords": ["admin123"],
        })

        assert result.status == AdapterResultStatus.SUCCESS
        assert result.data["valid_credentials"] == []
        assert result.data["attempts"] == 0
        assert "note" in result.data
        assert "does not require HTTP Basic" in result.data["note"]
        assert mock_get.call_count == 1

    @patch("src.adapters.credential_tester.paramiko")
    def test_ssh_success(self, mock_paramiko, adapter):
        mock_client = MagicMock()
        mock_paramiko.SSHClient.return_value = mock_client
        mock_client.connect.return_value = None

        result = adapter.execute({
            "target": "192.168.1.1",
            "protocol": "ssh",
            "usernames": ["root"],
            "passwords": ["toor"],
        })

        assert result.status == AdapterResultStatus.SUCCESS
        creds = result.data["valid_credentials"]
        assert len(creds) == 1
        assert creds[0] == {"username": "root", "password": "toor"}

    @patch("src.adapters.credential_tester.ftplib.FTP")
    def test_ftp_success(self, mock_ftp_cls, adapter):
        mock_ftp = MagicMock()
        mock_ftp_cls.return_value = mock_ftp
        mock_ftp.login.return_value = "230 Login successful."

        result = adapter.execute({
            "target": "ftp.example.com",
            "protocol": "ftp",
            "usernames": ["anonymous"],
            "passwords": ["test@test.com"],
        })

        assert result.status == AdapterResultStatus.SUCCESS
        creds = result.data["valid_credentials"]
        assert len(creds) == 1
        assert creds[0] == {"username": "anonymous", "password": "test@test.com"}
