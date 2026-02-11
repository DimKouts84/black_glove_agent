
import pytest
from unittest.mock import MagicMock, patch, call
from src.adapters.interface import AdapterResultStatus
from src.adapters.credential_tester import CredentialTesterAdapter, create_credential_tester_adapter

class TestCredentialTesterAdapter:

    @pytest.fixture
    def adapter(self):
        return create_credential_tester_adapter()

    def test_validate_params(self, adapter):
        # Missing target
        with pytest.raises(ValueError):
            adapter.validate_params({"protocol": "ssh", "usernames": ["u"], "passwords": ["p"]})
            
        # Missing protocol
        with pytest.raises(ValueError):
            adapter.validate_params({"target": "host", "usernames": ["u"], "passwords": ["p"]})
            
        # Invalid protocol
        with pytest.raises(ValueError):
            adapter.validate_params({"target": "host", "protocol": "telnet", "usernames": ["u"], "passwords": ["p"]})

        # Success
        adapter.validate_params({
            "target": "host", 
            "protocol": "ssh", 
            "usernames": ["root"], 
            "passwords": ["toor"]
        })

    @patch("src.adapters.credential_tester.requests.get")
    def test_http_basic_success(self, mock_get, adapter):
        # Mock successful auth
        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_get.return_value = mock_resp
        
        result = adapter.execute({
            "target": "http://example.com",
            "protocol": "http_basic",
            "usernames": ["admin"],
            "passwords": ["admin123"]
        })
        
        assert result.status == AdapterResultStatus.SUCCESS
        creds = result.data["valid_credentials"]
        assert len(creds) == 1
        assert creds[0] == {"username": "admin", "password": "admin123"}
        
    @patch("src.adapters.credential_tester.requests.get")
    def test_http_basic_failure(self, mock_get, adapter):
        # Mock failed auth
        mock_resp = MagicMock()
        mock_resp.status_code = 401
        mock_get.return_value = mock_resp
        
        result = adapter.execute({
            "target": "http://example.com",
            "protocol": "http_basic",
            "usernames": ["admin"],
            "passwords": ["wrong"]
        })
        
        assert result.status == AdapterResultStatus.SUCCESS
        creds = result.data["valid_credentials"]
        assert len(creds) == 0

    @patch("src.adapters.credential_tester.paramiko.SSHClient")
    def test_ssh_success(self, mock_ssh_client_cls, adapter):
        # Mock SSH client
        mock_client = MagicMock()
        mock_ssh_client_cls.return_value = mock_client
        
        # Connect succeeds (no exception raised)
        mock_client.connect.return_value = None
        
        result = adapter.execute({
            "target": "192.168.1.1",
            "protocol": "ssh",
            "usernames": ["root"],
            "passwords": ["toor"]
        })
        
        assert result.status == AdapterResultStatus.SUCCESS
        creds = result.data["valid_credentials"]
        assert len(creds) == 1
        assert creds[0] == {"username": "root", "password": "toor"}

    @patch("src.adapters.credential_tester.ftplib.FTP")
    def test_ftp_success(self, mock_ftp_cls, adapter):
        # Mock FTP
        mock_ftp = MagicMock()
        mock_ftp_cls.return_value = mock_ftp
        
        # Login succeeds
        mock_ftp.login.return_value = "230 Login successful."
        
        result = adapter.execute({
            "target": "ftp.example.com",
            "protocol": "ftp",
            "usernames": ["anonymous"],
            "passwords": ["test@test.com"]
        })
        
        assert result.status == AdapterResultStatus.SUCCESS
        creds = result.data["valid_credentials"]
        assert len(creds) == 1
        assert creds[0] == {"username": "anonymous", "password": "test@test.com"}
