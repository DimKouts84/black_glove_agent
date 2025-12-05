"""
Unit tests for Camera Security Adapter

Tests all security check functionality with mocked network responses.
"""

import pytest
import socket
from unittest.mock import Mock, patch, MagicMock
from typing import Dict, Any

from src.adapters.camera_security import CameraSecurityAdapter
from src.adapters.interface import AdapterResultStatus


class TestCameraSecurityAdapter:
    """Test suite for CameraSecurityAdapter."""
    
    @pytest.fixture
    def basic_config(self) -> Dict[str, Any]:
        """Basic adapter configuration."""
        return {
            "timeout": 3,
            "test_credentials": True,
            "max_credential_tests": 3
        }
    
    @pytest.fixture
    def adapter(self, basic_config):
        """Create a camera security adapter instance."""
        return CameraSecurityAdapter(basic_config)
    
    def test_adapter_initialization(self, adapter):
        """Test adapter initializes correctly."""
        assert adapter.version == "1.1.0"
        assert adapter.timeout == 3
        assert adapter.test_credentials is True
        assert adapter.max_credential_tests == 3
    
    def test_validate_config_valid(self, basic_config):
        """Test configuration validation with valid config."""
        adapter = CameraSecurityAdapter(basic_config)
        assert adapter.validate_config() is True
    
    def test_validate_config_invalid_timeout(self):
        """Test configuration validation with invalid timeout."""
        config = {"timeout": -1}
        adapter = CameraSecurityAdapter(config)
        with pytest.raises(ValueError, match="Timeout must be a positive number"):
            adapter.validate_config()
    
    def test_validate_config_invalid_test_credentials(self):
        """Test configuration validation with invalid test_credentials."""
        config = {"test_credentials": "yes"}
        adapter = CameraSecurityAdapter(config)
        with pytest.raises(ValueError, match="test_credentials must be a boolean"):
            adapter.validate_config()
    
    def test_validate_config_invalid_max_credential_tests(self):
        """Test configuration validation with invalid max_credential_tests."""
        config = {"max_credential_tests": 0}
        adapter = CameraSecurityAdapter(config)
        with pytest.raises(ValueError, match="max_credential_tests must be a positive integer"):
            adapter.validate_config()
    
    def test_validate_params_valid(self, adapter):
        """Test parameter validation with valid params."""
        params = {"target": "192.168.1.100"}
        assert adapter.validate_params(params) is True
    
    def test_validate_params_missing_target(self, adapter):
        """Test parameter validation with missing target."""
        params = {}
        with pytest.raises(ValueError, match="Missing required parameters"):
            adapter.validate_params(params)
    
    def test_validate_params_invalid_target_format(self, adapter):
        """Test parameter validation with invalid target format."""
        params = {"target": "192.168.1.100; rm -rf /"}
        with pytest.raises(ValueError, match="Invalid target format"):
            adapter.validate_params(params)
    
    @patch('src.adapters.camera_security.socket.socket')
    def test_scan_ports_all_closed(self, mock_socket_class, adapter):
        """Test port scanning when all ports are closed."""
        # Mock socket to simulate closed ports
        mock_socket = Mock()
        mock_socket.connect_ex.return_value = 1  # Connection refused
        mock_socket_class.return_value = mock_socket
        
        result = adapter._scan_ports("192.168.1.100")
        
        assert result == []
        assert mock_socket.close.called
    
    @patch('src.adapters.camera_security.socket.socket')
    def test_scan_ports_some_open(self, mock_socket_class, adapter):
        """Test port scanning when some ports are open."""
        # Mock socket to simulate open ports 80 and 554
        mock_socket = Mock()
        
        def connect_side_effect(addr):
            port = addr[1]
            if port in [80, 554]:
                return 0  # Success
            return 1  # Refused
        
        mock_socket.connect_ex.side_effect = connect_side_effect
        mock_socket_class.return_value = mock_socket
        
        result = adapter._scan_ports("192.168.1.100")
        
        assert 80 in result
        assert 554 in result
        assert len(result) == 2
    
    @patch('src.adapters.camera_security.socket.socket')
    def test_scan_ports_hostname_resolution_error(self, mock_socket_class, adapter):
        """Test port scanning with hostname resolution error."""
        mock_socket = Mock()
        mock_socket.connect_ex.side_effect = socket.gaierror("Name or service not known")
        mock_socket_class.return_value = mock_socket
        
        result = adapter._scan_ports("invalid.hostname.local")
        
        assert result == []
    
    @patch('src.adapters.camera_security.socket.socket')
    def test_rtsp_anonymous_access_vulnerable(self, mock_socket_class, adapter):
        """Test RTSP anonymous access detection - vulnerable case."""
        mock_socket = Mock()
        mock_socket.recv.return_value = b"RTSP/1.0 200 OK\r\nCSeq: 1\r\n\r\n"
        mock_socket_class.return_value = mock_socket
        
        result = adapter._test_rtsp_anonymous("192.168.1.100")
        
        assert result is not None
        assert "Anonymous RTSP stream accessible" in result
        assert "rtsp://192.168.1.100:554" in result
    
    @patch('src.adapters.camera_security.socket.socket')
    def test_rtsp_anonymous_access_secure(self, mock_socket_class, adapter):
        """Test RTSP anonymous access detection - secure case."""
        mock_socket = Mock()
        mock_socket.recv.return_value = b"RTSP/1.0 401 Unauthorized\r\nCSeq: 1\r\n\r\n"
        mock_socket_class.return_value = mock_socket
        
        result = adapter._test_rtsp_anonymous("192.168.1.100")
        
        assert result is None
    
    @patch('src.adapters.camera_security.socket.socket')
    def test_rtsp_anonymous_timeout(self, mock_socket_class, adapter):
        """Test RTSP anonymous access with timeout."""
        mock_socket = Mock()
        mock_socket.recv.side_effect = socket.timeout("Connection timed out")
        mock_socket_class.return_value = mock_socket
        
        result = adapter._test_rtsp_anonymous("192.168.1.100")
        
        assert result is None
    
    @patch('src.adapters.camera_security.socket.socket')
    def test_http_auth_no_auth_required_camera(self, mock_socket_class, adapter):
        """Test HTTP auth check - camera interface without auth."""
        mock_socket = Mock()
        mock_socket.recv.return_value = b"HTTP/1.1 200 OK\r\nContent-Type: text/html\r\n\r\n<html><body>IP Camera Web Interface</body></html>"
        mock_socket_class.return_value = mock_socket
        
        result = adapter._test_http_auth("192.168.1.100", 80)
        
        assert result is not None
        assert "HTTP VULNERABILITY" in result
        assert "without authentication" in result
    
    @patch('src.adapters.camera_security.socket.socket')
    def test_http_auth_required(self, mock_socket_class, adapter):
        """Test HTTP auth check - authentication required."""
        mock_socket = Mock()
        mock_socket.recv.return_value = b"HTTP/1.1 401 Unauthorized\r\nWWW-Authenticate: Basic realm=\"Camera\"\r\n\r\n"
        mock_socket_class.return_value = mock_socket
        
        result = adapter._test_http_auth("192.168.1.100", 80)
        
        assert result is not None
        assert "requires authentication" in result
    
    @patch('src.adapters.camera_security.socket.socket')
    def test_http_auth_forbidden(self, mock_socket_class, adapter):
        """Test HTTP auth check - forbidden response."""
        mock_socket = Mock()
        mock_socket.recv.return_value = b"HTTP/1.1 403 Forbidden\r\n\r\n"
        mock_socket_class.return_value = mock_socket
        
        result = adapter._test_http_auth("192.168.1.100", 80)
        
        assert result is not None
        assert "requires authentication" in result
    
    @patch('src.adapters.camera_security.socket.socket')
    def test_default_credentials_found(self, mock_socket_class, adapter):
        """Test default credential testing - credentials found."""
        mock_socket = Mock()
        # First attempt fails, second succeeds
        mock_socket.recv.side_effect = [
            b"HTTP/1.1 401 Unauthorized\r\n\r\n",
            b"HTTP/1.1 200 OK\r\n\r\nLogged in"
        ]
        mock_socket_class.return_value = mock_socket
        
        result = adapter._test_default_credentials("192.168.1.100", [80])
        
        assert len(result) > 0
        assert any("CRITICAL VULNERABILITY" in r for r in result)
        assert any("Default credentials work" in r for r in result)
    
    @patch('src.adapters.camera_security.socket.socket')
    def test_default_credentials_not_found(self, mock_socket_class, adapter):
        """Test default credential testing - no credentials found."""
        mock_socket = Mock()
        mock_socket.recv.return_value = b"HTTP/1.1 401 Unauthorized\r\n\r\n"
        mock_socket_class.return_value = mock_socket
        
        result = adapter._test_default_credentials("192.168.1.100", [80])
        
        assert len(result) > 0
        assert any("Default credentials tested" in r for r in result)
        assert any("none successful" in r for r in result)
    
    @patch.object(CameraSecurityAdapter, '_scan_ports')
    def test_execute_no_open_ports(self, mock_scan_ports, adapter):
        """Test execute with no open ports."""
        mock_scan_ports.return_value = []
        
        params = {"target": "192.168.1.100"}
        result = adapter.execute(params)
        
        assert result.status == AdapterResultStatus.SUCCESS
        assert result.data["target"] == "192.168.1.100"
        assert result.data["open_ports"] == []
        assert "No common camera ports are open" in result.data["findings"]
    
    @patch.object(CameraSecurityAdapter, '_scan_ports')
    @patch.object(CameraSecurityAdapter, '_test_rtsp_anonymous')
    @patch.object(CameraSecurityAdapter, '_test_http_auth')
    @patch.object(CameraSecurityAdapter, '_test_default_credentials')
    def test_execute_with_vulnerabilities(self, mock_creds, mock_http, mock_rtsp, mock_scan, adapter):
        """Test execute with detected vulnerabilities."""
        mock_scan.return_value = [80, 554]
        mock_rtsp.return_value = "Anonymous RTSP stream accessible at rtsp://192.168.1.100:554/"
        mock_http.return_value = "⚠️ HTTP VULNERABILITY: Camera web interface on port 80 accessible without authentication"
        mock_creds.return_value = ["🔴 CRITICAL VULNERABILITY: Default credentials work! admin:admin on port 80"]
        
        params = {"target": "192.168.1.100"}
        result = adapter.execute(params)
        
        assert result.status == AdapterResultStatus.SUCCESS
        assert result.data["vulnerabilities_detected"] is True
        assert len(result.data["open_ports"]) == 2
        assert any("RTSP VULNERABILITY" in f for f in result.data["findings"])
        assert any("HTTP VULNERABILITY" in f for f in result.data["findings"])
        assert any("CRITICAL VULNERABILITY" in f for f in result.data["findings"])
    
    @patch.object(CameraSecurityAdapter, '_scan_ports')
    @patch.object(CameraSecurityAdapter, '_test_rtsp_anonymous')
    @patch.object(CameraSecurityAdapter, '_test_http_auth')
    @patch.object(CameraSecurityAdapter, '_test_default_credentials')
    def test_execute_secure_camera(self, mock_creds, mock_http, mock_rtsp, mock_scan, adapter):
        """Test execute with secure camera configuration."""
        mock_scan.return_value = [80, 554]
        mock_rtsp.return_value = None
        mock_http.return_value = "✓ HTTP interface on port 80 requires authentication"
        mock_creds.return_value = ["✓ Default credentials tested (3 attempts) - none successful"]
        
        params = {"target": "192.168.1.100"}
        result = adapter.execute(params)
        
        assert result.status == AdapterResultStatus.SUCCESS
        assert result.data["vulnerabilities_detected"] is False
        assert len(result.data["open_ports"]) == 2
    
    @patch.object(CameraSecurityAdapter, '_scan_ports')
    def test_execute_with_error(self, mock_scan_ports, adapter):
        """Test execute with exception."""
        mock_scan_ports.side_effect = Exception("Network error")
        
        params = {"target": "192.168.1.100"}
        result = adapter.execute(params)
        
        assert result.status == AdapterResultStatus.ERROR
        assert "error" in result.data
        assert "Network error" in result.data["error"]
    
    def test_get_info(self, adapter):
        """Test adapter info retrieval."""
        info = adapter.get_info()
        
        assert info["name"] == "camera_security"
        assert info["version"] == "1.1.0"
        assert "camera" in info["description"].lower()
        assert "target" in info["required_params"]
        assert "Port scanning" in info["capabilities"][0]
        assert len(info["ports_checked"]) > 0
        assert "supported_vendors" in info
    
    def test_adapter_ports_coverage(self, adapter):
        """Test that common camera ports are included."""
        ports = adapter.CAMERA_PORTS
        
        # Verify critical camera ports are present
        assert 80 in ports  # HTTP
        assert 443 in ports  # HTTPS
        assert 554 in ports  # RTSP
        assert 8080 in ports  # HTTP-Alt
        assert 37777 in ports  # Dahua
        assert 8000 in ports  # Hikvision
        assert 34567 in ports  # Xiongmai
        assert len(ports) >= 22  # Enhanced with 22 vendor-specific ports
    
    def test_default_credentials_list(self, adapter):
        """Test that common default credentials are included."""
        creds = adapter.DEFAULT_CREDENTIALS
        
        # Verify common defaults are present
        assert ("admin", "admin") in creds
        assert ("admin", "") in creds
        assert ("admin", "12345") in creds
        assert ("root", "root") in creds
        assert len(creds) >= 5  # At least 5 credential pairs
    
    def test_execute_invalid_params(self, adapter):
        """Test execute with invalid parameters."""
        params = {"target": "192.168.1.100; echo hacked"}
        
        with pytest.raises(ValueError, match="Invalid target format"):
            adapter.execute(params)
    
    def test_config_with_disabled_credential_testing(self):
        """Test adapter with credential testing disabled."""
        config = {"test_credentials": False}
        adapter = CameraSecurityAdapter(config)
        
        assert adapter.test_credentials is False
    
    @patch.object(CameraSecurityAdapter, '_scan_ports')
    @patch.object(CameraSecurityAdapter, '_test_http_auth')
    def test_execute_no_credential_testing_when_disabled(self, mock_http, mock_scan, basic_config):
        """Test that credential testing is skipped when disabled."""
        basic_config["test_credentials"] = False
        adapter = CameraSecurityAdapter(basic_config)
        
        mock_scan.return_value = [80]
        mock_http.return_value = "✓ HTTP interface on port 80 requires authentication"
        
        params = {"target": "192.168.1.100"}
        result = adapter.execute(params)
        
        assert result.status == AdapterResultStatus.SUCCESS
        # Verify checks_performed doesn't include default_creds
        assert "default_creds" not in result.metadata["checks_performed"]


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
