"""
Tests for prerequisite verification functionality.
"""
import pytest
import sys
from unittest.mock import patch, MagicMock

# Add src to path for imports
sys.path.insert(0, 'src')

from agent.cli import verify_prerequisites

class TestPrerequisites:
    """Test suite for prerequisite verification."""
    
    def test_verify_prerequisites_docker_success(self):
        """Test Docker verification success."""
        with patch('docker.from_env') as mock_docker:
            mock_client = MagicMock()
            mock_client.ping.return_value = True
            mock_docker.return_value = mock_client
            
            with patch('requests.get') as mock_get:
                mock_response = MagicMock()
                mock_response.status_code = 200
                mock_get.return_value = mock_response
                
                with patch('pathlib.Path.mkdir'):
                    with patch('pathlib.Path.write_text'):
                        with patch('pathlib.Path.unlink'):
                            with patch('typer.echo'):  # Mock echo to avoid output
                                result = verify_prerequisites()
                                # Should return True when Docker works
                                assert result is True
    
    def test_verify_prerequisites_docker_failure(self):
        """Test Docker verification failure."""
        with patch('docker.from_env', side_effect=Exception("Docker not available")):
            with patch('requests.get') as mock_get:
                mock_response = MagicMock()
                mock_response.status_code = 200
                mock_get.return_value = mock_response
                
                with patch('pathlib.Path.mkdir'):
                    with patch('pathlib.Path.write_text'):
                        with patch('pathlib.Path.unlink'):
                            with patch('typer.echo'):  # Mock echo to avoid output
                                result = verify_prerequisites()
                                # Should return False when Docker fails
                                assert result is False
    
    def test_verify_prerequisites_llm_success(self):
        """Test LLM verification success."""
        with patch('docker.from_env') as mock_docker:
            mock_client = MagicMock()
            mock_client.ping.return_value = True
            mock_docker.return_value = mock_client
            
            with patch('requests.get') as mock_get:
                mock_response = MagicMock()
                mock_response.status_code = 200
                mock_get.return_value = mock_response
                
                with patch('pathlib.Path.mkdir'):
                    with patch('pathlib.Path.write_text'):
                        with patch('pathlib.Path.unlink'):
                            with patch('typer.echo'):  # Mock echo to avoid output
                                result = verify_prerequisites()
                                # Should return True when LLM works
                                assert result is True
    
    def test_verify_prerequisites_llm_failure(self):
        """Test LLM verification failure."""
        with patch('docker.from_env') as mock_docker:
            mock_client = MagicMock()
            mock_client.ping.return_value = True
            mock_docker.return_value = mock_client
            
            with patch('requests.get', side_effect=Exception("LLM not available")):
                with patch('pathlib.Path.mkdir'):
                    with patch('pathlib.Path.write_text'):
                        with patch('pathlib.Path.unlink'):
                            with patch('typer.echo'):  # Mock echo to avoid output
                                result = verify_prerequisites()
                                # Should still return True (LLM failure is warning, not error)
                                assert result is True
    
    def test_verify_prerequisites_file_permission_failure(self):
        """Test file permission verification failure."""
        with patch('docker.from_env') as mock_docker:
            mock_client = MagicMock()
            mock_client.ping.return_value = True
            mock_docker.return_value = mock_client
            
            with patch('requests.get') as mock_get:
                mock_response = MagicMock()
                mock_response.status_code = 200
                mock_get.return_value = mock_response
                
                with patch('pathlib.Path.mkdir', side_effect=Exception("Permission denied")):
                    with patch('typer.echo'):  # Mock echo to avoid output
                        result = verify_prerequisites()
                        # Should return False when file permissions fail
                        assert result is False
    
    def test_verify_prerequisites_all_success(self):
        """Test all prerequisites passing."""
        with patch('docker.from_env') as mock_docker:
            mock_client = MagicMock()
            mock_client.ping.return_value = True
            mock_docker.return_value = mock_client
            
            with patch('requests.get') as mock_get:
                mock_response = MagicMock()
                mock_response.status_code = 200
                mock_get.return_value = mock_response
                
                with patch('pathlib.Path.mkdir'):
                    with patch('pathlib.Path.write_text'):
                        with patch('pathlib.Path.unlink'):
                            with patch('typer.echo'):  # Mock echo to avoid output
                                result = verify_prerequisites()
                                # Should return True when all prerequisites pass
                                assert result is True

if __name__ == "__main__":
    pytest.main([__file__])
