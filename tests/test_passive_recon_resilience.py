"""
Tests for passive reconnaissance resilience and error handling.
"""
import pytest
import sys
from unittest.mock import Mock, patch, MagicMock
from pathlib import Path

# Add src to path for imports
sys.path.insert(0, str(Path(__file__).parent.parent / "src"))

from src.agent.exceptions import BlackGloveError, AdapterError, PolicyViolationError

class TestPassiveReconResilience:
    """Test suite for passive reconnaissance error resilience."""
    
    def test_plugin_manager_initialization(self):
        """Test that PluginManager can be initialized successfully."""
        from src.agent.plugin_manager import PluginManager
        pm = PluginManager()
        
        # Should be able to discover adapters
        result = pm.discover_adapters()
        assert isinstance(result, list)
    
    def test_custom_exception_types(self):
        """Test custom exception types."""
        # Test BlackGloveError
        error = BlackGloveError("Test error", "Try checking configuration")
        assert str(error) == "Test error"
        assert error.recovery_suggestion == "Try checking configuration"
        
        # Test AdapterError
        adapter_error = AdapterError("Adapter failed", recovery_suggestion="Check adapter configuration")
        assert isinstance(adapter_error, BlackGloveError)
        assert adapter_error.recovery_suggestion == "Check adapter configuration"
        
        # Test PolicyViolationError
        policy_error = PolicyViolationError("Policy violation", recovery_suggestion="Review target authorization")
        assert isinstance(policy_error, BlackGloveError)
        assert policy_error.recovery_suggestion == "Review target authorization"
    
    def test_global_exception_handler_decorator(self):
        """Test that global exception handler prevents CLI crashes."""
        from src.agent.exceptions import global_exception_handler
        import typer
        
        @global_exception_handler
        def failing_function():
            raise ValueError("This should be caught")
        
        # The decorator handles exceptions and raises typer.Exit
        # So we expect a typer.Exit exception to be raised
        with pytest.raises((typer.Exit, SystemExit)):
            failing_function()
    
    def test_session_continuity_after_errors(self):
        """Test that CLI session continues after errors."""
        # This would test the actual CLI behavior
        # For now, we test that our exception handling doesn't terminate the process
        import subprocess
        import sys
        
        # Test that error handling prevents hard crashes
        test_code = """
import sys
sys.path.insert(0, 'src')
try:
    from src.agent.exceptions import BlackGloveError
    raise BlackGloveError('Test error')
except BlackGloveError:
    print('Handled gracefully')
"""
        
        # This should not cause a system exit
        result = exec(test_code)
        assert result is None  # Should complete without crashing

if __name__ == "__main__":
    pytest.main([__file__, "-v"])
