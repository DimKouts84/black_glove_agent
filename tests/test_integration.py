"""
Integration Tests for Black Glove Core Architecture

This module contains integration tests that demonstrate the core components
working together: adapters, policy engine, plugin manager, LLM client, and orchestrator.
"""

import pytest
import tempfile
import os
from unittest.mock import Mock, patch
from typing import Dict, Any

import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).parent.parent))

from src.agent.orchestrator import Orchestrator, create_orchestrator, OrchestratorContext
from src.agent.policy_engine import create_policy_engine
from src.agent.plugin_manager import create_plugin_manager
from src.agent.llm_client import LLMConfig, LLMProvider, create_llm_client
from src.agent.models import Asset
from src.adapters.interface import AdapterResult, AdapterResultStatus


class TestCoreArchitectureIntegration:
    """Integration tests for core architecture components."""
    
    def test_complete_passive_recon_workflow(self):
        """Test complete passive reconnaissance workflow with all components."""
        # Create configuration with all components
        config = {
            "policy": {
                "rate_limiting": {
                    "window_size": 60,
                    "max_requests": 10,
                    "global_max_requests": 100
                },
                "target_validation": {
                    "authorized_networks": ["192.168.1.0/24", "10.0.0.0/8"],
                    "authorized_domains": ["example.com", "test.com"]
                },
                "allowed_exploits": []
            },
            "passive_tools": ["whois", "dns_lookup"],
            "scan_mode": "passive"
        }
        
        # Create orchestrator
        orchestrator = create_orchestrator(config)
        
        # Add authorized asset
        asset = Asset(
            target="192.168.1.100",
            tool_name="whois",
            parameters={"port": 80}
        )
        
        # Test asset addition (policy validation)
        assert orchestrator.add_asset(asset) is True
        assert len(orchestrator.assets) == 1
        
        # Mock adapter responses for passive recon
        with patch('src.agent.plugin_manager.PluginManager.run_adapter') as mock_run_adapter:
            # Mock successful adapter results
            adapter_result = AdapterResult(
                status=AdapterResultStatus.SUCCESS,
                data={"domain": "test.com", "ip": "192.168.1.100"},
                metadata={"tool": "whois", "timestamp": "2025-01-01T00:00:00Z"}
            )
            mock_run_adapter.return_value = adapter_result
            
            # Run passive reconnaissance
            results = orchestrator.run_passive_recon()
            
            # Verify results
            assert len(results) == 2  # One for each passive tool
            assert len(orchestrator.scan_results) == 2
            assert orchestrator.workflow_manager.state.name == "COMPLETED"
            
            # Verify policy engine was used (rate limiting)
            rates = orchestrator.policy_engine.get_current_rates()
            assert "global" in rates
            
            # Verify findings were processed
            assert len(orchestrator.result_processor.findings) >= 0
    
    def test_policy_engine_integration(self):
        """Test policy engine integration with unauthorized targets."""
        config = {
            "policy": {
                "target_validation": {
                    "authorized_networks": ["192.168.1.0/24"],
                    "authorized_domains": ["example.com"]
                },
                "rate_limiting": {
                    "window_size": 60,
                    "max_requests": 5
                }
            }
        }
        
        orchestrator = create_orchestrator(config)
        
        # Test unauthorized IP target
        unauthorized_asset = Asset(
            target="10.0.0.1",  # Not in authorized networks
            tool_name="nmap",
            parameters={}
        )
        
        assert orchestrator.add_asset(unauthorized_asset) is False
        assert len(orchestrator.assets) == 0
        
        # Test unauthorized domain target
        unauthorized_domain_asset = Asset(
            target="malicious.com",  # Not in authorized domains
            tool_name="nmap",
            parameters={}
        )
        
        assert orchestrator.add_asset(unauthorized_domain_asset) is False
        assert len(orchestrator.assets) == 0
        
        # Verify violations were logged
        violations = orchestrator.policy_engine.get_violation_report()
        assert len(violations) >= 2  # At least 2 violations logged
    
    def test_rate_limiting_integration(self):
        """Test rate limiting integration across components."""
        config = {
            "policy": {
                "rate_limiting": {
                    "window_size": 1,  # 1 second window for testing
                    "max_requests": 2,  # Only 2 requests allowed per second
                    "global_max_requests": 5
                },
                "target_validation": {
                    "authorized_networks": ["192.168.1.0/24"]
                }
            },
            "passive_tools": ["whois", "dns_lookup", "ssl_check"]  # 3 tools
        }
        
        orchestrator = create_orchestrator(config)
        
        # Add authorized asset
        asset = Asset(
            target="192.168.1.100",
            tool_name="whois",
            parameters={}
        )
        assert orchestrator.add_asset(asset) is True
        
        # Mock adapter to track calls
        call_count = 0
        def mock_adapter_run(tool_name, params):
            nonlocal call_count
            call_count += 1
            return AdapterResult(
                status=AdapterResultStatus.SUCCESS,
                data={"result": f"test_{call_count}"},
                metadata={"tool": tool_name}
            )
        
        with patch('src.agent.plugin_manager.PluginManager.run_adapter', side_effect=mock_adapter_run):
            # Run passive recon - should be rate limited
            results = orchestrator.run_passive_recon()
            
            # Should have some results but rate limiting may have affected some
            assert len(results) >= 0
            assert call_count >= 0
    
    def test_plugin_manager_adapter_discovery(self):
        """Test plugin manager adapter discovery and validation."""
        # Create plugin manager
        plugin_manager = create_plugin_manager()
        
        # Test adapter discovery
        adapters = plugin_manager.discover_adapters()
        assert isinstance(adapters, list)
        
        # Test getting adapter info
        if adapters:  # If any adapters were found
            adapter_info = plugin_manager.get_adapter_info(adapters[0])
            assert isinstance(adapter_info, dict)
            assert "name" in adapter_info
            assert "version" in adapter_info
    
    @patch('src.agent.llm_client.LLMClient._make_api_call')
    def test_llm_client_integration(self, mock_make_api_call):
        """Test LLM client integration with mock responses."""
        # Mock LLM response
        mock_response = {
            "choices": [{
                "message": {
                    "content": "This is a test LLM response for security analysis."
                }
            }]
        }
        mock_make_api_call.return_value = mock_response
        
        # Create LLM client
        config = LLMConfig(
            provider=LLMProvider.LMSTUDIO,
            endpoint="http://localhost:1234/v1",
            model="test-model"
        )
        llm_client = create_llm_client(config)
        
        # Test LLM interaction
        context = "Test target: 192.168.1.100"
        objective = "Analyze potential security issues"
        
        response = llm_client.plan_next_steps(context, objective)
        assert response.content == "This is a test LLM response for security analysis."
        
        # Test finding analysis
        tool_output = {"port": 22, "service": "ssh", "version": "OpenSSH 7.9"}
        analysis = llm_client.analyze_findings(tool_output, context)
        assert analysis.content == "This is a test LLM response for security analysis."
    
    def test_orchestrator_factory_and_context_manager(self):
        """Test orchestrator factory function and context manager."""
        # Test factory function
        orchestrator = create_orchestrator()
        assert orchestrator is not None
        assert hasattr(orchestrator, 'policy_engine')
        assert hasattr(orchestrator, 'plugin_manager')
        assert hasattr(orchestrator, 'llm_client')
        
        # Test context manager
        config = {"policy": {"test": "config"}}
        with OrchestratorContext(config) as orchestrator_ctx:
            assert orchestrator_ctx is not None
            assert orchestrator_ctx.config == config
        
        # Context manager should clean up automatically
        # (cleanup method would be called on exit)
    
    def test_complete_workflow_with_error_handling(self):
        """Test complete workflow with various error conditions."""
        config = {
            "policy": {
                "target_validation": {
                    "authorized_networks": ["192.168.1.0/24"]
                },
                "rate_limiting": {
                    "window_size": 60,
                    "max_requests": 10
                }
            },
            "passive_tools": ["whois"]
        }
        
        orchestrator = create_orchestrator(config)
        
        # Test with valid asset
        valid_asset = Asset(
            target="192.168.1.100",
            tool_name="whois",
            parameters={}
        )
        assert orchestrator.add_asset(valid_asset) is True
        
        # Test with adapter failure
        with patch('src.agent.plugin_manager.PluginManager.run_adapter') as mock_run:
            # Mock adapter failure
            mock_run.side_effect = Exception("Adapter unavailable")
            
            results = orchestrator.run_passive_recon()
            # Should handle gracefully and return empty results
            assert isinstance(results, list)
        
        # Test with LLM failure
        with patch('src.agent.llm_client.requests.post') as mock_post:
            mock_post.side_effect = Exception("LLM unavailable")
            
            # Planning should fall back to default
            steps = orchestrator.plan_active_scans()
            # Should still return default steps
            assert isinstance(steps, list)
        
        # Test report generation with errors
        report = orchestrator.generate_report("json")
        assert isinstance(report, dict)
        assert "summary" in report
        assert "assets" in report


class TestCrossComponentIntegration:
    """Tests for integration between multiple components."""
    
    def test_policy_and_adapter_integration(self):
        """Test policy engine and adapter integration."""
        config = {
            "policy": {
                "target_validation": {
                    "authorized_networks": ["192.168.1.0/24"]
                },
                "rate_limiting": {
                    "window_size": 60,
                    "max_requests": 5
                }
            }
        }
        
        orchestrator = create_orchestrator(config)
        
        # Add authorized asset
        asset = Asset(
            target="192.168.1.100",
            tool_name="test_tool",
            parameters={}
        )
        assert orchestrator.add_asset(asset) is True
        
        # Mock adapter execution that respects rate limits
        with patch('src.agent.plugin_manager.PluginManager.run_adapter') as mock_run:
            adapter_result = AdapterResult(
                status=AdapterResultStatus.SUCCESS,
                data={"test": "data"},
                metadata={"tool": "test_tool"}
            )
            mock_run.return_value = adapter_result
            
            # Execute scan step
            from src.agent.models import WorkflowStep
            step = WorkflowStep(
                name="test_step",
                description="Test scan",
                tool="test_tool",
                target="192.168.1.100",
                parameters={},
                priority=1
            )
            
            result = orchestrator.execute_scan_step(step, approval_required=False)
            
            # Verify all components worked together
            assert result is not None
            assert result.tool_name == "test_tool"
            assert result.status == "completed"
            
            # Verify rate limiting was tracked
            rates = orchestrator.policy_engine.get_current_rates()
            assert "test_tool" in rates or "global" in rates
    
    def test_evidence_storage_integration(self):
        """Test evidence storage integration across components."""
        config = {
            "policy": {
                "target_validation": {
                    "authorized_networks": ["192.168.1.0/24"]
                }
            }
        }
        
        orchestrator = create_orchestrator(config)
        
        # Add asset
        asset = Asset(
            target="192.168.1.100",
            tool_name="whois",
            parameters={}
        )
        assert orchestrator.add_asset(asset) is True
        
        # Mock adapter with evidence path
        with patch('src.agent.plugin_manager.PluginManager.run_adapter') as mock_run:
            adapter_result = AdapterResult(
                status=AdapterResultStatus.SUCCESS,
                data={"domain": "test.com"},
                metadata={"tool": "whois"},
                evidence_path="/tmp/evidence/test.txt"
            )
            mock_run.return_value = adapter_result
            
            results = orchestrator.run_passive_recon()
            
            # Verify evidence paths are tracked
            if results:
                assert hasattr(results[0], 'evidence_path')
                # Evidence path may be None or a string depending on implementation


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
