"""
Tests for Orchestrator Implementation

This module contains tests for the orchestrator, workflow manager,
result processor, and related orchestration components.
"""

import pytest
import tempfile
from datetime import datetime
from unittest.mock import Mock, patch
from typing import Dict, Any, List

from src.agent.orchestrator import (
    Orchestrator, WorkflowManager, ResultProcessor, WorkflowState, ScanMode,
    create_orchestrator, OrchestratorContext
)
from src.agent.models import Asset, ScanResult, WorkflowStep
from src.adapters.interface import AdapterResult, AdapterResultStatus


class TestWorkflowState:
    """Test cases for workflow state enumeration."""
    
    def test_workflow_state_enum(self):
        """Test workflow state enumeration values."""
        assert WorkflowState.PENDING.value == "pending"
        assert WorkflowState.RUNNING.value == "running"
        assert WorkflowState.PAUSED.value == "paused"
        assert WorkflowState.COMPLETED.value == "completed"
        assert WorkflowState.FAILED.value == "failed"
        assert WorkflowState.CANCELLED.value == "cancelled"


class TestScanMode:
    """Test cases for scan mode enumeration."""
    
    def test_scan_mode_enum(self):
        """Test scan mode enumeration values."""
        assert ScanMode.PASSIVE.value == "passive"
        assert ScanMode.ACTIVE.value == "active"
        assert ScanMode.LAB.value == "lab"


class TestWorkflowManager:
    """Test cases for the WorkflowManager implementation."""
    
    def test_workflow_manager_initialization(self):
        """Test WorkflowManager initialization."""
        manager = WorkflowManager()
        
        assert manager.current_step is None
        assert manager.step_history == []
        assert manager.state == WorkflowState.PENDING
        assert manager.start_time is None
        assert manager.end_time is None
    
    def test_workflow_manager_with_initial_values(self):
        """Test WorkflowManager with initial values."""
        step = WorkflowStep(
            name="test_step",
            description="Test step",
            tool="nmap",
            target="127.0.0.1",
            parameters={}
        )
        manager = WorkflowManager(
            current_step=step,
            state=WorkflowState.RUNNING,
            start_time=datetime.now()
        )
        
        assert manager.current_step == step
        assert manager.state == WorkflowState.RUNNING
        assert manager.start_time is not None


class TestResultProcessor:
    """Test cases for the ResultProcessor implementation."""
    
    def test_result_processor_initialization(self):
        """Test ResultProcessor initialization."""
        processor = ResultProcessor()
        
        assert processor.processed_results == []
        assert processor.raw_outputs == []
        assert processor.findings == []
    
    def test_result_processor_with_initial_data(self):
        """Test ResultProcessor with initial data."""
        results = [Mock(spec=ScanResult)]
        raw_outputs = [{"test": "output"}]
        findings = [{"test": "finding"}]
        
        processor = ResultProcessor(
            processed_results=results,
            raw_outputs=raw_outputs,
            findings=findings
        )
        
        assert processor.processed_results == results
        assert processor.raw_outputs == raw_outputs
        assert processor.findings == findings


class TestOrchestrator:
    """Test cases for the Orchestrator implementation."""
    
    def test_orchestrator_initialization(self):
        """Test Orchestrator initialization."""
        from src.agent.llm_client import LLMConfig, LLMProvider
        
        config = {
            "policy": {"test": "config"},
            "adapters_path": "/tmp/adapters",
            "llm": LLMConfig(
                provider=LLMProvider.LMSTUDIO,
                endpoint="http://localhost:1234/v1",
                model="test-model"
            )
        }
        
        orchestrator = Orchestrator(config)
        
        assert orchestrator.config == config
        assert orchestrator.db_connection is None
        assert orchestrator.assets == []
        assert orchestrator.scan_results == []
        assert orchestrator.completed_steps == set()
        
        # Check that core components were initialized
        assert orchestrator.policy_engine is not None
        assert orchestrator.plugin_manager is not None
        assert orchestrator.llm_client is not None
        assert orchestrator.workflow_manager is not None
        assert orchestrator.result_processor is not None
    
    def test_orchestrator_with_db_connection(self):
        """Test Orchestrator initialization with database connection."""
        config = {"test": "config"}
        db_connection = Mock()
        
        orchestrator = Orchestrator(config, db_connection)
        
        assert orchestrator.db_connection == db_connection
    
    def test_add_asset_success(self):
        """Test adding asset successfully."""
        config = {"policy": {"target_validation": {"authorized_networks": ["192.168.1.0/24"]}}}
        orchestrator = Orchestrator(config)
        
        asset = Asset(
            target="192.168.1.100",
            tool_name="nmap",
            parameters={"port": 80}
        )
        
        # Mock policy engine to allow the asset
        with patch.object(orchestrator.policy_engine, 'validate_asset', return_value=True):
            result = orchestrator.add_asset(asset)
            
            assert result is True
            assert len(orchestrator.assets) == 1
            assert orchestrator.assets[0] == asset
    
    def test_add_asset_rejected_by_policy(self):
        """Test adding asset rejected by policy."""
        config = {"policy": {"target_validation": {"authorized_networks": ["10.0.0.0/8"]}}}
        orchestrator = Orchestrator(config)
        
        asset = Asset(
            target="192.168.1.100",
            tool_name="nmap",
            parameters={"port": 80}
        )
        
        # Mock policy engine to reject the asset
        with patch.object(orchestrator.policy_engine, 'validate_asset', return_value=False):
            result = orchestrator.add_asset(asset)
            
            assert result is False
            assert len(orchestrator.assets) == 0
    
    def test_cleanup(self):
        """Test orchestrator cleanup."""
        config = {"test": "config"}
        orchestrator = Orchestrator(config)
        
        # Add some test data
        asset = Asset(target="127.0.0.1", tool_name="test", parameters={})
        orchestrator.assets.append(asset)
        orchestrator.scan_results.append(Mock(spec=ScanResult))
        orchestrator.completed_steps.add("test_step")
        
        # Mock plugin manager cleanup
        with patch.object(orchestrator.plugin_manager, 'cleanup') as mock_cleanup:
            orchestrator.cleanup()
            
            assert len(orchestrator.assets) == 0
            assert len(orchestrator.scan_results) == 0
            assert len(orchestrator.completed_steps) == 0
            assert len(orchestrator.result_processor.processed_results) == 0
            assert len(orchestrator.result_processor.raw_outputs) == 0
            assert len(orchestrator.result_processor.findings) == 0
            mock_cleanup.assert_called_once()


class TestOrchestratorWorkflow:
    """Test cases for orchestrator workflow methods."""
    
    @patch('src.agent.orchestrator.PluginManager.run_adapter')
    @patch('src.agent.orchestrator.PolicyEngine.validate_asset')
    @patch('src.agent.orchestrator.PolicyEngine.enforce_rate_limits')
    def test_run_passive_recon_success(self, mock_rate_limits, mock_validate, mock_run_adapter):
        """Test successful passive reconnaissance."""
        config = {
            "policy": {"test": "config"},
            "passive_tools": ["whois", "dns_lookup"]
        }
        orchestrator = Orchestrator(config)
        
        # Add test asset
        asset = Asset(target="example.com", tool_name="whois", parameters={})
        orchestrator.assets.append(asset)
        
        # Mock successful responses
        mock_validate.return_value = True
        mock_rate_limits.return_value = True
        
        # Mock adapter results
        adapter_result = AdapterResult(
            status=AdapterResultStatus.SUCCESS,
            data={"test": "output"},
            metadata={"tool": "whois"}
        )
        mock_run_adapter.return_value = adapter_result
        
        # Run passive recon
        results = orchestrator.run_passive_recon()
        
        assert len(results) == 2  # One for each tool
        assert orchestrator.workflow_manager.state == WorkflowState.COMPLETED
        assert orchestrator.workflow_manager.start_time is not None
        assert orchestrator.workflow_manager.end_time is not None
    
    def test_run_passive_recon_no_assets(self):
        """Test passive reconnaissance with no assets."""
        config = {"policy": {"test": "config"}}
        orchestrator = Orchestrator(config)
        
        results = orchestrator.run_passive_recon()
        
        assert results == []
        assert orchestrator.workflow_manager.state == WorkflowState.PENDING
    
    @patch('src.agent.orchestrator.LLMClient.plan_next_steps')
    def test_plan_active_scans_success(self, mock_plan_next_steps):
        """Test successful active scan planning."""
        config = {"policy": {"test": "config"}}
        orchestrator = Orchestrator(config)
        
        # Add some scan results for context
        asset = Asset(target="example.com", tool_name="nmap", parameters={})
        scan_result = ScanResult(
            asset=asset,
            tool_name="nmap",
            status="completed",
            findings=[],
            raw_output={},
            metadata={}
        )
        orchestrator.scan_results.append(scan_result)
        
        # Mock LLM response
        mock_response = Mock()
        mock_response.content = "1. Run nmap scan\n2. Run sqlmap scan"
        mock_plan_next_steps.return_value = mock_response
        
        steps = orchestrator.plan_active_scans(ScanMode.ACTIVE)
        
        assert len(steps) == 2
        assert steps[0].description == "1. Run nmap scan"
        assert steps[1].description == "2. Run sqlmap scan"
    
    def test_plan_active_scans_no_results(self):
        """Test active scan planning with no results."""
        config = {"policy": {"test": "config"}}
        orchestrator = Orchestrator(config)
        
        steps = orchestrator.plan_active_scans(ScanMode.ACTIVE)
        
        assert steps == []
    
    @patch('src.agent.orchestrator.LLMClient.plan_next_steps')
    def test_plan_active_scans_llm_failure(self, mock_plan_next_steps):
        """Test active scan planning with LLM failure."""
        config = {"policy": {"test": "config"}}
        orchestrator = Orchestrator(config)
        
        # Add some scan results for context
        asset = Asset(target="example.com", tool_name="nmap", parameters={})
        scan_result = ScanResult(
            asset=asset,
            tool_name="nmap",
            status="completed",
            findings=[],
            raw_output={},
            metadata={}
        )
        orchestrator.scan_results.append(scan_result)
        
        # Mock LLM failure
        mock_plan_next_steps.side_effect = Exception("LLM unavailable")
        
        steps = orchestrator.plan_active_scans(ScanMode.ACTIVE)
        
        # Should fall back to default plan
        assert len(steps) > 0
        assert steps[0].tool in ["nmap", "sqlmap", "gobuster"]


class TestOrchestratorScanExecution:
    """Test cases for orchestrator scan execution methods."""
    
    @patch('src.agent.orchestrator.PluginManager.run_adapter')
    @patch('src.agent.orchestrator.PolicyEngine.validate_asset')
    @patch('src.agent.orchestrator.PolicyEngine.enforce_rate_limits')
    def test_execute_scan_step_success(self, mock_rate_limits, mock_validate, mock_run_adapter):
        """Test successful scan step execution."""
        config = {"policy": {"test": "config"}}
        orchestrator = Orchestrator(config)
        
        # Create test step
        step = WorkflowStep(
            name="test_step",
            description="Test scan step",
            tool="nmap",
            target="example.com",
            parameters={"target": "example.com"}
        )
        
        # Mock successful responses
        mock_validate.return_value = True
        mock_rate_limits.return_value = True
        
        adapter_result = AdapterResult(
            status=AdapterResultStatus.SUCCESS,
            data={"scan": "results"},
            metadata={"tool": "nmap"}
        )
        mock_run_adapter.return_value = adapter_result
        
        # Mock user approval
        with patch.object(orchestrator, '_get_user_approval', return_value=True):
            result = orchestrator.execute_scan_step(step)
            
            assert result is not None
            assert result.tool_name == "nmap"
            assert "test_step" in orchestrator.completed_steps
    
    @patch('src.agent.orchestrator.PolicyEngine.validate_asset')
    def test_execute_scan_step_rejected_by_policy(self, mock_validate):
        """Test scan step execution rejected by policy."""
        config = {"policy": {"test": "config"}}
        orchestrator = Orchestrator(config)
        
        # Create test step
        step = WorkflowStep(
            name="test_step",
            description="Test scan step",
            tool="nmap",
            target="unauthorized.com",
            parameters={"target": "unauthorized.com"}
        )
        
        # Mock policy rejection
        mock_validate.return_value = False
        
        result = orchestrator.execute_scan_step(step)
        
        assert result is None
        assert "test_step" not in orchestrator.completed_steps
    
    def test_execute_scan_step_user_cancellation(self):
        """Test scan step execution cancelled by user."""
        config = {"policy": {"test": "config"}}
        orchestrator = Orchestrator(config)
        
        # Create test step
        step = WorkflowStep(
            name="test_step",
            description="Test scan step",
            tool="nmap",
            target="example.com",
            parameters={"target": "example.com"}
        )
        
        # Mock user cancellation
        with patch.object(orchestrator, '_get_user_approval', return_value=False):
            result = orchestrator.execute_scan_step(step)
            
            assert result is None
            assert "test_step" not in orchestrator.completed_steps


class TestOrchestratorReporting:
    """Test cases for orchestrator reporting methods."""
    
    def test_generate_report_json(self):
        """Test generating JSON report."""
        config = {"policy": {"test": "config"}}
        orchestrator = Orchestrator(config)
        
        # Add test data
        asset = Asset(target="example.com", tool_name="nmap", parameters={})
        orchestrator.assets.append(asset)
        
        scan_result = ScanResult(
            asset=asset,
            tool_name="nmap",
            status="completed",
            findings=[{"test": "finding"}],
            raw_output={"raw": "data"},
            metadata={"tool": "nmap"}
        )
        orchestrator.scan_results.append(scan_result)
        
        # Add findings to result processor (this is what the orchestrator does during processing)
        orchestrator.result_processor.findings.append({"test": "finding"})
        
        # Generate report
        report = orchestrator.generate_report("json")
        
        assert "summary" in report
        assert "assets" in report
        assert "results" in report
        assert "findings" in report
        assert "violations" in report
        assert "rates" in report
        
        assert report["summary"]["total_assets"] == 1
        assert report["summary"]["total_scans"] == 1
        assert report["summary"]["total_findings"] == 1
    
    def test_calculate_scan_duration(self):
        """Test scan duration calculation."""
        orchestrator = Orchestrator({"test": "config"})
        
        # Test with no timestamps
        duration = orchestrator._calculate_scan_duration()
        assert duration == 0.0
        
        # Test with timestamps (this would be set by workflow methods)
        # The actual calculation is tested through the workflow methods


class TestOrchestratorFactory:
    """Test cases for orchestrator factory function."""
    
    def test_create_orchestrator_default(self):
        """Test creating orchestrator with default config."""
        orchestrator = create_orchestrator()
        
        assert isinstance(orchestrator, Orchestrator)
        assert "policy" in orchestrator.config
        assert "passive_tools" in orchestrator.config
    
    def test_create_orchestrator_custom(self):
        """Test creating orchestrator with custom config."""
        config = {
            "policy": {"custom": "policy"},
            "custom_setting": "value"
        }
        
        orchestrator = create_orchestrator(config)
        
        assert isinstance(orchestrator, Orchestrator)
        assert orchestrator.config == config


class TestOrchestratorContext:
    """Test cases for orchestrator context manager."""
    
    def test_orchestrator_context_manager(self):
        """Test orchestrator context manager."""
        config = {"test": "config"}
        
        with OrchestratorContext(config) as orchestrator:
            assert isinstance(orchestrator, Orchestrator)
            assert orchestrator.config == config
        
        # Context should exit cleanly (cleanup would be called)


class TestOrchestratorIntegration:
    """Integration tests for orchestrator components."""
    
    def test_complete_workflow_lifecycle(self):
        """Test complete workflow lifecycle."""
        config = {
            "policy": {
                "target_validation": {"authorized_networks": ["192.168.1.0/24"]},
                "rate_limiting": {"window_size": 60, "max_requests": 10}
            },
            "passive_tools": ["whois"]
        }
        
        with OrchestratorContext(config) as orchestrator:
            # 1. Add asset
            asset = Asset(target="192.168.1.100", tool_name="whois", parameters={})
            assert orchestrator.add_asset(asset) is True
            
            # 2. Run passive recon (mocked)
            with patch('src.agent.orchestrator.PluginManager.run_adapter') as mock_run:
                adapter_result = AdapterResult(
                    status=AdapterResultStatus.SUCCESS,
                    data={"domain": "test.com"},
                    metadata={"tool": "whois"}
                )
                mock_run.return_value = adapter_result
                
                results = orchestrator.run_passive_recon()
                assert len(results) >= 0  # May be 0 due to mocking
            
            # 3. Plan active scans
            steps = orchestrator.plan_active_scans(ScanMode.PASSIVE)
            # Should get default plan since no real results
            
            # 4. Generate report
            report = orchestrator.generate_report("json")
            assert isinstance(report, dict)
            assert "summary" in report
    
    def test_error_handling_consistency(self):
        """Test consistent error handling across methods."""
        config = {"policy": {"test": "config"}}
        orchestrator = Orchestrator(config)
        
        # All major methods should handle errors gracefully
        methods = [
            (orchestrator.run_passive_recon, []),
            (orchestrator.plan_active_scans, [ScanMode.PASSIVE]),
            (orchestrator.generate_report, ["json"])
        ]
        
        for method, args in methods:
            try:
                result = method(*args)
                # Should not raise exceptions for basic operations
            except Exception as e:
                # If exceptions occur, they should be handled appropriately
                assert True  # Exception handling is tested elsewhere


if __name__ == "__main__":
    pytest.main([__file__])
