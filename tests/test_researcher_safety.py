import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).parent.parent))

import pytest
from unittest.mock import MagicMock, patch
from src.agent.agents.researcher import ResearcherAgent
from src.agent.models import WorkflowStep

class TestResearcherSafety:
    @pytest.fixture
    def mock_components(self):
        llm_client = MagicMock()
        plugin_manager = MagicMock()
        policy_engine = MagicMock()
        
        # Setup plugin manager to return some tools
        plugin_manager.discover_adapters.return_value = ["nmap", "gobuster"]
        plugin_manager.execute_tool.return_value = MagicMock(success=True, stdout="Tool output")
        
        return llm_client, plugin_manager, policy_engine

    def test_initialization_requires_policy_engine(self, mock_components):
        llm_client, plugin_manager, policy_engine = mock_components
        
        # Should initialize correctly with policy engine
        agent = ResearcherAgent(llm_client, plugin_manager, policy_engine)
        assert agent.policy_engine == policy_engine
        assert "nmap" in agent.tools

    def test_execute_tool_enforces_policy_validation(self, mock_components):
        llm_client, plugin_manager, policy_engine = mock_components
        agent = ResearcherAgent(llm_client, plugin_manager, policy_engine)
        
        # Mock policy engine to reject asset
        policy_engine.validate_asset.return_value = False
        
        result = agent.execute_tool("nmap", {"target": "evil.com"})
        
        # Should return blocked message
        assert "BLOCKED" in result
        assert "policy" in result.lower()
        
        # Should verify asset was checked
        policy_engine.validate_asset.assert_called_once()
        # Should NOT execute tool
        plugin_manager.execute_tool.assert_not_called()

    def test_execute_tool_enforces_rate_limits(self, mock_components):
        llm_client, plugin_manager, policy_engine = mock_components
        agent = ResearcherAgent(llm_client, plugin_manager, policy_engine)
        
        # Mock policy engine to accept asset but reject rate limit
        policy_engine.validate_asset.return_value = True
        policy_engine.enforce_rate_limits.return_value = False
        
        result = agent.execute_tool("nmap", {"target": "good.com"})
        
        # Should return blocked message
        assert "BLOCKED" in result
        assert "rate limit" in result.lower()
        
        # Should verify rate limit was checked
        policy_engine.enforce_rate_limits.assert_called_once_with("nmap")
        # Should NOT execute tool
        plugin_manager.execute_tool.assert_not_called()

    def test_execute_tool_allows_valid_request(self, mock_components):
        llm_client, plugin_manager, policy_engine = mock_components
        agent = ResearcherAgent(llm_client, plugin_manager, policy_engine)
        
        # Mock policy engine to accept everything
        policy_engine.validate_asset.return_value = True
        policy_engine.enforce_rate_limits.return_value = True
        
        result = agent.execute_tool("nmap", {"target": "good.com"})
        
        # Should NOT return blocked message
        assert "BLOCKED" not in result
        
        # Should verify checks passed
        policy_engine.validate_asset.assert_called_once()
        policy_engine.enforce_rate_limits.assert_called_once_with("nmap")
        # Should execute tool
        plugin_manager.execute_tool.assert_called_once()
        # Should record rate limit usage
        policy_engine.rate_limiter.record_request.assert_called_once_with("nmap")
