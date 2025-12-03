"""
Unit tests for Orchestrator structured parsing logic.
"""
import pytest
import json
from unittest.mock import MagicMock, patch
import sys
from pathlib import Path

# Add project root to path
sys.path.insert(0, str(Path(__file__).parent.parent))

from src.agent.orchestrator import Orchestrator, WorkflowStep
from src.agent.llm_client import LLMResponse

class TestOrchestratorParsing:
    """Test parsing logic in Orchestrator."""
    
    @pytest.fixture
    def orchestrator(self):
        """Create a mock orchestrator."""
        with patch("src.agent.orchestrator.create_policy_engine"), \
             patch("src.agent.orchestrator.create_plugin_manager"), \
             patch("src.agent.orchestrator.create_llm_client"):
            
            config = {
                "llm": {},
                "policy": {},
                "adapters_path": "plugins"
            }
            orch = Orchestrator(config)
            orch.llm_client = MagicMock()
            return orch

    def test_parse_llm_plan_json(self, orchestrator):
        """Test parsing valid JSON plan."""
        json_plan = {
            "scan_plan": [
                {
                    "tool": "nmap",
                    "target": "192.168.1.1",
                    "parameters": {"ports": "80"},
                    "priority": 1,
                    "rationale": "Test scan"
                }
            ]
        }
        plan_text = json.dumps(json_plan)
        
        steps = orchestrator._parse_llm_plan(plan_text)
        
        assert len(steps) == 1
        assert steps[0].tool == "nmap"
        assert steps[0].target == "192.168.1.1"
        assert steps[0].parameters == {"ports": "80"}

    def test_parse_llm_plan_json_in_markdown(self, orchestrator):
        """Test parsing JSON plan wrapped in markdown."""
        json_plan = {
            "scan_plan": [
                {
                    "tool": "gobuster",
                    "target": "example.com",
                    "priority": 1
                }
            ]
        }
        plan_text = f"Here is the plan:\n```json\n{json.dumps(json_plan)}\n```"
        
        steps = orchestrator._parse_llm_plan(plan_text)
        
        assert len(steps) == 1
        assert steps[0].tool == "gobuster"
        assert steps[0].target == "example.com"

    def test_parse_llm_plan_fallback(self, orchestrator):
        """Test fallback parsing when JSON is invalid."""
        plan_text = "Run nmap on 192.168.1.1\nExecute gobuster against example.com"
        
        steps = orchestrator._parse_llm_plan(plan_text)
        
        assert len(steps) == 2
        assert steps[0].tool == "nmap"
        assert steps[0].target == "192.168.1.1"
        assert steps[1].tool == "gobuster"
        assert steps[1].target == "example.com"

    def test_analyze_findings_json(self, orchestrator):
        """Test analyzing findings with valid JSON response."""
        json_findings = {
            "findings": [
                {
                    "title": "Open Port",
                    "description": "Port 80 is open",
                    "severity": "high",
                    "category": "misconfiguration",
                    "affected_resource": "192.168.1.1:80",
                    "remediation": "Close it"
                }
            ]
        }
        
        # Mock LLM response
        orchestrator.llm_client.analyze_findings.return_value = LLMResponse(
            content=json.dumps(json_findings),
            model="test",
            usage={}
        )
        
        findings = orchestrator._analyze_findings("raw output", "192.168.1.1")
        
        assert len(findings) == 1
        assert findings[0]["title"] == "Open Port"
        assert findings[0]["severity"] == "high"
        assert findings[0]["category"] == "misconfiguration"

    def test_analyze_findings_fallback(self, orchestrator):
        """Test analyzing findings fallback."""
        text_response = "Found a Critical vulnerability in the system."
        
        # Mock LLM response
        orchestrator.llm_client.analyze_findings.return_value = LLMResponse(
            content=text_response,
            model="test",
            usage={}
        )
        
        findings = orchestrator._analyze_findings("raw output", "192.168.1.1")
        
        assert len(findings) == 1
        assert findings[0]["severity"] == "critical"
        assert findings[0]["description"] == text_response
