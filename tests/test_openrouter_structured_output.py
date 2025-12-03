"""
Integration Test for OpenRouter with Structured JSON Output

This test verifies that the LLM client can successfully connect to OpenRouter
and receive structured JSON responses for planning and analysis.
"""

import pytest
import os
import json
import sys
from pathlib import Path

# Add src to path for imports
sys.path.insert(0, str(Path(__file__).parent.parent / "src"))

from agent.llm_client import LLMClient, LLMConfig, LLMProvider, LLMMessage
from dotenv import load_dotenv

# Load environment variables from .env
load_dotenv(Path(__file__).parent.parent / ".env")


@pytest.mark.skipif(
    not os.getenv("OPENROUTER_API_KEY"),
    reason="OPENROUTER_API_KEY not set in environment"
)
class TestOpenRouterStructuredOutput:
    """Test OpenRouter integration with structured JSON output."""
    
    def setup_method(self):
        """Setup OpenRouter client before each test."""
        self.config = LLMConfig(
            provider=LLMProvider.OPENROUTER,
            endpoint="https://openrouter.ai/api/v1",
            model="anthropic/claude-3.5-sonnet",  # Fast and reliable model
            api_key=os.getenv("OPENROUTER_API_KEY"),
            temperature=0.1,  # Low temperature for more consistent output
            enable_rag=False  # Disable RAG for this test
        )
        self.client = LLMClient(self.config)
    
    def test_openrouter_connection(self):
        """Test basic connection to OpenRouter."""
        # Simple health check
        messages = [
            LLMMessage(role="user", content="Respond with 'OK'")
        ]
        
        response = self.client.generate(messages)
        assert response is not None
        assert response.content is not None
        assert len(response.content) > 0
        print(f"✅ OpenRouter connection successful: {response.content[:50]}")
    
    def test_plan_next_steps_structured_json(self):
        """Test planning with structured JSON output."""
        context = "Target example.com: dns_lookup completed, ssl_check completed"
        objective = "Plan active scanning based on passive recon results"
        
        response = self.client.plan_next_steps(context, objective, structured=True)
        
        assert response is not None
        assert response.content is not None
        
        # Try to parse as JSON
        try:
            # Handle markdown code blocks
            content = response.content
            if "```" in content:
                import re
                json_match = re.search(r'```(?:json)?\s*(\{.*?\})\s*```', content, re.DOTALL)
                if json_match:
                    content = json_match.group(1)
            
            plan_data = json.loads(content)
            
            assert "scan_plan" in plan_data, "Response should contain 'scan_plan' field"
            assert isinstance(plan_data["scan_plan"], list), "scan_plan should be a list"
            
            if plan_data["scan_plan"]:
                first_step = plan_data["scan_plan"][0]
                assert "tool" in first_step, "Each step should have 'tool'"
                assert "target" in first_step, f"Each step should have 'target'"
                assert "priority" in first_step, "Each step should have 'priority'"
                
                print(f"✅ Structured planning response:")
                print(json.dumps(plan_data, indent=2)[:500])
                
        except json.JSONDecodeError as e:
            pytest.fail(f"Failed to parse response as JSON: {e}\nResponse: {response.content[:500]}")
    
    def test_analyze_findings_structured_json(self):
        """Test findings analysis with structured JSON output."""
        tool_output = """
Nmap scan report for example.com (93.184.216.34)
PORT    STATE SERVICE
22/tcp  open  ssh     OpenSSH 7.4 (protocol 2.0)
80/tcp  open  http    nginx 1.18.0
443/tcp open  https   nginx 1.18.0
        """
        
        response = self.client.analyze_findings(tool_output, context="Target: example.com", structured=True)
        
        assert response is not None
        assert response.content is not None
        
        # Try to parse as JSON
        try:
            # Handle markdown code blocks
            content = response.content
            if "```" in content:
                import re
                json_match = re.search(r'```(?:json)?\s*(\{.*?\})\s*```', content, re.DOTALL)
                if json_match:
                    content = json_match.group(1)
            
            findings_data = json.loads(content)
            
            assert "findings" in findings_data, "Response should contain 'findings' field"
            assert isinstance(findings_data["findings"], list), "findings should be a list"
            
            if findings_data["findings"]:
                first_finding = findings_data["findings"][0]
                assert "title" in first_finding, "Each finding should have 'title'"
                assert "severity" in first_finding, "Each finding should have 'severity'"
                assert "description" in first_finding, "Each finding should have 'description'"
                assert "category" in first_finding, "Each finding should have 'category'"
                
                # Verify severity is valid
                valid_severities = ["critical", "high", "medium", "low", "info"]
                severity = first_finding["severity"].lower()
                assert severity in valid_severities, f"Severity '{severity}' must be one of {valid_severities}"
                
                print(f"✅ Structured findings response:")
                print(json.dumps(findings_data, indent=2)[:500])
                
        except json.JSONDecodeError as e:
            pytest.fail(f"Failed to parse response as JSON: {e}\nResponse: {response.content[:500]}")
    
    def test_severity_extraction(self):
        """Test that severity levels are properly extracted."""
        tool_output = "Critical vulnerability found: Remote Code Execution"
        
        response = self.client.analyze_findings(tool_output, context="Test", structured=True)
        content = response.content
        
        # Extract JSON
        if "```" in content:
            import re
            json_match = re.search(r'```(?:json)?\s*(\{.*?\})\s*```', content, re.DOTALL)
            if json_match:
                content = json_match.group(1)
        
        findings_data = json.loads(content)
        
        if findings_data["findings"]:
            # Should identify this as critical or high severity
            severity = findings_data["findings"][0]["severity"].lower()
            assert severity in ["critical", "high"], f"Should detect high/critical severity, got: {severity}"
            print(f"✅ Correctly identified severity: {severity}")


if __name__ == "__main__":
    # Run tests
    pytest.main([__file__, "-v", "-s"])
