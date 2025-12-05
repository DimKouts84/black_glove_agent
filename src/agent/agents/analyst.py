"""
Analyst Agent for Black Glove pentest agent.
Responsible for analyzing tool results and generating security insights.
"""

import json
import re
from typing import Dict, Any, List, Optional, Union
from datetime import datetime
import logging

from ..llm_client import LLMClient, LLMMessage, LLMResponse
from ..plugin_manager import PluginManager
from ..models import WorkflowStep
from .base import BaseAgent

class AnalystAgent(BaseAgent):
    """
    Agent responsible for analyzing tool results and generating security insights.
    
    Takes raw tool output and parsed data, then uses LLM to generate
    structured security findings and recommendations.
    """
    
    def __init__(self, llm_client: LLMClient, session_id: str = None):
        """
        Initialize the Analyst Agent.
        
        Args:
            llm_client: LLM client for generating responses
            session_id: Optional session ID for context
        """
        super().__init__(llm_client, session_id)
        self.role = "analyst"
        
        # Set up analysis tools available to this agent
        self.tools = [
            "analyze_findings", "plan_workflow", "generate_report",
            "nmap", "gobuster", "whois", "dns_lookup", "ssl_check",
            "sublist3r", "wappalyzer", "viewdns", "camera_security"
        ]
        self.set_tools(self.tools)
    
    def analyze_findings(self, tool_results: Union[List[Dict[str, Any]], str, Dict[str, Any]]) -> str:
        """
        Analyze tool results and generate security insights.
        
        Args:
            tool_results: Tool execution results (list, dict, or string)
            
        Returns:
            str: Analysis and findings summary
        """
        # Handle different input types gracefully
        if isinstance(tool_results, str):
            # If it's just a string (like an error message), wrap it
            tool_results = [{"tool": "unknown", "result": tool_results}]
        elif isinstance(tool_results, dict):
            # If it's a single result dict, wrap it in a list
            tool_results = [tool_results]
        elif not isinstance(tool_results, list):
            # Fallback for unexpected types
            tool_results = [{"tool": "unknown", "output": str(tool_results)}]

        self.logger.info(f"Analyzing {len(tool_results)} tool results")
        
        try:
            # Combine all tool outputs for analysis
            combined_output = self._combine_tool_outputs(tool_results)
            
            # Use LLM to generate structured analysis
            analysis = self._llm_analysis(combined_output)
            
            # Log the analysis action
            self.log_action("Security analysis completed", {
                "tools_analyzed": len(tool_results),
                "analysis_length": len(analysis),
                "findings_detected": self._count_findings(analysis)
            })
            
            return analysis
            
        except Exception as e:
            error_msg = f"ERROR in security analysis: {str(e)}"
            self.logger.error(error_msg)
            return error_msg
    
    def analyze_single_tool(self, tool_name: str, raw_output: str, parsed_data: Dict[str, Any] = None) -> str:
        """
        Analyze a single tool's output.
        
        Args:
            tool_name: Name of the tool
            raw_output: Raw output from the tool
            parsed_data: Optional parsed data structure
            
        Returns:
            str: Analysis of the single tool result
        """
        self.logger.info(f"Analyzing single tool: {tool_name}")
        
        try:
            # Create context for single tool analysis
            context = f"""
Tool: {tool_name}
Output: {raw_output}
Parsed Data: {parsed_data}
Analysis Time: {datetime.now().isoformat()}
"""
            
            # Use LLM to generate analysis
            analysis = self._llm_single_analysis(context, tool_name)
            
            return analysis
            
        except Exception as e:
            error_msg = f"ERROR analyzing {tool_name}: {str(e)}"
            self.logger.error(error_msg)
            return error_msg
    
    def generate_security_report(self, analysis_results: List[str], target_info: Dict[str, Any] = None) -> str:
        """
        Generate a comprehensive security report from multiple analyses.
        
        Args:
            analysis_results: List of analysis results from different tools
            target_info: Information about the target being analyzed
            
        Returns:
            str: Formatted security report
        """
        self.logger.info("Generating comprehensive security report")
        
        try:
            # Combine all analysis results
            combined_analysis = "\n\n".join(analysis_results)
            
            # Create target context if available
            target_context = ""
            if target_info:
                target_context = f"""
Target Information:
{json.dumps(target_info, indent=2)}
"""
            
            # Generate comprehensive report using LLM
            report = self._llm_report_generation(combined_analysis, target_context)
            
            # Log the report generation
            self.log_action("Security report generated", {
                "analyses_combined": len(analysis_results),
                "report_length": len(report),
                "has_target_info": target_info is not None
            })
            
            return report
            
        except Exception as e:
            error_msg = f"ERROR generating security report: {str(e)}"
            self.logger.error(error_msg)
            return error_msg
    
    def identify_vulnerabilities(self, tool_results: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """
        Identify potential vulnerabilities from tool results.
        
        Args:
            tool_results: List of tool execution results
            
        Returns:
            List[Dict[str, Any]]: List of identified vulnerabilities
        """
        self.logger.info("Identifying potential vulnerabilities")
        
        vulnerabilities = []
        
        for result in tool_results:
            tool_name = result.get('tool', 'unknown')
            parsed_data = result.get('parsed', {})
            
            # Tool-specific vulnerability checks
            if tool_name == 'nmap':
                vulns = self._check_nmap_vulnerabilities(parsed_data)
                vulnerabilities.extend(vulns)
            elif tool_name == 'gobuster':
                vulns = self._check_gobuster_vulnerabilities(parsed_data)
                vulnerabilities.extend(vulns)
            elif tool_name == 'ssl_check':
                vulns = self._check_ssl_vulnerabilities(parsed_data)
                vulnerabilities.extend(vulns)
        
        return vulnerabilities
    
    def _combine_tool_outputs(self, tool_results: List[Dict[str, Any]]) -> str:
        """
        Combine multiple tool outputs into a single context string.
        
        Args:
            tool_results: List of tool execution results
            
        Returns:
            str: Combined output context
        """
        combined_parts = []
        
        for i, result in enumerate(tool_results, 1):
            tool_name = result.get('tool', 'unknown')
            result_text = result.get('result', result.get('output', ''))
            parsed = result.get('parsed', {})
            
            # Handle datetime objects in parsed data
            def json_serial(obj):
                if isinstance(obj, datetime):
                    return obj.isoformat()
                return str(obj)

            try:
                parsed_json = json.dumps(parsed, indent=2, default=json_serial)
            except Exception:
                parsed_json = str(parsed)
            
            part = f"""
=== TOOL RESULT {i} ===
Tool: {tool_name}
Status: {'SUCCESS' if 'ERROR' not in str(result_text)[:20] else 'FAILED'}

Raw Output:
{result_text}

Parsed Data:
{parsed_json}

=== END TOOL RESULT {i} ===
"""
            combined_parts.append(part)
        
        return "\n".join(combined_parts)
    
    def _llm_analysis(self, combined_output: str) -> str:
        """
        Use LLM to generate comprehensive security analysis.
        
        Args:
            combined_output: Combined tool outputs
            
        Returns:
            str: LLM-generated analysis
        """
        system_prompt = self.get_system_prompt()
        
        # Override system prompt for analysis
        analysis_prompt = f"""You are a cybersecurity analyst. Analyze the following tool outputs for security findings.

{system_prompt}

Focus on:
1. Identifying potential security issues and misconfigurations
2. Assessing risk levels (Critical, High, Medium, Low, Info)
3. Providing actionable remediation recommendations
4. Prioritizing findings by impact and likelihood
5. Maintaining professional cybersecurity terminology

Format your analysis as:
- **EXECUTIVE SUMMARY**: Brief overview of key findings
- **DETAILED FINDINGS**: Specific issues with risk levels
- **PRIORITY RECOMMENDATIONS**: Top remediation actions
- **NEXT STEPS**: Suggested follow-up actions

Be thorough but concise. Focus on actionable insights."""
        
        messages = [
            LLMMessage(role="system", content=analysis_prompt),
            LLMMessage(role="user", content=f"Analyze this security data:\n\n{combined_output}")
        ]
        
        response = self.llm_client.generate(messages)
        return response.content
    
    def _llm_single_analysis(self, context: str, tool_name: str) -> str:
        """
        Use LLM to analyze a single tool's output.
        
        Args:
            context: Tool output context
            tool_name: Name of the tool
            
        Returns:
            str: Single tool analysis
        """
        system_prompt = f"""You are a cybersecurity analyst focusing on {tool_name} results.

Analyze the {tool_name} output for security implications:
1. What security-relevant information was discovered?
2. Are there any potential issues or misconfigurations?
3. What is the risk level and impact?
4. What remediation steps are recommended?

Provide a concise analysis in bullet point format."""
        
        messages = [
            LLMMessage(role="system", content=system_prompt),
            LLMMessage(role="user", content=context)
        ]
        
        response = self.llm_client.generate(messages)
        return response.content
    
    def _llm_report_generation(self, combined_analysis: str, target_context: str) -> str:
        """
        Use LLM to generate a comprehensive security report.
        
        Args:
            combined_analysis: Combined analysis results
            target_context: Target information context
            
        Returns:
            str: Comprehensive security report
        """
        system_prompt = """You are a cybersecurity consultant generating a professional security assessment report.

Create a comprehensive report that includes:
1. **ASSESSMENT SUMMARY**: High-level overview and methodology
2. **FINDINGS BY SEVERITY**: Critical/High/Medium/Low/Info findings with details
3. **RISK ASSESSMENT**: Overall risk posture and key risk factors
4. **REMEDIATION ROADMAP**: Prioritized action plan with timelines
5. **TECHNICAL APPENDIX**: Detailed technical findings and evidence

Use professional report formatting with clear sections and actionable recommendations."""
        
        messages = [
            LLMMessage(role="system", content=system_prompt),
            LLMMessage(role="user", content=f"""
Generate a comprehensive security assessment report based on this analysis:

{target_context}

Analysis Results:
{combined_analysis}

Report Date: {datetime.now().strftime('%Y-%m-%d')}
Assessment Type: Security Reconnaissance and Analysis
""")
        ]
        
        response = self.llm_client.generate(messages)
        return response.content
    
    def _count_findings(self, analysis: str) -> int:
        """
        Count the number of findings in an analysis.
        
        Args:
            analysis: Analysis text
            
        Returns:
            int: Approximate number of findings
        """
        # Simple heuristic to count findings
        findings_indicators = [
            "critical", "high risk", "medium risk", "low risk", 
            "vulnerability", "misconfiguration", "issue", "finding"
        ]
        
        analysis_lower = analysis.lower()
        count = 0
        for indicator in findings_indicators:
            count += analysis_lower.count(indicator)
        
        return max(1, count // 3)  # Rough estimation
    
    def _check_nmap_vulnerabilities(self, parsed_data: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Check for potential vulnerabilities in Nmap results."""
        vulnerabilities = []
        
        ports = parsed_data.get('ports', [])
        
        for port_info in ports:
            port = port_info.get('port', 0)
            service = port_info.get('service', '').lower()
            
            # Check for commonly problematic services
            if port == 22 and 'ssh' in service:
                vulnerabilities.append({
                    "type": "service_exposure",
                    "severity": "medium",
                    "description": "SSH service accessible",
                    "port": port,
                    "service": service,
                    "recommendation": "Ensure SSH is properly configured and updated"
                })
            elif port == 80 and 'http' in service:
                vulnerabilities.append({
                    "type": "unencrypted_service",
                    "severity": "low",
                    "description": "HTTP service (unencrypted)",
                    "port": port,
                    "service": service,
                    "recommendation": "Consider migrating to HTTPS"
                })
            elif port == 3389 and 'rdp' in service:
                vulnerabilities.append({
                    "type": "remote_access",
                    "severity": "high",
                    "description": "RDP service accessible",
                    "port": port,
                    "service": service,
                    "recommendation": "Restrict RDP access and ensure proper authentication"
                })
        
        return vulnerabilities
    
    def _check_gobuster_vulnerabilities(self, parsed_data: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Check for potential vulnerabilities in Gobuster results."""
        vulnerabilities = []
        
        paths = parsed_data.get('paths', [])
        
        # Check for sensitive paths
        sensitive_paths = ['admin', 'login', 'wp-admin', 'phpmyadmin', 'config', '.git']
        
        for path in paths:
            path_lower = path.lower()
            for sensitive in sensitive_paths:
                if sensitive in path_lower:
                    vulnerabilities.append({
                        "type": "sensitive_path_exposure",
                        "severity": "medium",
                        "description": f"Sensitive path discovered: {path}",
                        "path": path,
                        "recommendation": "Review access controls for sensitive directories"
                    })
                    break
        
        return vulnerabilities
    
    def _check_ssl_vulnerabilities(self, parsed_data: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Check for potential SSL/TLS vulnerabilities."""
        vulnerabilities = []
        
        # Basic SSL vulnerability checks (placeholder implementation)
        ssl_info = parsed_data.get('info', {})
        
        if ssl_info.get('certificate_valid') == False:
            vulnerabilities.append({
                "type": "ssl_certificate",
                "severity": "high",
                "description": "Invalid or expired SSL certificate",
                "recommendation": "Renew SSL certificate and fix certificate chain"
            })
        
        return vulnerabilities
    
    def get_role_description(self) -> str:
        """Get description of the analyst agent's role."""
        return """Security analysis and reporting expert. You are responsible for:
1. Analyzing tool outputs for security implications and potential vulnerabilities
2. Generating structured security findings with risk assessments
3. Providing actionable remediation recommendations
4. Creating comprehensive security reports for stakeholders
5. Prioritizing findings based on risk level and business impact
6. Maintaining professional cybersecurity assessment standards

You focus on turning raw data into actionable security intelligence."""
    
    def summarize_findings(self, findings: List[Dict[str, Any]]) -> str:
        """
        Create a summary of identified findings.
        
        Args:
            findings: List of vulnerability findings
            
        Returns:
            str: Formatted findings summary
        """
        if not findings:
            return "No significant security findings identified."
        
        # Group findings by severity
        by_severity = {
            'critical': [], 'high': [], 'medium': [], 'low': [], 'info': []
        }
        
        for finding in findings:
            severity = finding.get('severity', 'info').lower()
            if severity not in by_severity:
                by_severity['info'].append(finding)
            else:
                by_severity[severity].append(finding)
        
        # Create summary
        summary_lines = ["## Security Findings Summary\n"]
        
        for severity in ['critical', 'high', 'medium', 'low', 'info']:
            findings_list = by_severity[severity]
            if findings_list:
                count = len(findings_list)
                summary_lines.append(f"**{severity.upper()}** ({count} findings):")
                for finding in findings_list[:3]:  # Limit display
                    summary_lines.append(f"  • {finding.get('description', 'Unknown issue')}")
                if count > 3:
                    summary_lines.append(f"  ... and {count - 3} more")
                summary_lines.append("")
        
        return "\n".join(summary_lines)
