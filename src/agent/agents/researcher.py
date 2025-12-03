"""
Researcher Agent for Black Glove pentest agent.
Responsible for executing security tools and parsing raw output.
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

class ResearcherAgent(BaseAgent):
    """
    Agent responsible for executing security tools and parsing results.
    
    Takes structured tool calls and executes them using the PluginManager,
    then processes and normalizes the output for analysis.
    """
    
    def __init__(self, llm_client: LLMClient, plugin_manager: PluginManager, policy_engine: Any, session_id: str = None):
        """
        Initialize the Researcher Agent.
        
        Args:
            llm_client: LLM client for generating responses
            plugin_manager: Plugin manager for tool execution
            policy_engine: Policy engine for safety enforcement
            session_id: Optional session ID for context
        """
        super().__init__(llm_client, session_id)
        self.plugin_manager = plugin_manager
        self.policy_engine = policy_engine
        self.role = "researcher"
        
        # Set up tools available to this agent dynamically
        self.tools = self.plugin_manager.discover_adapters()
        # Ensure management tools are included if not discovered
        management_tools = ["add_asset", "list_assets", "generate_report"]
        for tool in management_tools:
            if tool not in self.tools:
                self.tools.append(tool)
                
        self.set_tools(self.tools)
    
    def execute_tool_step(self, workflow_step: WorkflowStep) -> str:
        """
        Execute a single tool step from a workflow plan.
        
        Args:
            workflow_step: Workflow step to execute
            
        Returns:
            str: Result of the tool execution
        """
        self.logger.info(f"Executing workflow step: {workflow_step.tool} on {workflow_step.target}")
        
        # Execute the tool
        result = self.execute_tool(
            tool_name=workflow_step.tool,
            parameters={
                "target": workflow_step.target,
                **workflow_step.parameters
            }
        )
        
        return result
    
    def execute_tool(self, tool_name: str, parameters: Dict[str, Any]) -> str:
        """
        Execute a specific tool with given parameters.
        
        Args:
            tool_name: Name of the tool to execute
            parameters: Parameters for the tool
            
        Returns:
            str: Formatted result of tool execution
        """
        self.logger.info(f"Executing tool: {tool_name} with params: {parameters}")
        
        try:
            # Check if tool is available
            if not self.validate_tool(tool_name):
                return f"ERROR: Tool '{tool_name}' is not available for researcher agent"
            
            # 1. Safety Check: Validate Target
            # Construct a temporary asset object for validation
            # We need to extract the target from parameters
            target = parameters.get("target")
            if target:
                from ..models import Asset
                # Create a temporary asset for validation
                asset = Asset(
                    target=target,
                    tool_name=tool_name,
                    parameters=parameters
                )
                
                if not self.policy_engine.validate_asset(asset):
                    self.logger.warning(f"BLOCKED: Policy violation for target {target}")
                    return f"BLOCKED: Action blocked by safety policy. Target '{target}' is not authorized."
            
            # 2. Safety Check: Rate Limiting
            if not self.policy_engine.enforce_rate_limits(tool_name):
                self.logger.warning(f"BLOCKED: Rate limit exceeded for {tool_name}")
                return f"BLOCKED: Rate limit exceeded for tool '{tool_name}'. Please try again later."
            
            # Execute via plugin manager
            if tool_name in ["add_asset", "list_assets", "generate_report"]:
                # Handle management tools directly
                result = self._execute_management_tool(tool_name, parameters)
            else:
                # Handle security tools via plugin manager
                adapter_result = self.plugin_manager.execute_tool(tool_name, parameters)
                
                # Record rate limit usage
                self.policy_engine.rate_limiter.record_request(tool_name)
                
                if adapter_result.success:
                    result = self._format_tool_result(tool_name, adapter_result)
                else:
                    result = f"ERROR executing {tool_name}: {adapter_result.stderr}"
            
            # Log the action
            self.log_action(f"Tool execution: {tool_name}", {
                "parameters": parameters,
                "result_length": len(result),
                "success": "ERROR" not in result[:20] and "BLOCKED" not in result[:20]
            })
            
            return result
            
        except Exception as e:
            error_msg = f"ERROR: Failed to execute {tool_name}: {str(e)}"
            self.logger.error(error_msg)
            return error_msg
    
    def _execute_management_tool(self, tool_name: str, parameters: Dict[str, Any]) -> str:
        """
        Execute management tools (asset operations, reporting).
        
        Args:
            tool_name: Name of the management tool
            parameters: Tool parameters
            
        Returns:
            str: Result of management tool execution
        """
        try:
            if tool_name == "add_asset":
                # Import and execute asset management
                from ..adapters.asset_manager import run as asset_manager_run
                
                result = asset_manager_run({
                    "command": "add",
                    **parameters
                })
                
                return f"Asset Management: {result.stdout}" if result.success else f"Asset Management Error: {result.stderr}"
            
            elif tool_name == "list_assets":
                from ..adapters.asset_manager import run as asset_manager_run
                
                result = asset_manager_run({"command": "list"})
                
                return f"Asset List:\n{result.stdout}" if result.success else f"Asset List Error: {result.stderr}"
            
            elif tool_name == "generate_report":
                from ..adapters.asset_manager import run as asset_manager_run
                
                result = asset_manager_run({
                    "command": "report",
                    **parameters
                })
                
                return f"Report Generated:\n{result.stdout}" if result.success else f"Report Generation Error: {result.stderr}"
            
            else:
                return f"Unknown management tool: {tool_name}"
                
        except Exception as e:
            return f"ERROR in management tool {tool_name}: {str(e)}"
    
    def _format_tool_result(self, tool_name: str, adapter_result) -> str:
        """
        Format tool result for human-readable output.
        
        Args:
            tool_name: Name of the executed tool
            adapter_result: Result from adapter execution
            
        Returns:
            str: Formatted result
        """
        try:
            # Start with basic status
            if adapter_result.success:
                result_lines = [f"✅ {tool_name.upper()} executed successfully"]
            else:
                result_lines = [f"❌ {tool_name.upper()} execution failed"]
            
            # Add stdout if available
            if adapter_result.stdout:
                stdout_lines = adapter_result.stdout.strip().split('\n')
                if stdout_lines and stdout_lines[0]:
                    result_lines.append("\n📤 OUTPUT:")
                    # Truncate very long outputs
                    if len(stdout_lines) > 50:
                        result_lines.extend(stdout_lines[:25])
                        result_lines.append(f"... ({len(stdout_lines) - 50} more lines truncated)")
                        result_lines.extend(stdout_lines[-25:])
                    else:
                        result_lines.extend(stdout_lines)
            
            # Add stderr if available and not empty
            if adapter_result.stderr and adapter_result.stderr.strip():
                stderr_lines = adapter_result.stderr.strip().split('\n')
                if stderr_lines and stderr_lines[0]:
                    result_lines.append("\n⚠️ ERRORS/WARNINGS:")
                    result_lines.extend(stderr_lines[:10])  # Limit error output
            
            # Add metadata if available
            if hasattr(adapter_result, 'metadata') and adapter_result.metadata:
                result_lines.append("\n📊 METADATA:")
                for key, value in adapter_result.metadata.items():
                    if key != 'evidence_path' or not adapter_result.metadata.get('evidence_path'):
                        result_lines.append(f"  • {key}: {value}")
                
                # Add evidence path if available
                if adapter_result.metadata.get('evidence_path'):
                    result_lines.append(f"  • evidence: {adapter_result.metadata['evidence_path']}")
            
            return '\n'.join(result_lines)
            
        except Exception as e:
            return f"ERROR formatting result: {str(e)}"
    
    def parse_tool_output(self, tool_name: str, raw_output: str) -> Dict[str, Any]:
        """
        Parse raw tool output into structured data.
        
        Args:
            tool_name: Name of the tool that produced the output
            raw_output: Raw output from tool execution
            
        Returns:
            Dict[str, Any]: Parsed and structured output
        """
        self.logger.debug(f"Parsing output from {tool_name}")
        
        try:
            if tool_name == "nmap":
                return self._parse_nmap_output(raw_output)
            elif tool_name == "gobuster":
                return self._parse_gobuster_output(raw_output)
            elif tool_name == "whois":
                return self._parse_whois_output(raw_output)
            elif tool_name == "dns_lookup":
                return self._parse_dns_output(raw_output)
            else:
                # For unknown tools, return basic structure
                return {
                    "tool": tool_name,
                    "raw_output": raw_output,
                    "parsed": False,
                    "timestamp": datetime.now().isoformat()
                }
                
        except Exception as e:
            self.logger.error(f"Error parsing {tool_name} output: {str(e)}")
            return {
                "tool": tool_name,
                "error": str(e),
                "raw_output": raw_output,
                "timestamp": datetime.now().isoformat()
            }
    
    def _parse_nmap_output(self, output: str) -> Dict[str, Any]:
        """Parse Nmap output into structured data."""
        # Basic Nmap parsing - look for open ports and services
        ports = []
        services = []
        
        # Look for port lines like "22/tcp open  ssh"
        port_pattern = r'(\d+)/tcp\s+(\w+)\s+(.+)'
        matches = re.findall(port_pattern, output)
        
        for port, state, service in matches:
            ports.append({
                "port": int(port),
                "state": state,
                "service": service.strip()
            })
            services.append(service.strip())
        
        return {
            "tool": "nmap",
            "ports": ports,
            "services": services,
            "open_ports_count": len(ports),
            "timestamp": datetime.now().isoformat()
        }
    
    def _parse_gobuster_output(self, output: str) -> Dict[str, Any]:
        """Parse Gobuster output into structured data."""
        paths = []
        
        # Look for discovered paths
        path_pattern = r'(.+?)\s+[=\s]+'
        matches = re.findall(path_pattern, output)
        
        for path in matches:
            if path.startswith('/') and path.strip():
                paths.append(path.strip())
        
        return {
            "tool": "gobuster",
            "paths": paths,
            "paths_count": len(paths),
            "timestamp": datetime.now().isoformat()
        }
    
    def _parse_whois_output(self, output: str) -> Dict[str, Any]:
        """Parse WHOIS output into structured data."""
        info = {}
        
        # Extract common WHOIS fields
        whois_fields = {
            'Registrar': r'Registrar:\s*(.+)',
            'Creation Date': r'Creation Date:\s*(.+)',
            'Expiry Date': r'Expiry Date:\s*(.+)',
            'Name Server': r'Name Server:\s*(.+)',
            'Registrant': r'Registrant:\s*(.+)',
            'Admin Email': r'Admin Email:\s*(.+)'
        }
        
        for field, pattern in whois_fields.items():
            match = re.search(pattern, output, re.IGNORECASE)
            if match:
                info[field.lower().replace(' ', '_')] = match.group(1).strip()
        
        return {
            "tool": "whois",
            "info": info,
            "raw_output": output[:1000] + "..." if len(output) > 1000 else output,
            "timestamp": datetime.now().isoformat()
        }
    
    def _parse_dns_output(self, output: str) -> Dict[str, Any]:
        """Parse DNS lookup output into structured data."""
        records = []
        
        # Basic DNS record parsing
        record_pattern = r'([A-Z]+)\s+(\d+)\s+IN\s+([A-Z]+)\s+(.+)'
        matches = re.findall(record_pattern, output)
        
        for record_type, ttl, class_type, value in matches:
            records.append({
                "type": record_type,
                "ttl": int(ttl),
                "class": class_type,
                "value": value.strip()
            })
        
        return {
            "tool": "dns_lookup",
            "records": records,
            "records_count": len(records),
            "timestamp": datetime.now().isoformat()
        }
    
    def batch_execute(self, tool_calls: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """
        Execute multiple tool calls in sequence.
        
        Args:
            tool_calls: List of tool call dictionaries
            
        Returns:
            List[Dict[str, Any]]: Results of tool executions
        """
        results = []
        
        for i, tool_call in enumerate(tool_calls):
            self.logger.info(f"Executing tool {i+1}/{len(tool_calls)}: {tool_call.get('tool')}")
            
            tool_name = tool_call.get('tool')
            parameters = tool_call.get('parameters', {})
            
            result = self.execute_tool(tool_name, parameters)
            parsed_result = self.parse_tool_output(tool_name, result)
            
            results.append({
                "tool": tool_name,
                "parameters": parameters,
                "result": result,
                "parsed": parsed_result,
                "success": "ERROR" not in result[:20]
            })
            
            # Small delay between tools to be respectful
            import time
            time.sleep(0.5)
        
        return results
    
    def get_role_description(self) -> str:
        """Get description of the researcher agent's role."""
        return """Security tool executor and data parser. You are responsible for:
1. Executing security reconnaissance tools (nmap, gobuster, whois, dns_lookup, etc.)
2. Parsing and normalizing tool output into structured data
3. Handling tool errors gracefully and reporting them clearly
4. Managing tool execution with proper validation and safety checks
5. Providing formatted, human-readable results

You maintain a focus on accuracy and completeness in data collection."""
    
    def get_available_tools_summary(self) -> str:
        """
        Get a summary of available tools for this agent.
        
        Returns:
            str: Summary of available tools
        """
        tool_registry = self.get_tool_registry()
        tools_by_category = tool_registry.get_tools_by_category()
        
        summary_lines = ["Available tools by category:"]
        for category, tools in tools_by_category.items():
            summary_lines.append(f"\n{category.upper()}:")
            for tool in tools:
                tool_info = tool_registry.get_tool_info(tool)
                summary_lines.append(f"  • {tool}: {tool_info['description']}")
        
        return '\n'.join(summary_lines)
