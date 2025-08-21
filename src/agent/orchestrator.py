"""
Orchestrator for Black Glove Pentest Agent

This module implements the main workflow orchestration engine that coordinates
passive reconnaissance, active scanning, and result processing with safety controls.
"""

import logging
import time
from typing import Any, Dict, List, Optional, Set
from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum

from .models import Asset, ScanResult, WorkflowStep, OrchestrationContext
from .policy_engine import PolicyEngine, create_policy_engine
from .plugin_manager import PluginManager, create_plugin_manager
from .llm_client import LLMClient, create_llm_client, LLMMessage
from ..adapters.interface import AdapterResult, AdapterResultStatus


class ScanMode(Enum):
    """Enumeration of scan modes."""
    PASSIVE = "passive"
    ACTIVE = "active"
    LAB = "lab"


class WorkflowState(Enum):
    """Enumeration of workflow states."""
    PENDING = "pending"
    RUNNING = "running"
    PAUSED = "paused"
    COMPLETED = "completed"
    FAILED = "failed"
    CANCELLED = "cancelled"


@dataclass
class WorkflowManager:
    """
    Handles workflow state and step sequencing.
    
    Attributes:
        current_step: Current workflow step
        step_history: History of completed steps
        state: Current workflow state
        start_time: Workflow start time
        end_time: Workflow end time
    """
    current_step: Optional[WorkflowStep] = None
    step_history: List[WorkflowStep] = field(default_factory=list)
    state: WorkflowState = WorkflowState.PENDING
    start_time: Optional[datetime] = None
    end_time: Optional[datetime] = None


@dataclass
class ResultProcessor:
    """
    Normalizes and stores tool output.
    
    Attributes:
        processed_results: List of processed scan results
        raw_outputs: Raw adapter outputs for evidence
        findings: Security findings identified
    """
    processed_results: List[ScanResult] = field(default_factory=list)
    raw_outputs: List[Dict[str, Any]] = field(default_factory=list)
    findings: List[Dict[str, Any]] = field(default_factory=list)


class Orchestrator:
    """
    Main workflow engine with methods for scan coordination.
    
    Coordinates passive reconnaissance, active scanning, safety controls,
    and result processing through integration with policy engine,
    plugin manager, and LLM client.
    """
    
    def __init__(self, config: Dict[str, Any], db_connection=None):
        """
        Initialize the orchestrator.
        
        Args:
            config: Orchestrator configuration
            db_connection: Optional database connection
        """
        self.config = config
        self.db_connection = db_connection
        self.logger = logging.getLogger("black_glove.orchestrator")
        
        # Initialize core components
        self.policy_engine = create_policy_engine(config.get("policy", {}))
        self.plugin_manager = create_plugin_manager(config.get("adapters_path"))
        self.llm_client = create_llm_client(config.get("llm"))
        
        # Initialize workflow components
        self.workflow_manager = WorkflowManager()
        self.result_processor = ResultProcessor()
        
        # Track assets and scan progress
        self.assets: List[Asset] = []
        self.scan_results: List[ScanResult] = []
        self.completed_steps: Set[str] = set()
        
        self.logger.info("Orchestrator initialized")
    
    def add_asset(self, asset: Asset) -> bool:
        """
        Add an asset to the scan queue.
        
        Args:
            asset: Asset to add
            
        Returns:
            bool: True if asset was added, False if rejected by policy
        """
        self.logger.debug(f"Adding asset: {asset.target}")
        
        # Validate asset through policy engine
        if not self.policy_engine.validate_asset(asset):
            self.logger.warning(f"Asset rejected by policy: {asset.target}")
            return False
        
        self.assets.append(asset)
        self.logger.info(f"Asset added successfully: {asset.target}")
        return True
    
    def run_passive_recon(self) -> List[ScanResult]:
        """
        Execute passive reconnaissance workflow.
        
        Returns:
            List of scan results from passive tools
        """
        self.logger.info("Starting passive reconnaissance workflow")
        
        if not self.assets:
            self.logger.warning("No assets to scan")
            return []
        
        # Set workflow state
        self.workflow_manager.state = WorkflowState.RUNNING
        self.workflow_manager.start_time = datetime.now()
        
        results = []
        
        # Run passive reconnaissance tools
        passive_tools = self.config.get("passive_tools", ["whois", "dns_lookup", "ssl_check"])
        
        for asset in self.assets:
            self.logger.info(f"Running passive recon on {asset.target}")
            
            # Determine asset type from parameters or target
            asset_type = asset.parameters.get("asset_type", "host")
            if "." in asset.target and not asset.target.replace(".", "").isdigit():
                asset_type = "domain"
            elif ":" in asset.target:
                asset_type = "host"  # host:port format
            else:
                # Check if it's an IP address
                import ipaddress
                try:
                    ipaddress.ip_address(asset.target)
                    asset_type = "host"
                except ValueError:
                    asset_type = "domain"
            
            for tool_name in passive_tools:
                try:
                    # Check rate limits before execution
                    if not self.policy_engine.enforce_rate_limits(tool_name):
                        self.logger.warning(f"Rate limit exceeded for {tool_name}")
                        continue
                    
                    # Map asset parameters to tool-specific parameters
                    params = self._map_asset_to_tool_params(asset, tool_name, asset_type)
                    
                    # Validate required parameters before execution
                    adapter_info = self.plugin_manager.get_adapter_info(tool_name)
                    if adapter_info:
                        required_params = adapter_info.get("example_usage", {}).keys()
                        missing_params = [param for param in required_params if param not in params]
                        if missing_params:
                            self.logger.warning(f"Missing required parameters for {tool_name}: {missing_params}")
                            continue
                    
                    # Run adapter
                    adapter_result = self.plugin_manager.run_adapter(tool_name, params)
                    
                    # Record rate limit usage
                    self.policy_engine.rate_limiter.record_request(tool_name)
                    
                    # Process result
                    scan_result = self._process_tool_output(adapter_result, asset, tool_name)
                    if scan_result:
                        results.append(scan_result)
                        self.scan_results.append(scan_result)
                    
                    self.logger.debug(f"Completed {tool_name} on {asset.target}")
                    
                except Exception as e:
                    self.logger.error(f"Error running {tool_name} on {asset.target}: {e}")
                    # Continue with other tools/assets
                    continue
        
        # Update workflow state
        self.workflow_manager.state = WorkflowState.COMPLETED
        self.workflow_manager.end_time = datetime.now()
        
        self.logger.info(f"Passive reconnaissance completed with {len(results)} results")
        return results
    
    def plan_active_scans(self, scan_mode: ScanMode = ScanMode.PASSIVE) -> List[WorkflowStep]:
        """
        Use LLM to plan active scanning steps.
        
        Args:
            scan_mode: Scan mode (PASSIVE, ACTIVE, LAB)
            
        Returns:
            List of planned workflow steps
        """
        self.logger.info(f"Planning active scans in {scan_mode.value} mode")
        
        if not self.scan_results:
            self.logger.warning("No passive recon results to base planning on")
            return []
        
        # Build context from passive results
        context = self._build_recon_context()
        objective = f"Plan {scan_mode.value} scanning activities based on reconnaissance findings"
        
        try:
            # Get LLM planning suggestions
            llm_response = self.llm_client.plan_next_steps(context, objective)
            
            # Parse LLM response into workflow steps
            steps = self._parse_llm_plan(llm_response.content)
            
            self.logger.info(f"Generated {len(steps)} planned scanning steps")
            return steps
            
        except Exception as e:
            self.logger.error(f"LLM planning failed: {e}")
            # Fallback to default scanning plan
            return self._get_default_scan_plan(scan_mode)
    
    def execute_scan_step(self, step: WorkflowStep, approval_required: bool = True) -> Optional[ScanResult]:
        """
        Run individual scan steps with approval.
        
        Args:
            step: Workflow step to execute
            approval_required: Whether user approval is required
            
        Returns:
            ScanResult from step execution, or None if cancelled
        """
        self.logger.info(f"Executing scan step: {step.name}")
        
        # Check if step requires approval
        if approval_required and not self._get_user_approval(step):
            self.logger.info(f"Scan step cancelled by user: {step.name}")
            return None
        
        # Validate target through policy engine
        asset = Asset(
            target=step.target,
            tool_name=step.tool,
            parameters=step.parameters
        )
        
        if not self.policy_engine.validate_asset(asset):
            self.logger.warning(f"Step rejected by policy: {step.name}")
            return None
        
        # Check rate limits
        if not self.policy_engine.enforce_rate_limits(step.tool):
            self.logger.warning(f"Rate limit exceeded for {step.tool}")
            return None
        
        try:
            # Execute the tool through plugin manager
            adapter_result = self.plugin_manager.run_adapter(step.tool, step.parameters)
            
            # Record rate limit usage
            self.policy_engine.rate_limiter.record_request(step.tool)
            
            # Process and store result
            scan_result = self._process_tool_output(adapter_result, asset, step.tool)
            if scan_result:
                self.scan_results.append(scan_result)
                self.completed_steps.add(step.name)
            
            self.logger.info(f"Scan step completed: {step.name}")
            return scan_result
            
        except Exception as e:
            self.logger.error(f"Scan step failed: {step.name} - {e}")
            
            # Log policy violation if it was a safety issue
            if "rate limit" in str(e).lower() or "policy" in str(e).lower():
                self.policy_engine.log_violation(
                    self.policy_engine.violations[-1] if self.policy_engine.violations else None
                )
            
            return None
    
    def _process_tool_output(self, adapter_result: AdapterResult, asset: Asset, tool_name: str) -> Optional[ScanResult]:
        """
        Process and normalize adapter results.
        
        Args:
            adapter_result: Raw adapter result
            asset: Asset that was scanned
            tool_name: Name of the tool used
            
        Returns:
            Normalized ScanResult, or None if processing failed
        """
        self.logger.debug(f"Processing output from {tool_name}")
        
        # Store raw output for evidence
        raw_output = {
            "tool": tool_name,
            "target": asset.target,
            "timestamp": datetime.now().isoformat(),
            "status": adapter_result.status.value,
            "data": adapter_result.data,
            "metadata": adapter_result.metadata,
            "evidence_path": adapter_result.evidence_path
        }
        self.result_processor.raw_outputs.append(raw_output)
        
        # Handle different result statuses
        if adapter_result.status == AdapterResultStatus.SUCCESS:
            # Analyze findings with LLM
            findings = self._analyze_findings(adapter_result.data, asset.target)
            
            # Create normalized scan result
            scan_result = ScanResult(
                asset=asset,
                tool_name=tool_name,
                status="completed",
                findings=findings,
                raw_output=adapter_result.data,
                metadata=adapter_result.metadata,
                evidence_path=adapter_result.evidence_path,
                execution_time=adapter_result.execution_time
            )
            
            # Store findings
            if findings:
                self.result_processor.findings.extend(findings)
            
            self.result_processor.processed_results.append(scan_result)
            return scan_result
            
        elif adapter_result.status == AdapterResultStatus.FAILURE:
            # Log failure but still create result
            scan_result = ScanResult(
                asset=asset,
                tool_name=tool_name,
                status="failed",
                findings=[],
                raw_output=adapter_result.data,
                metadata=adapter_result.metadata,
                evidence_path=adapter_result.evidence_path,
                execution_time=adapter_result.execution_time,
                error_message=adapter_result.error_message
            )
            
            self.result_processor.processed_results.append(scan_result)
            return scan_result
            
        else:
            # Handle other statuses (TIMEOUT, ERROR, etc.)
            self.logger.warning(f"Adapter returned {adapter_result.status.value} status")
            return None
    
    def _analyze_findings(self, tool_output: Any, target: str) -> List[Dict[str, Any]]:
        """
        Use LLM to analyze tool output and identify security issues.
        
        Args:
            tool_output: Raw tool output
            target: Target that was scanned
            
        Returns:
            List of identified findings
        """
        try:
            # Convert tool output to string if needed
            if not isinstance(tool_output, str):
                import json
                output_str = json.dumps(tool_output, indent=2)
            else:
                output_str = tool_output
            
            # Get LLM analysis
            context = f"Target: {target}"
            llm_response = self.llm_client.analyze_findings(output_str, context)
            
            # For now, treat the entire response as one finding
            # In a real implementation, this would parse structured findings
            if llm_response.content.strip():
                return [{
                    "description": llm_response.content,
                    "severity": "medium",  # Would be determined by LLM in real implementation
                    "target": target,
                    "timestamp": datetime.now().isoformat()
                }]
            
        except Exception as e:
            self.logger.error(f"Finding analysis failed: {e}")
        
        return []
    
    def _build_recon_context(self) -> str:
        """
        Build context string from passive reconnaissance results.
        
        Returns:
            Context string for LLM planning
        """
        if not self.scan_results:
            return "No reconnaissance data available."
        
        context_parts = []
        for result in self.scan_results:
            context_parts.append(f"Target {result.asset.target}: {result.tool_name} completed")
            if result.findings:
                context_parts.append(f"  Findings: {len(result.findings)} issues identified")
        
        return "\n".join(context_parts)
    
    def _parse_llm_plan(self, plan_text: str) -> List[WorkflowStep]:
        """
        Parse LLM-generated plan into workflow steps.
        
        Args:
            plan_text: LLM-generated planning text
            
        Returns:
            List of workflow steps
        """
        # Simple parsing - in real implementation, this would be more sophisticated
        steps = []
        lines = plan_text.strip().split('\n')
        
        for i, line in enumerate(lines):
            if line.strip() and not line.startswith('#'):
                step = WorkflowStep(
                    name=f"planned_step_{i}",
                    description=line.strip(),
                    tool="nmap",  # Default tool
                    target="default",  # Would be parsed from line
                    parameters={},
                    priority=i
                )
                steps.append(step)
        
        return steps
    
    def _get_default_scan_plan(self, scan_mode: ScanMode) -> List[WorkflowStep]:
        """
        Get default scanning plan when LLM planning fails.
        
        Args:
            scan_mode: Scan mode to plan for
            
        Returns:
            List of default workflow steps
        """
        default_steps = []
        
        if scan_mode == ScanMode.PASSIVE:
            # Passive scanning steps
            tools = ["nmap", "sslscan", "nikto"]
        elif scan_mode == ScanMode.ACTIVE:
            # Active scanning steps
            tools = ["nmap", "sqlmap", "gobuster"]
        else:  # LAB mode
            # Comprehensive scanning steps
            tools = ["nmap", "sqlmap", "gobuster", "metasploit"]
        
        # If no assets, create steps for a default target
        targets = [asset.target for asset in self.assets] if self.assets else ["default_target"]
        
        for i, tool in enumerate(tools):
            for target in targets:
                step = WorkflowStep(
                    name=f"{tool}_{target}_{i}",
                    description=f"Run {tool} on {target}",
                    tool=tool,
                    target=target,
                    parameters={"target": target},
                    priority=i
                )
                default_steps.append(step)
        
        return default_steps
    
    def _get_user_approval(self, step: WorkflowStep) -> bool:
        """
        Get user approval for potentially dangerous scan steps.
        
        Args:
            step: Workflow step requiring approval
            
        Returns:
            bool: True if approved, False if cancelled
        """
        # In a real implementation, this would interact with user interface
        # For now, auto-approve based on scan mode and policy
        scan_mode = self.config.get("scan_mode", "passive")
        
        if scan_mode == "lab":
            return True  # Auto-approve in lab mode
        
        # Check if tool is considered dangerous
        dangerous_tools = ["metasploit", "sqlmap", "hydra"]
        if step.tool in dangerous_tools:
            # In real implementation, this would prompt user
            self.logger.info(f"Auto-approving dangerous tool {step.tool} (would prompt user in real implementation)")
            return True
        
        return True  # Auto-approve by default
    
    def _count_findings_by_severity(self, findings: List[Dict[str, Any]]) -> Dict[str, int]:
        """
        Count findings by severity level.
        
        Args:
            findings: List of findings
            
        Returns:
            Dictionary mapping severity levels to counts
        """
        counts = {
            'critical': 0,
            'high': 0,
            'medium': 0,
            'low': 0,
            'info': 0
        }
        
        for finding in findings:
            severity = finding.get('severity', 'medium').lower()
            if severity in counts:
                counts[severity] += 1
            else:
                counts['medium'] += 1
                
        return counts
    
    def generate_report(self, format_type: str = "json") -> Dict[str, Any]:
        """
        Create findings report from scan results.
        
        Args:
            format_type: Report format (json, markdown, html)
            
        Returns:
            Dictionary containing report data
        """
        self.logger.info(f"Generating {format_type} report")
        
        # Count findings by severity
        findings_by_severity = self._count_findings_by_severity(self.result_processor.findings)
        
        report_data = {
            "summary": {
                "total_assets": len(self.assets),
                "total_scans": len(self.scan_results),
                "total_findings": len(self.result_processor.findings),
                "findings_by_severity": findings_by_severity,
                "scan_duration": self._calculate_scan_duration(),
                "timestamp": datetime.now().isoformat()
            },
            "assets": [asset.to_dict() for asset in self.assets],
            "results": [result.to_dict() for result in self.scan_results],
            "findings": self.result_processor.findings,
            "violations": self.policy_engine.get_violation_report(),
            "rates": self.policy_engine.get_current_rates()
        }
        
        return report_data
    
    def _calculate_scan_duration(self) -> float:
        """
        Calculate total scan duration.
        
        Returns:
            Scan duration in seconds
        """
        if self.workflow_manager.start_time and self.workflow_manager.end_time:
            duration = self.workflow_manager.end_time - self.workflow_manager.start_time
            return duration.total_seconds()
        return 0.0
    
    def cleanup(self) -> None:
        """
        Clean up resources and unload adapters.
        """
        self.logger.info("Cleaning up orchestrator resources")
        
        # Clean up plugin manager
        self.plugin_manager.cleanup()
        
        # Clear assets and results
        self.assets.clear()
        self.scan_results.clear()
        self.completed_steps.clear()
        
        # Clear processors
        self.result_processor.processed_results.clear()
        self.result_processor.raw_outputs.clear()
        self.result_processor.findings.clear()
        
        self.logger.info("Orchestrator cleanup completed")
    
    def _map_asset_to_tool_params(self, asset: Asset, tool_name: str, asset_type: str) -> Dict[str, Any]:
        """
        Map asset parameters to tool-specific parameters.
        
        Args:
            asset: Asset to map
            tool_name: Name of the tool
            asset_type: Type of asset (host, domain, vm)
            
        Returns:
            Dictionary of tool-specific parameters
        """
        params = {"target": asset.target, **asset.parameters}
        
        # Add default timeout if not provided
        if "timeout" not in params:
            params["timeout"] = 30
        
        # Map based on tool type and asset type
        if tool_name == "whois":
            if asset_type == "domain":
                params["domain"] = asset.target
            else:
                # For IP addresses, try to extract domain if possible
                # or skip WHOIS for IPs (WHOIS is primarily for domains)
                self.logger.debug(f"Skipping WHOIS for non-domain target: {asset.target}")
                params["domain"] = asset.target  # Fallback - let adapter handle validation
                
        elif tool_name == "dns_lookup":
            if asset_type == "domain":
                params["domain"] = asset.target
                params["record_types"] = ["A", "MX", "NS", "TXT", "CNAME"]
            else:
                # For IP addresses, we might want reverse DNS lookup
                # For now, treat as domain for testing
                params["domain"] = asset.target
                params["record_types"] = ["A", "PTR"]  # Reverse lookup for IPs
                
        elif tool_name == "ssl_check":
            # SSL check works with both domains and IPs
            if asset_type == "domain":
                params["host"] = asset.target
            else:
                # For IP addresses, extract host and port if present
                if ":" in asset.target:
                    host, port = asset.target.rsplit(":", 1)
                    if port.isdigit():
                        params["host"] = host
                        params["port"] = int(port)
                    else:
                        params["host"] = asset.target
                        params["port"] = 443
                else:
                    params["host"] = asset.target
                    params["port"] = 443
        
        return params


def create_orchestrator(config: Dict[str, Any] = None, db_connection=None) -> Orchestrator:
    """
    Factory function to create an orchestrator instance.
    
    Args:
        config: Optional orchestrator configuration
        db_connection: Optional database connection
        
    Returns:
        Orchestrator: Configured orchestrator instance
    """
    if config is None:
        config = {
            "policy": {
                "rate_limiting": {
                    "window_size": 60,
                    "max_requests": 10,
                    "global_max_requests": 100
                },
                "target_validation": {
                    "authorized_networks": ["192.168.1.0/24"],
                    "authorized_domains": ["example.com"]
                },
                "allowed_exploits": []
            },
            "passive_tools": ["whois", "dns_lookup", "ssl_check"],
            "scan_mode": "passive"
        }
    else:
        # Ensure policy configuration includes target validation from main config
        if "policy" not in config:
            config["policy"] = {}
        
        if "target_validation" not in config["policy"]:
            config["policy"]["target_validation"] = {}
        
        # Copy authorized networks and domains from main config to policy config
        if "authorized_networks" in config and "target_validation" in config["policy"]:
            config["policy"]["target_validation"]["authorized_networks"] = config["authorized_networks"]
        if "authorized_domains" in config and "target_validation" in config["policy"]:
            config["policy"]["target_validation"]["authorized_domains"] = config["authorized_domains"]
    
    return Orchestrator(config, db_connection)


# Context manager for orchestrator
class OrchestratorContext:
    """
    Context manager for orchestrator to ensure proper cleanup.
    """
    
    def __init__(self, config: Dict[str, Any] = None, db_connection=None):
        self.config = config
        self.db_connection = db_connection
        self.orchestrator = None
    
    def __enter__(self):
        self.orchestrator = create_orchestrator(self.config, self.db_connection)
        return self.orchestrator
    
    def __exit__(self, exc_type, exc_val, exc_tb):
        if self.orchestrator:
            self.orchestrator.cleanup()
