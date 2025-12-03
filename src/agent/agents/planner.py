"""
Planner Agent for Black Glove pentest agent.
Responsible for breaking down high-level goals into actionable scanning tasks.
"""

import json
import re
from typing import List, Dict, Any, Optional
from datetime import datetime

from ..llm_client import LLMClient, LLMMessage, LLMConfig, LLMProvider, LLMResponse
from ..db import get_db_connection
from ..models import WorkflowStep, ScanPlan
from .base import BaseAgent

class PlannerAgent(BaseAgent):
    """
    Agent responsible for planning scanning workflows.
    
    Takes a high-level goal (e.g., "scan my home router") and breaks it down
    into specific, executable steps using reconnaissance tools.
    """
    
    def __init__(self, llm_client: LLMClient, session_id: str = None):
        """
        Initialize the Planner Agent.
        
        Args:
            llm_client: LLM client for generating plans
            session_id: Optional session ID for context
        """
        super().__init__(llm_client, session_id)
        self.role = "planner"
        self.tools = [
            "nmap", "gobuster", "whois", "dns_lookup", "ssl_check",
            "sublist3r", "wappalyzer", "shodan", "viewdns"
        ]
    
    def get_role_description(self) -> str:
        """
        Get a brief description of the PlannerAgent role.
        """
        return "Creates safe, prioritized multi-step scanning workflows. Ensures suggested tools are authorized, low-risk by default, and provides rationale for each step."
    
    def plan_workflow(self, goal: str, context: str = "") -> ScanPlan:
        """
        Plan a multi-step workflow for scanning based on the goal.
        
        Args:
            goal: User's scanning goal (e.g., "scan my home router")
            context: Additional context to guide planning
            
        Returns:
            ScanPlan: Structured plan with ordered steps to execute
        """
        self.logger.info(f"Planning workflow for goal: {goal}")
        
        # Build system prompt with role description
        system_prompt = f"""You are a cybersecurity planning expert responsible for creating safe and effective penetration testing workflows.
Your task is to break down high-level scanning goals into a sequence of specific, executable steps using authorized reconnaissance tools.
You must ONLY suggest scans on assets that have been previously added to the system and are in scope.

Available tools:
{', '.join(self.tools)}

For each step, specify:
1. Tool to use
2. Target asset (must match an existing asset)
3. Parameters
4. Priority
5. Detailed rationale (why this step is necessary, expected findings, safety considerations)

IMPORTANT: Respond ONLY with valid JSON that matches the expected schema. No additional text, explanations, or formatting.
        
Current context: {context if context else 'No additional context available'}"""

        # Build user prompt with goal
        user_prompt = f"Create a scanning workflow to achieve this goal: {goal}"

        # Generate response from LLM
        messages = [
            LLMMessage(role="system", content=system_prompt),
            LLMMessage(role="user", content=user_prompt)
        ]
        
        response = self.llm_client.generate(messages, structured=True)
        
        # Parse and validate the response
        try:
            plan_data = json.loads(response.content)
            return self._validate_scan_plan(plan_data, goal)
        except json.JSONDecodeError:
            self.logger.error("Failed to parse JSON response from LLM")
            return self._create_fallback_plan(goal)
    
    def _validate_scan_plan(self, plan_data: Dict, goal: str) -> ScanPlan:
        """
        Validate and structure the scan plan data from the LLM.
        
        Args:
            plan_data: Raw data from LLM response
            goal: Original scanning goal
            
        Returns:
            ScanPlan: Validated scan plan
        """
        try:
            # Validate required fields
            if "scan_plan" not in plan_data:
                raise ValueError("Missing required 'scan_plan' field in response")
            
            steps = []
            for step_data in plan_data["scan_plan"]:
                # Validate step fields
                required_fields = ["tool", "target", "parameters", "priority", "rationale"]
                for field in required_fields:
                    if field not in step_data:
                        raise ValueError(f"Missing required field '{field}' in scan step")
                
                # Validate tool is in our allowed set
                if step_data["tool"] not in self.tools:
                    raise ValueError(f"Unauthorized tool '{step_data['tool']}' requested")
                
                # Create WorkflowStep object
                step = WorkflowStep(
                    tool=step_data["tool"],
                    target=step_data["target"],
                    parameters=step_data["parameters"],
                    priority=step_data["priority"],
                    rationale=step_data["rationale"]
                )
                steps.append(step)
            
            # Sort steps by priority
            steps.sort(key=lambda x: x.priority)
            
            return ScanPlan(
                goal=goal,
                created_at=datetime.now().isoformat(),
                steps=steps
            )
        
        except Exception as e:
            self.logger.error(f"Validation failed for scan plan: {str(e)}")
            return self._create_fallback_plan(goal)
    
    def _create_fallback_plan(self, goal: str) -> ScanPlan:
        """
        Create a simple fallback plan if validation fails.
        
        Args:
            goal: Original scanning goal
            
        Returns:
            ScanPlan: Basic scan plan
        """
        self.logger.warning("Creating fallback scan plan due to validation issues")
        
        # Default to passive recon steps as fallback
        steps = [
            WorkflowStep(
                tool="whois",
                target="default-target",
                parameters={"domain": "example.com"},
                priority=1,
                rationale="Basic domain information gathering"
            ),
            WorkflowStep(
                tool="dns_lookup",
                target="default-target",
                parameters={"domain": "example.com"},
                priority=2,
                rationale="Basic DNS enumeration"
            )
        ]
        
        return ScanPlan(
            goal=goal,
            created_at=datetime.now().isoformat(),
            steps=steps
        )
    
    def get_available_assets(self) -> List[Dict]:
        """
        Get list of available assets from database.
        
        Returns:
            List[Dict]: List of asset details
        """
        conn = get_db_connection()
        cursor = conn.cursor()
        
        cursor.execute("SELECT id, name, type, value FROM assets")
        assets = cursor.fetchall()
        
        return [
            {"id": asset[0], "name": asset[1], "type": asset[2], "value": asset[3]}
            for asset in assets
        ]
    
    def update_context(self, new_context: str) -> None:
        """
        Update the agent's context with new information.
        
        Args:
            new_context: New context to add
        """
        self.context = new_context
        self.logger.debug(f"Planner context updated")
    
    def clear_context(self) -> None:
        """Clear the agent's context."""
        self.context = ""
        self.logger.debug("Planner context cleared")
