"""
Investigator Agent for Black Glove pentest agent.
The central coordinator that manages the ReAct (Reasoning-Action) loop and handles
user interaction by routing tasks to specialized agents.
"""

from typing import List, Dict, Any, Optional, Tuple, Generator
import logging
import json
import re
import time
from datetime import datetime

from ..llm_client import LLMClient, LLMMessage, LLMResponse
from ..rag.manager import RAGDocument
from ..plugin_manager import PluginManager
from .planner import PlannerAgent
from .researcher import ResearcherAgent
from .analyst import AnalystAgent
from .base import BaseAgent

class InvestigatorAgent(BaseAgent):
    """
    The central investigator agent that handles user interaction and coordinates
    the other specialized agents in a ReAct loop (Reasoning-Action).
    
    This agent:
    1. Receives user queries
    2. Determines if it needs to delegate to Planner (complex goals)
    3. Manages the ReAct loop for multi-step tool execution
    4. Handles session context and conversation flow
    """
    
    def __init__(
        self,
        llm_client: LLMClient,
        plugin_manager: PluginManager,
        policy_engine: Any,
        session_id: str = None
    ):
        """
        Initialize the Investigator Agent.
        
        Args:
            llm_client: LLM client for generating responses
            plugin_manager: Plugin manager for tool execution
            policy_engine: Policy engine for safety enforcement
            session_id: Session ID for context persistence
        """
        super().__init__(llm_client, session_id)
        self.plugin_manager = plugin_manager
        self.policy_engine = policy_engine
        self.planner = PlannerAgent(llm_client, session_id)
        self.researcher = ResearcherAgent(llm_client, plugin_manager, policy_engine, session_id)
        self.analyst = AnalystAgent(llm_client, session_id)
        self.role = "investigator"
        self.max_react_steps = 5  # Prevent infinite loops

    def get_role_description(self) -> str:
        """
        Get a brief description of the InvestigatorAgent role.
        """
        return "Coordinates multi-step reconnaissance workflows; delegates planning, execution, and analysis to specialized agents and manages session context."

    def handle_user_query(self, user_input: str) -> Generator[Dict[str, Any], None, None]:
        """
        Process a user query through the ReAct loop.
        
        Args:
            user_input: User's message or command
            
        Yields:
            Events for the CLI to render:
            - {'type': 'thinking', 'content': str} - Reasoning steps
            - {'type': 'tool_call', 'tool': str, 'params': dict} - Tool calls
            - {'type': 'tool_result', 'result': str} - Tool results
            - {'type': 'answer', 'content': str} - Final answer
        """
        self.logger.info(f"Handling user query: {user_input}")
        yield {"type": "thinking", "content": "Analyzing your request..."}
        
        # First, check if this is a complex goal requiring planning
        if self._requires_planning(user_input):
            yield {"type": "thinking", "content": "This requires a multi-step plan. Consulting the planner..."}
            scan_plan = self.planner.plan_workflow(user_input)
            
            # Execute the plan step by step
            for step in scan_plan.steps:
                yield {
                    "type": "thinking", 
                    "content": f"Executing step: {step.tool} on {step.target}"
                }
                
                # Execute the step and get intermediate result
                result = self.researcher.execute_tool_step(step)
                yield {"type": "tool_call", "tool": step.tool, "params": step.parameters}
                yield {"type": "tool_result", "result": result}
                
                # Let the analyst provide insights
                analysis = self.analyst.analyze_findings(result)
                yield {"type": "thinking", "content": f"Analyst: {analysis}"}
                
                # Update context with latest findings
                self.update_context(f"Step completed: {step.tool} on {step.target} - {analysis}")
        
        else:
            # Simple queries can go straight to ReAct loop
            yield from self._process_react_loop(user_input)
    
    def _process_react_loop(self, user_input: str) -> Generator[Dict[str, Any], None, None]:
        """
        Process a query using the ReAct (Reasoning-Action) loop.
        
        Args:
            user_input: User's message
            
        Yields:
            Events for the CLI as in handle_user_query
        """
        steps = 0
        remaining_input = user_input
        
        while steps < self.max_react_steps:
            steps += 1
            
            # 1. Reasoning step - decide what to do
            yield {"type": "thinking", "content": "Thinking about next action..."}
            action, params, rationale = self._decide_action(remaining_input)
            
            if not action:
                # If no action determined, provide direct answer
                break
            
            # 2. Action step - execute tool
            yield {
                "type": "thinking", 
                "content": f"Action: {rationale}" + 
                          (f" (Parameterizing: {params})" if params else "")
            }
            
            yield {"type": "tool_call", "tool": action, "params": params}
            result = self.researcher.execute_tool(action, params)
            yield {"type": "tool_result", "result": result}
            
            # 3. Observation step - analyze results
            analysis = self.analyst.analyze_findings(result)
            yield {"type": "thinking", "content": f"Analysis: {analysis}"}
            
            # 4. Determine if more steps needed
            if self._is_final_answer(analysis, remaining_input):
                yield {"type": "thinking", "content": "Final answer determined."}
                yield {"type": "answer", "content": analysis}
                return
            
            # Update remaining input with new context
            remaining_input += f"\n\nPrevious result: {analysis}"
        
        # If we didn't break via final answer, generate response
        final_response = self._generate_final_response(remaining_input)
        yield {"type": "answer", "content": final_response}
    
    def _requires_planning(self, user_input: str) -> bool:
        """
        Determine if a user query requires a multi-step plan.
        
        Args:
            user_input: User's message
            
        Returns:
            bool: True if complex goal requiring planning
        """
        planning_keywords = [
            "scan", "reconnaissance", "pentest", "security test", 
            "audit", "analyze", "find vulnerabilities", "test for"
        ]
        
        user_input = user_input.lower()
        return any(keyword in user_input for keyword in planning_keywords)
    
    def _decide_action(self, current_input: str) -> Tuple[Optional[str], Optional[Dict], str]:
        """
        Use LLM to decide next action in ReAct loop.
        
        Args:
            current_input: Current context including user query and prior results
            
        Returns:
            Tuple of (action, parameters, rationale)
        """
        # Get available tools dynamically
        available_tools = self.plugin_manager.discover_adapters()
        tool_list = ", ".join(available_tools)
        
        system_prompt = f"""You are an intelligent cybersecurity agent that decides on the next action to take.
Given the current context, determine if you need to use a tool to answer the query.
If you need to use a tool, specify:
- tool: name of the tool to use (must be one of: {tool_list}, add_asset, list_assets, generate_report)
- parameters: a JSON object with required parameters for the tool
- rationale: clear explanation of why this action is necessary

If you already have enough information to answer, return "answer" as the tool with empty parameters.

Respond in JSON format only with these exact keys: tool, parameters, rationale"""

        user_prompt = f"Current context: {current_input}\n\nWhat's the next action?"

        # Get history if available
        history = []
        if self.conversation_memory:
            # Get recent messages, excluding system messages
            raw_history = self.conversation_memory.get_recent_messages(10)
            history = [msg for msg in raw_history if msg.role != "system"]

        messages = [
            LLMMessage(role="system", content=system_prompt),
            *history,
            LLMMessage(role="user", content=user_prompt)
        ]
        
        try:
            response = self.llm_client.generate(messages)
            action_data = json.loads(response.content)
            
            # Validate response structure
            if "tool" not in action_data or "parameters" not in action_data or "rationale" not in action_data:
                raise ValueError("Invalid action format from LLM")
                
            return action_data["tool"], action_data["parameters"], action_data["rationale"]
            
        except Exception as e:
            self.logger.error(f"Error determining action: {str(e)}")
            return None, None, "Error determining next action"

    def _is_final_answer(self, analysis: str, original_query: str) -> bool:
        """
        Determine if the current analysis constitutes a final answer.
        
        Args:
            analysis: Current analysis of results
            original_query: User's original query
            
        Returns:
            bool: True if final answer is reached
        """
        # Simple heuristic based on whether analysis answers the original query
        ending_phrases = [
            "final analysis", "conclusion", "to summarize", "in conclusion",
            "to conclude", "based on the above", "therefore", "so we can say"
        ]
        
        analysis_lower = analysis.lower()
        return any(phrase in analysis_lower for phrase in ending_phrases)
    
    def _generate_final_response(self, context: str) -> str:
        """
        Generate a final, polished response for the user.
        
        Args:
            context: Full conversation context
            
        Returns:
            str: Final response to user
        """
        system_prompt = """You are a helpful cybersecurity assistant providing clear explanations to the user.
Create a concise, professional response that summarizes the findings and provides actionable insights.
Focus on security implications and next steps when relevant.
Avoid technical jargon when possible, but don't oversimplify security concepts."""

        user_prompt = f"Based on this analysis, provide a final response to the user:\n\n{context}"

        messages = [
            LLMMessage(role="system", content=system_prompt),
            LLMMessage(role="user", content=user_prompt)
        ]
        
        response = self.llm_client.generate(messages)
        return response.content
    
    def add_rag_document(self, document: RAGDocument) -> None:
        """
        Add a document to the RAG system for all sub-agents.
        
        Args:
            document: Document to add
        """
        self.planner.add_rag_document(document)
        self.researcher.add_rag_document(document)
        self.analyst.add_rag_document(document)
        self.logger.info(f"Added RAG document: {document.doc_id}")
