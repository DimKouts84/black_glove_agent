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
from adapters.interface import AdapterResultStatus
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
        
        # Decompose the query into multiple intents if needed
        intents = self._decompose_query(user_input)
        
        # If decomposition failed or returned single intent, wrap in list
        if not intents:
            intents = [user_input]
            
        if len(intents) > 1:
            yield {"type": "thinking", "content": f"Decomposed request into {len(intents)} tasks: {intents}"}
            
        # Process each intent sequentially
        context_accumulator = ""
        
        for i, intent in enumerate(intents):
            if len(intents) > 1:
                yield {"type": "thinking", "content": f"Processing task {i+1}/{len(intents)}: {intent}"}
                
            # Add context from previous intents
            current_intent_input = intent
            if context_accumulator:
                current_intent_input += f"\n\nContext from previous steps:\n{context_accumulator}"
            
            # First, check if this is a complex goal requiring planning
            if self._requires_planning(current_intent_input):
                yield {"type": "thinking", "content": "This requires a multi-step plan. Consulting the planner..."}
                scan_plan = self.planner.plan_workflow(current_intent_input)
                
                # Execute the plan step by step
                # Get available tools for validation
                available_tools = self.plugin_manager.discover_adapters()

                for step in scan_plan.steps:
                    # Validate tool before execution to prevent planner hallucinations
                    if step.tool not in available_tools:
                        self.logger.warning(f"Planner attempted to use unavailable tool: {step.tool}")
                        context_accumulator += f"\nSkipping step: Tool '{step.tool}' is not available."
                        continue

                    yield {
                        "type": "thinking", 
                        "content": f"Executing step: {step.tool} on {step.target}"
                    }
                    
                    # Execute the step and get intermediate result
                    result = self.researcher.execute_tool_step(step)
                    yield {"type": "tool_call", "tool": step.tool, "params": step.parameters}
                    yield {"type": "tool_result", "result": result}
                    
                    # Persist result to memory for future recall
                    if self.conversation_memory:
                        self.conversation_memory.add_message(
                            LLMMessage(role="system", content=f"Tool '{step.tool}' completed. Result: {result}")
                        )
                    
                    # Let the analyst provide insights
                    analysis = self.analyst.analyze_findings(result)
                    yield {"type": "thinking", "content": f"Analyst: {analysis}"}
                    
                    # Update context with latest findings
                    self.update_context(f"Step completed: {step.tool} on {step.target} - {analysis}")
                    context_accumulator += f"\nResults for {intent}: {analysis}"
            
            else:
                # Simple queries can go straight to ReAct loop
                should_continue = True
                for event in self._process_react_loop(current_intent_input):
                    yield event
                    # Capture the final answer for context accumulation
                    if event['type'] == 'answer':
                        context_accumulator += f"\nResults for {intent}: {event['content']}"
                        should_continue = False
                
                # If the loop didn't yield a final answer (e.g. error), ensure we don't break the flow
                if should_continue and not context_accumulator:
                     context_accumulator += f"\nProcessed: {intent}"
    
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
        # Track executed tools to avoid calling the same tool repeatedly in a single ReAct loop
        executed_tools = set()
        
        while steps < self.max_react_steps:
            steps += 1
            
            # 1. Reasoning step - decide what to do
            yield {"type": "thinking", "content": "Thinking about next action..."}
            action, params, rationale = self._decide_action(remaining_input)
            
            if not action:
                # If no action determined, use the rationale as direct answer if it's a complete answer
                if rationale and len(rationale) > 20:
                    yield {"type": "answer", "content": rationale}
                    return
                break
            # Prevent repeating the same tool multiple times if it was already run in this loop
            if action in executed_tools:
                self.logger.debug(f"Skipping repeated tool action '{action}' in ReAct loop")
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
            executed_tools.add(action)
            
            # Persist result to memory for future recall
            if self.conversation_memory:
                 self.conversation_memory.add_message(
                    LLMMessage(role="system", content=f"Tool '{action}' completed. Result: {result}")
                 )
            
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
        
        # Exclude general knowledge questions
        knowledge_patterns = [
            r"what (is|are|does) (a|an|the)?",
            r"how (do|does) .* work",
            r"explain",
            r"define"
        ]
        
        # Check if it looks like a knowledge question
        if any(re.search(pattern, user_input) for pattern in knowledge_patterns):
            # Exception: if it contains "my" or "our" or "target", it might be specific
            if not any(word in user_input for word in ["my", "our", "scan", "test", "target", "example"]):
                 return False
                 
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
        
        # Quick command detection: allow simple queries to map to tools directly
        
        # Split input to isolate the active optional intent from context history
        # The loop adds context with "\n\nContext from previous steps:"
        active_intent = current_input
        if "Context from previous steps:" in current_input:
            active_intent = current_input.split("Context from previous steps:")[0]
        
        lower_input = active_intent.lower()
        
        # Detect general knowledge questions that don't need tools
        # Only trigger tools for personal/action queries (with "my", "our", etc.)
        knowledge_patterns = [
            (r"what is (an?|the) \w+", "my" not in lower_input),  # "What is an IP?" but not "What is my IP?"
            (r"how (does|do|is|are) \w+", True),  # "How does DNS work?"
            (r"explain \w+", True),  # "Explain port scanning"
            (r"define \w+", True),  # "Define reconnaissance"
            (r"tell me about \w+", "my" not in lower_input),  # "Tell me about IPs" but not "Tell me about my IP"
        ]
        for pattern, condition in knowledge_patterns:
            if re.search(pattern, lower_input) and condition:
                return None, None, ""  # Empty rationale triggers fallback to _generate_final_response
        
        if "public ip" in lower_input or "my ip" in lower_input or "ip address" in lower_input:
            # Check for force refresh intents
            force_refresh = any(word in lower_input for word in ["recheck", "refresh", "again", "update", "new"])
            
            if not force_refresh:
                # Check memory for IP address
                cached = self._check_memory_for_tool_result("public_ip")
                if cached:
                    return None, None, f"Yes, I already checked that! Your public IP address is {cached} (via ipify.org)."
            return "public_ip", {}, "User asked directly for public IP"
        if "list assets" in lower_input or ("list" in lower_input and "asset" in lower_input):
            return "list_assets", {}, "User asked to list assets"
        if "add asset" in lower_input or ("add" in lower_input and ("domain" in lower_input or "host" in lower_input or "vm" in lower_input)):
            # Let LLM parse the required params if provided; fallback to empty add_asset call
            return "add_asset", {}, "User asked to add an asset"
        
        # Heuristics for common tools to improve reliability
        # Helper to extract domain/target
        def extract_target(text):
            # Simple regex for domain/IP
            match = re.search(r'\b([a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}\b|\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b', text)
            return match.group(0) if match else None

        # Check memory first - avoid redundant tool execution
        if "whois" in lower_input:
            target = extract_target(current_input)
            if target:
                cached = self._check_memory_for_tool_result("whois")
                if cached:
                    return "answer", {}, f"I recall the WHOIS data for {target}: {cached}"
                return "whois", {"domain": target}, "User asked for WHOIS lookup"
        
        if "dns" in lower_input and "lookup" in lower_input:
            target = extract_target(current_input)
            if target:
                cached = self._check_memory_for_tool_result("dns_lookup")
                if cached:
                    return "answer", {}, f"I recall the DNS records for {target}: {cached}"
                return "dns_lookup", {"domain": target, "record_type": "A"}, "User asked for DNS lookup"
        
        if "nmap" in lower_input:
            target = extract_target(current_input)
            if target:
                cached = self._check_memory_for_tool_result("nmap")
                if cached:
                    return "answer", {}, f"I recall the Nmap scan for {target}: {cached}"
                return "nmap", {"target": target, "scan_type": "quick"}, "User asked for Nmap scan"
        
        if "gobuster" in lower_input:
            target = extract_target(current_input)
            if target:
                cached = self._check_memory_for_tool_result("gobuster")
                if cached:
                    return "answer", {}, f"I recall the Gobuster scan for {target}: {cached}"
                # Gobuster needs a URL usually, but we'll pass target and let adapter handle or fail
                return "gobuster", {"target": target}, "User asked for Gobuster scan"

        # Get current assets from database to provide context
        current_assets_info = "No assets configured yet."
        try:
            from adapters.asset_manager import run as asset_manager_run
            assets_result = asset_manager_run({"command": "list"})
            if assets_result.status == AdapterResultStatus.SUCCESS and assets_result.data:
                current_assets_info = assets_result.data
        except Exception as e:
            self.logger.debug(f"Could not fetch assets: {e}")
        
        system_prompt = f"""You are Black Glove, an advanced automated penetration testing agent.
            Your goal is to proactively assist the user with security reconnaissance, analysis, and testing.

            AVAILABLE TOOLS:
            - public_ip: Get the user's public IP address (no parameters needed)
            - {tool_list}
            - add_asset: Add a new target to the database (type: host, domain, or vm; value: IP or domain name)
            - list_assets: List all configured targets from the database
            - generate_report: Create a security report

            CURRENT ASSETS IN DATABASE:
            {current_assets_info}

            CRITICAL INSTRUCTIONS:
            1. You are Black Glove. Never say you are ChatGPT or any other AI.
            2. You MUST respond with ONLY valid JSON. No other text before or after.
            3. When the user asks for their IP address, use tool "public_ip" with empty parameters {{}}.
            4. When the user asks to add an asset, use add_asset with {{"type": "domain", "value": "example.com"}}.

            OUTPUT FORMAT - You must output EXACTLY this JSON structure:
            {{
                "tool": "tool_name_here",
                "parameters": {{}},
                "rationale": "explanation here"
            }}

            For answering without a tool:
            {{
                "tool": "answer",
                "parameters": {{}},
                "rationale": "your answer to the user"
            }}

            JSON ONLY. No markdown, no code blocks, no extra text."""

        user_prompt = f"""User query: {current_input}

            Respond with JSON only:"""

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
            content = response.content.strip()
            
            # SPECIAL HANDLING for models outputting tool calls in <|...|> format
            # Example: <|start|>assistant<|channel|>commentary to=public_ip <|constrain|>json<|message|>{}<|call|>
            if "to=" in content and "<|message|>" in content:
                tool_match = re.search(r'to=([a-zA-Z0-9_]+)', content)
                json_match = re.search(r'<\|message\|>(.*?)<\|call\|>', content, re.DOTALL)
                
                if tool_match:
                    tool_name = tool_match.group(1)
                    params = {}
                    if json_match:
                        try:
                            json_str = json_match.group(1).strip()
                            if json_str:
                                params = json.loads(json_str)
                        except:
                            pass # Default to empty params
                    
                    return tool_name, params, f"Model requested tool {tool_name}"

            # SPECIAL HANDLING for models outputting tool names in <<tool_name>> format
            if "<<" in content and ">>" in content:
                lt_match = re.search(r'<<\s*([a-zA-Z0-9_]+)\s*(\{.*?\})?\s*>>', content, re.DOTALL)
                if lt_match:
                    tool_name = lt_match.group(1)
                    params = {}
                    json_params = lt_match.group(2)
                    if json_params:
                        try:
                            params = json.loads(json_params)
                        except:
                            params = {}
                    return tool_name, params, f"Model requested tool {tool_name} via <<tool>> token"

            # Clean up malformed LLM output (control tokens from some models)
            # Remove patterns like <|start|>, <|channel|>, <|constrain|>, <|message|>, <|call|>
            content = re.sub(r'<\|[^|]+\|>', '', content)
            # Remove "assistant", "commentary", "to=..." fragments from malformed output
            content = re.sub(r'\bassistant\b', '', content, flags=re.IGNORECASE)
            content = re.sub(r'\bcommentary\b', '', content, flags=re.IGNORECASE)
            content = re.sub(r'assistantcommentary', '', content, flags=re.IGNORECASE)
            content = re.sub(r'\bto=[a-zA-Z_]+\b', '', content, flags=re.IGNORECASE)
            content = re.sub(r'\bjson\b', '', content, flags=re.IGNORECASE)
            content = content.strip()
            
            # Clean markdown code blocks if present
            if "```" in content:
                json_match = re.search(r"```(?:json)?\s*(\{.*?\})\s*```", content, re.DOTALL)
                if json_match:
                    content = json_match.group(1)
            
            # Ensure we have just the JSON object if there's extra text
            start = content.find("{")
            end = content.rfind("}")
            if start != -1 and end != -1:
                content = content[start:end+1]
            
            # If content is empty or doesn't look like JSON, try to extract tool name
            if not content or not content.startswith("{"):
                # Check if LLM mentioned a tool name in response (check original response)
                original_lower = response.content.lower()
                # Map common queries to tools
                if "public_ip" in original_lower or "my ip" in original_lower or "ip address" in original_lower:
                    return "public_ip", {}, "Fetching your public IP address"
                
                # Check against actual available tools
                for tool in available_tools:
                    if tool in original_lower:
                        return tool, {}, f"Using {tool} tool based on request"
                
                # Fallback to answer
                return None, None, response.content
            
            try:
                action_data = json.loads(content)
                
                # Handle Schema Violations gracefully
                if "tool" not in action_data:
                    # Look for content in common keys from hallucinations
                    for key in ["request", "error", "message", "answer", "content"]:
                        if key in action_data and isinstance(action_data[key], str):
                            return None, None, action_data[key]
                    # Flatten entire dict values to string if nothing else
                    return None, None, " ".join([str(v) for v in action_data.values() if isinstance(v, str)])

                # Validate Tool Name - prevent hallucinations like 'assistant' or 'camera_security'
                tool_name = action_data["tool"]
                if tool_name not in available_tools and tool_name not in ["public_ip", "answer", "add_asset", "list_assets", "nmap", "whois"]:
                     # Treat as answer if tool is fake/unknown
                     # Check if there is a useful message in rationale or parameters
                     rationale = action_data.get("rationale", "")
                     if not rationale:
                         rationale = str(action_data)
                     return None, None, rationale

            except json.JSONDecodeError:
                self.logger.debug(f"Failed to parse JSON from LLM response: {response.content}")
                # Fallback: Treat the entire response as a direct answer
                return None, None, response.content
            
            # Validate response structure keys if tool is valid
            if "tool" in action_data and "parameters" in action_data:
                return action_data["tool"], action_data["parameters"], action_data.get("rationale", "Tool execution")
                
            return None, None, response.content
            
        except Exception as e:
            self.logger.error(f"Error determining action: {str(e)}")
            if 'response' in locals() and hasattr(response, 'content'):
                 return None, None, response.content
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
        # Get available tools for context
        available_tools = self.plugin_manager.discover_adapters()
        tool_list = ", ".join(available_tools)

        system_prompt = f"""You are Black Glove, an advanced automated penetration testing agent.
            Your goal is to assist the user with security reconnaissance, analysis, and testing.
            You have access to these tools: {tool_list}.

            Create a concise, professional, NATURAL LANGUAGE response.
            Do NOT output JSON.
            Output Format: Plain text paragraph.
            Do NOT invent or hallucinate findings. Only report results that are explicitly present in the context.
            If the user asks for a scan that hasn't been performed yet, state that you need to run a scan to determine that.
            Focus on security implications and next steps when relevant.
            Avoid technical jargon when possible, but don't oversimplify security concepts.
            Be conversational and engaging.
            Do NOT identify yourself as ChatGPT or an OpenAI model or an LLM from other provider Like Google Gemini, Qwen or others."""

        user_prompt = f"""SYSTEM REMINDER: You are Black Glove, a pentesting agent with tools: {tool_list}.
            Based on this analysis, provide a final response to the user:\n\n{context}

            IMPORTANT: Respond in plain text only. Do not use JSON."""

        messages = [
            LLMMessage(role="system", content=system_prompt),
            LLMMessage(role="user", content=user_prompt)
        ]
        
        response = self.llm_client.generate(messages)
        content = response.content.strip()
        
        # Clean up malformed LLM output (control tokens from some models)
        content = re.sub(r'<\|[^|]+\|>', '', content)
        content = re.sub(r'\bassistant\b', '', content, flags=re.IGNORECASE)
        content = re.sub(r'\bcommentary\b', '', content, flags=re.IGNORECASE)
        content = re.sub(r'\bto=[a-zA-Z_]+\b', '', content, flags=re.IGNORECASE)
        
        return content.strip()
    
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

    def _decompose_query(self, user_input: str) -> List[str]:
        """
        Decompose a user query into multiple atomic intents/tasks.
        
        Args:
            user_input: User's original query
            
        Returns:
            List of atomic task strings
        """
        if not self.llm_client:
            return [user_input]
            
        prompt = f"""Break down this user query into a sequence of atomic, standalone tasks.
        User query: "{user_input}"
        
        If the query contains multiple distinct requests (e.g. "What is my IP? Then scan it"), split them.
        If it's a single request, return just that request in the list.
        Each task must be a complete sentence that makes sense on its own.
        
        Respond with JSON:
        {{
            "tasks": ["First task", "Second task dependent on first"]
        }}
        """
        
        try:
            messages = [LLMMessage(role="user", content=prompt)]
            response = self.llm_client.generate(messages, add_to_memory=False)
            
            # Simple JSON extraction
            content = response.content
            json_match = re.search(r'\{.*\}', content, re.DOTALL)
            if json_match:
                data = json.loads(json_match.group())
                tasks = data.get("tasks", [])
                if tasks and isinstance(tasks, list):
                    return tasks
                    
        except Exception as e:
            self.logger.warning(f"Failed to decompose query: {e}")
            
        return [user_input]

    def _check_memory_for_tool_result(self, tool_name: str) -> Optional[str]:
        """
        Check existing conversation memory for recent results from a specific tool.
        
        Args:
            tool_name: Name of the tool to check for
            
        Returns:
            String containing the result if found, None otherwise
        """
        if not self.conversation_memory:
            return None
            
        # Get last 10 messages
        max_lookback = 10
        recent_messages = self.conversation_memory.get_recent_messages(max_lookback)
        
        # Look for tool results in the recent history
        # We look for "Tool completed" or "Previous result" or explicit tool names in ASSISTANT/SYSTEM messages
        found_result = None
        
        # Iterate backwards to find most recent
        for msg in reversed(recent_messages):
            if msg.role == "assistant" or msg.role == "system":
                # Check for explicit tool mentions in our own thinking/logs if we had them in memory
                # But typically memory stores the conversation TEXT.
                # So we look for text patterns that indicate we already ran this.
                lower_content = msg.content.lower()
                
                # Heuristics for result detection
                if f"results for {tool_name}" in lower_content:
                    found_result = msg.content
                    break
                
                    found_result = msg.content
                    break
                if tool_name == "public_ip":
                    # Match various formats for IP addresses
                    ip_match = re.search(r'"ipv4"\s*:\s*"([\d.]+)"', msg.content)
                    if ip_match:
                        return ip_match.group(1)
                    ip_match = re.search(r'\b(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\b', msg.content)
                    if ip_match and ("public ip" in lower_content or "ip address" in lower_content):
                        return ip_match.group(1)
                    
        return found_result
