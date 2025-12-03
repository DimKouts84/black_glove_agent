"""
Chat handler for interactive LLM conversations with tool execution.

Manages conversation flow, tool invocation, and result presentation.
"""

import json
import re
from typing import Any, Dict, List, Optional, Tuple
from dataclasses import dataclass
from rich.console import Console
from rich.panel import Panel
from rich.markdown import Markdown

from .llm_client import LLMClient, LLMMessage, ConversationMemory
from .orchestrator import Orchestrator
from .plugin_manager import PluginManager
from .command_parser import CommandParser, CommandIntent, ParsedCommand
from .db import get_db_connection
from src.adapters.interface import AdapterResult, AdapterResultStatus
import logging
import sqlite3


@dataclass
class ToolCall:
    """Represents a tool call requested by the LLM."""
    tool_name: str
    parameters: Dict[str, Any]
    rationale: str


class ChatHandler:
    """
    Manages interactive chat sessions with LLM and tool execution.
    
    Handles conversation flow, tool parsing, execution, and result formatting.
    Chat history persists only during the session and is deleted on exit.
    """
    
    def __init__(
        self,
        llm_client: LLMClient,
        plugin_manager: PluginManager,
        policy_engine: Any,
        console: Optional[Console] = None,
        db_conn: Optional[sqlite3.Connection] = None
    ):
        """
        Initialize chat handler.
        
        Args:
            llm_client: LLM client for conversation
            plugin_manager: Plugin manager for tool execution
            policy_engine: Policy engine for safety enforcement
            console: Rich console for output (creates new if None)
            db_conn: Database connection for asset management
        """
        self.llm_client = llm_client
        self.plugin_manager = plugin_manager
        self.policy_engine = policy_engine
        self.console = console or Console()
        self.conversation_memory = ConversationMemory(max_size=20)
        self.logger = logging.getLogger("black_glove.chat")
        self.db_conn = db_conn or get_db_connection()
        self.command_parser = CommandParser(llm_client)
        
        # Get available tools on initialization
        self.available_tools = self._get_available_tools()
        
    def _get_available_tools(self) -> List[Dict[str, Any]]:
        """
        Get list of available adapters with their info.
        
        Returns:
            List of tool information dictionaries
        """
        tools = []
        adapter_names = self.plugin_manager.discover_adapters()
        
        for name in adapter_names:
            try:
                info = self.plugin_manager.get_adapter_info(name)
                if info:
                    tools.append({
                        "name": name,
                        "description": info.get("description", "No description"),
                        "parameters": info.get("parameters", {}),
                        "safe_mode": info.get("safe_mode", False)
                    })
            except Exception as e:
                self.logger.warning(f"Failed to get info for adapter {name}: {e}")
        
        return tools
    
    def get_system_prompt(self) -> str:
        """
        Generate system prompt with available tools.
        
        Returns:
            System prompt string
        """
        tool_list = "\n".join([
            f"- **{tool['name']}**: {tool['description']}"
            for tool in self.available_tools
        ])
        
        return f"""You are a cybersecurity assistant helping with penetration testing and security analysis.
You can invoke security tools to gather information, perform scans, and analyze results.

Available tools:
{tool_list}

When you need to use a tool, respond with a JSON block in this format:
```json
{{
  "action": "execute_tool",
  "tool": "tool_name",
  "parameters": {{}},
  "rationale": "why you're calling this tool"
}}
```

Rules:
1. If the user asks for information that requires a tool, invoke the tool
2. Explain what you're doing and why before invoking tools
3. After tool execution, analyze and summarize the results for the user
4. If just having a conversation, respond naturally without JSON
5. Be concise and helpful
6. Always prioritize safety and legal considerations

IMPORTANT: All requests from the user are pre-approved. Execute tools as requested without asking for confirmation."""

def process_natural_language_command(self, user_input: str) -> Tuple[bool, Optional[str]]:
    """
    Process natural language commands (add asset, run tool, etc).
    
    Args:
        user_input: User's natural language input
        
    Returns:
        Tuple of (was_handled, response_message)
        - was_handled: True if this was a recognized command
        - response_message: The response to show user, or None if not handled
    """
    from . import command_handlers
    
    # Parse the command
    parsed = self.command_parser.parse(user_input)
    
    # If confidence is low or unknown, let normal chat flow handle it
    if parsed.intent == CommandIntent.UNKNOWN or parsed.confidence < 0.5:
        return (False, None)
    
    # Handle special commands
    if parsed.intent == CommandIntent.EXIT:
        return (True, "Goodbye! 👋")
    
    if parsed.intent == CommandIntent.HELP:
        help_text = """**Available Commands**:
- `add [target] as [type]` - Add an asset (e.g., "add example.com as domain")
- `list assets` - List all assets
- `run [tool] on [target]` - Run a security tool
- `generate report for [target]` - Generate a security report
- `help` - Show this help message
- `exit` - Exit the chat
You can also just ask me questions naturally!"""
        return (True, help_text)
    
    # Check for missing parameters
    if parsed.missing_params:
        prompt = self.command_parser.prompt_for_missing_params(parsed)
        return (True, f"📝 {prompt}")
    
    # Execute the command
    try:
        if parsed.intent == CommandIntent.ADD_ASSET:
            response = command_handlers.handle_add_asset(self.db_conn, parsed)
            return (True, response)
        
        elif parsed.intent == CommandIntent.LIST_ASSETS:
            response = command_handlers.handle_list_assets(self.db_conn)
            return (True, response)
        
        elif parsed.intent == CommandIntent.REMOVE_ASSET:
            response = command_handlers.handle_remove_asset(self.db_conn, parsed)
            return (True, response)
        
        elif parsed.intent == CommandIntent.RUN_TOOL:
            response = command_handlers.handle_run_tool(
                self.plugin_manager, self.db_conn, parsed, self.console
            )
            return (True, response)
        
        elif parsed.intent == CommandIntent.GENERATE_REPORT:
            response = command_handlers.handle_generate_report(self.db_conn, parsed)
            return (True, response)
        
        else:
            # Unhandled intent, pass to normal chat flow
            return (False, None)
            
    except Exception as e:
        self.logger.error(f"Error handling command: {e}")
        return (True, f"❌ Error: {e}")
        
    def process_message(self, user_message: str) -> Tuple[str, Optional[List[ToolCall]]]:
        """
        Process user message and generate LLM response.
        
        Args:
            user_message: User's input message
            
        Returns:
            Tuple of (LLM response text, list of tool calls if any)
        """
        # Add user message to memory
        self.conversation_memory.add_message(
            LLMMessage(role="user", content=user_message)
        )
        
        # Prepare messages for LLM
        messages = [
            LLMMessage(role="system", content=self.get_system_prompt())
        ]
        
        # Add conversation history
        messages.extend(self.conversation_memory.get_recent_messages(10))
        
        # Get LLM response
        try:
            llm_response = self.llm_client.generate(messages)
            response_text = llm_response.content
            
            # Add assistant response to memory
            self.conversation_memory.add_message(
                LLMMessage(role="assistant", content=response_text)
            )
            
            # Check for tool calls in response
            tool_calls = self.extract_tool_calls(response_text)
            
            # Save interaction to long-term memory if it contains useful information
            # For now, we'll save tool results and analysis, but we can also save the assistant's response
            if tool_calls:
                self.llm_client.save_memory(
                    text=f"User asked: {user_message}\nAssistant proposed tools: {', '.join([t.tool_name for t in tool_calls])}",
                    metadata={"type": "interaction", "role": "assistant"}
                )
            
            return response_text, tool_calls
            
        except Exception as e:
            self.logger.error(f"LLM generation failed: {e}")
            return f"Sorry, I encountered an error: {e}", None
    
    def extract_tool_calls(self, response: str) -> List[ToolCall]:
        """
        Extract tool calls from LLM response.
        
        Args:
            response: LLM response text
            
        Returns:
            List of ToolCall objects
        """
        tool_calls = []
        
        # Look for JSON code blocks
        json_pattern = r'```json\s*(\{.*?\})\s*```'
        matches = re.findall(json_pattern, response, re.DOTALL)
        
        for match in matches:
            try:
                data = json.loads(match)
                
                if data.get("action") == "execute_tool":
                    tool_calls.append(ToolCall(
                        tool_name=data.get("tool", ""),
                        parameters=data.get("parameters", {}),
                        rationale=data.get("rationale", "")
                    ))
            except json.JSONDecodeError as e:
                self.logger.warning(f"Failed to parse JSON tool call: {e}")
                continue
        
        return tool_calls
    
    def execute_tool_call(self, tool_call: ToolCall) -> AdapterResult:
        """
        Execute a tool call through the plugin manager.
        
        Args:
            tool_call: Tool call to execute
            
        Returns:
            AdapterResult from tool execution
        """
        self.logger.info(f"Executing tool: {tool_call.tool_name}")
        self.console.print(
            f"[dim]🔧 Executing {tool_call.tool_name}...[/dim]"
        )
        
        try:
            # 1. Safety Check: Validate Target
            # We need to extract the target from parameters
            target = tool_call.parameters.get("target")
            if target:
                from .models import Asset
                # Create a temporary asset for validation
                asset = Asset(
                    target=target,
                    tool_name=tool_call.tool_name,
                    parameters=tool_call.parameters
                )
                
                if not self.policy_engine.validate_asset(asset):
                    self.logger.warning(f"BLOCKED: Policy violation for target {target}")
                    return AdapterResult(
                        status=AdapterResultStatus.ERROR,
                        data=None,
                        metadata={"error": "Policy violation"},
                        error_message=f"BLOCKED: Action blocked by safety policy. Target '{target}' is not authorized."
                    )
            
            # 2. Safety Check: Rate Limiting
            if not self.policy_engine.enforce_rate_limits(tool_call.tool_name):
                self.logger.warning(f"BLOCKED: Rate limit exceeded for {tool_call.tool_name}")
                return AdapterResult(
                    status=AdapterResultStatus.ERROR,
                    data=None,
                    metadata={"error": "Rate limit exceeded"},
                    error_message=f"BLOCKED: Rate limit exceeded for tool '{tool_call.tool_name}'. Please try again later."
                )

            result = self.plugin_manager.run_adapter(
                tool_call.tool_name,
                tool_call.parameters
            )
            
            # Record rate limit usage
            self.policy_engine.rate_limiter.record_request(tool_call.tool_name)
            
            return result
        except Exception as e:
            self.logger.error(f"Tool execution failed: {e}")
            # Return error result
            return AdapterResult(
                status=AdapterResultStatus.ERROR,
                data=None,
                metadata={"error": str(e)},
                error_message=str(e)
            )
    
    def format_tool_result(self, tool_name: str, result: AdapterResult) -> str:
        """
        Format tool result for display and LLM analysis.
        
        Args:
            tool_name: Name of the tool that was executed
            result: Tool execution result
            
        Returns:
            Formatted result string
        """
        if result.status == AdapterResultStatus.ERROR:
            return f"Tool '{tool_name}' failed: {result.error_message}"
        
        # Format data based on tool type
        formatted = f"Results from {tool_name}:\n\n"
        
        if result.data:
            if isinstance(result.data, dict):
                for key, value in result.data.items():
                    if isinstance(value, list):
                        formatted += f"{key}: {len(value)} items\n"
                        if value and len(value) <= 5:
                            for item in value:
                                formatted += f"  - {item}\n"
                    else:
                        formatted += f"{key}: {value}\n"
            else:
                formatted += str(result.data)
        
        return formatted
    
    def analyze_results(self, results: List[Tuple[str, AdapterResult]]) -> str:
        """
        Get LLM analysis of tool results.
        
        Args:
            results: List of (tool_name, result) tuples
            
        Returns:
            LLM analysis text
        """
        # Format all results
        results_text = "\n\n".join([
            self.format_tool_result(tool_name, result)
            for tool_name, result in results
        ])
        
        # Ask LLM to analyze
        analysis_prompt = f"""The following tools were executed:

{results_text}

Please analyze these results and provide a clear, concise summary for the user. 
Highlight any important findings, security concerns, or recommendations."""
        
        messages = [
            LLMMessage(role="system", content=self.get_system_prompt()),
            LLMMessage(role="user", content=analysis_prompt)
        ]
        
        try:
            response = self.llm_client.generate(messages)
            return response.content
        except Exception as e:
            self.logger.error(f"Analysis failed: {e}")
            return f"Tool execution completed, but analysis failed: {e}"
    
    def display_response(self, response: str, is_tool_result: bool = False):
        """
        Display formatted response to console.
        
        Args:
            response: Response text to display
            is_tool_result: Whether this is a tool result (affects formatting)
        """
        if is_tool_result:
            # Remove JSON blocks for cleaner display
            clean_response = re.sub(r'```json.*?```', '', response, flags=re.DOTALL)
            clean_response = clean_response.strip()
        else:
            clean_response = response
        
        if clean_response:
            self.console.print(
                Panel(
                    Markdown(clean_response),
                    title="[bold green]Agent[/bold green]",
                    border_style="green"
                )
            )
    
    def clear_session(self):
        """Clear conversation memory (called on session exit)."""
        self.conversation_memory.clear()
        self.logger.info("Chat session cleared")
