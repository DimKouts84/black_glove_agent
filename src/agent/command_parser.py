"""
Command Parser for Natural Language Understanding

Extracts intents and parameters from user inputs to enable conversational CLI.
"""

from enum import Enum
from dataclasses import dataclass, field
from typing import Dict, Any, List, Optional
import logging


class CommandIntent(Enum):
    """Enumeration of command intents that can be extracted from user input."""
    ADD_ASSET = "add_asset"
    REMOVE_ASSET = "remove_asset"
    LIST_ASSETS = "list_assets"
    RUN_TOOL = "run_tool"
    GENERATE_REPORT = "generate_report"
    SHOW_FINDINGS = "show_findings"
    HELP = "help"
    EXIT = "exit"
    UNKNOWN = "unknown"


@dataclass
class ParsedCommand:
    """Represents a parsed command with intent and extracted parameters."""
    intent: CommandIntent
    parameters: Dict[str, Any] = field(default_factory=dict)
    confidence: float = 1.0
    raw_input: str = ""
    missing_params: List[str] = field(default_factory=list)
    
    @property
    def is_complete(self) -> bool:
        """Check if all required parameters are present."""
        return len(self.missing_params) == 0


class CommandParser:
    """
    Parses natural language commands into structured intents and parameters.
    """
    
    def __init__(self, llm_client=None):
        """
        Initialize command parser.
        
        Args:
            llm_client: Optional LLM client for advanced parsing
        """
        self.llm_client = llm_client
        self.logger = logging.getLogger("black_glove.command_parser")
        
        # Define required parameters for each intent
        self.required_params = {
            CommandIntent.ADD_ASSET: ["name", "type", "value"],
            CommandIntent.REMOVE_ASSET: ["name"],
            CommandIntent.RUN_TOOL: ["tool", "target"],
            CommandIntent.GENERATE_REPORT: ["target"],
            CommandIntent.SHOW_FINDINGS: ["target"],
        }
    
    def parse(self, user_input: str) -> ParsedCommand:
        """
        Parse user input into a structured command.
        
        Args:
            user_input: Natural language input from user
            
        Returns:
            ParsedCommand with intent and parameters
        """
        user_input = user_input.strip()
        
        # Try rule-based parsing first (fast path)
        parsed = self._rule_based_parse(user_input)
        
        # If LLM is available and confidence is low, use LLM parsing
        if self.llm_client and parsed.confidence < 0.7:
            parsed = self._llm_based_parse(user_input)
        
        # Identify missing parameters
        if parsed.intent in self.required_params:
            required = set(self.required_params[parsed.intent])
            provided = set(parsed.parameters.keys())
            parsed.missing_params = list(required - provided)
        
        self.logger.debug(f"Parsed intent: {parsed.intent}, params: {parsed.parameters}")
        return parsed
    
    def _rule_based_parse(self, user_input: str) -> ParsedCommand:
        """
        Use simple rules to parse common command patterns.
        
        Args:
            user_input: User input text
            
        Returns:
            ParsedCommand
        """
        lower_input = user_input.lower()
        
        # Exit commands
        if lower_input in ["exit", "quit", "bye", "goodbye"]:
            return ParsedCommand(
                intent=CommandIntent.EXIT,
                confidence=1.0,
                raw_input=user_input
            )
        
        # Help commands
        if lower_input in ["help", "?", "what can you do"]:
            return ParsedCommand(
                intent=CommandIntent.HELP,
                confidence=1.0,
                raw_input=user_input
            )
        
        # List assets
        if any(phrase in lower_input for phrase in ["list assets", "show assets", "my assets", "what assets"]):
            return ParsedCommand(
                intent=CommandIntent.LIST_ASSETS,
                confidence=0.9,
                raw_input=user_input
            )
        
        # Add asset pattern: "add [target] as [type]" or "add [target] type [type]"
        if "add" in lower_input and ("as" in lower_input or "type" in lower_input):
            params = self._extract_add_asset_params(user_input)
            return ParsedCommand(
                intent=CommandIntent.ADD_ASSET,
                parameters=params,
                confidence=0.8 if params else 0.5,
                raw_input=user_input
            )
        
        # Run tool pattern
        if any(phrase in lower_input for phrase in ["run ", "scan ", "execute ", "use "]):
            params = self._extract_run_tool_params(user_input)
            return ParsedCommand(
                intent=CommandIntent.RUN_TOOL,
                parameters=params,
                confidence=0.7 if params else 0.4,
                raw_input=user_input
            )
        
        # Report generation
        if any(phrase in lower_input for phrase in ["report", "generate report", "create report"]):
            params = self._extract_report_params(user_input)
            return ParsedCommand(
                intent=CommandIntent.GENERATE_REPORT,
                parameters=params,
                confidence=0.8 if params else 0.5,
                raw_input=user_input
            )
        
        # Unknown intent
        return ParsedCommand(
            intent=CommandIntent.UNKNOWN,
            confidence=0.0,
            raw_input=user_input
        )
    
    def _extract_add_asset_params(self, text: str) -> Dict[str, Any]:
        """Extract parameters for add_asset command."""
        import re
        params = {}
        
        # Pattern: "add [target] as [type]" or "add [target] as a/an [type]"
        # More flexible pattern to handle optional articles
        match = re.search(r'add\s+([^\s]+)\s+as\s+(?:a\s+|an\s+)?(\w+)', text, re.IGNORECASE)
        if match:
            params["value"] = match.group(1)
            params["type"] = match.group(2).lower()
            # Use value as name if not specified
            params["name"] = params["value"].replace(".", "_").replace(":", "_")
        
        return params
    
    def _extract_run_tool_params(self, text: str) -> Dict[str, Any]:
        """Extract parameters for run_tool command."""
        import re
        params = {}
        
        # Pattern 1: "run [tool] on [target]"
        match = re.search(r'(?:run|scan|execute|use)\s+(\w+)\s+(?:on|against|for)\s+([^\s]+)', text, re.IGNORECASE)
        if match:
            params["tool"] = match.group(1).lower()
            params["target"] = match.group(2)
        else:
            # Pattern 2: "scan [target] with [tool]"
            match = re.search(r'(?:scan|execute|use)\s+([^\s]+)\s+(?:with|using)\s+(\w+)', text, re.IGNORECASE)
            if match:
                params["target"] = match.group(1)
                params["tool"] = match.group(2).lower()
        
        return params
    
    def _extract_report_params(self, text: str) -> Dict[str, Any]:
        """Extract parameters for generate_report command."""
        import re
        params = {}
        
        # Pattern: "report for [target]"
        match = re.search(r'report\s+(?:for|on)\s+([^\s]+)', text, re.IGNORECASE)
        if match:
            params["target"] = match.group(1)
        
        return params
    
    def _llm_based_parse(self, user_input: str) -> ParsedCommand:
        """
        Use LLM to parse complex commands.
        
        Args:
            user_input: User input text
            
        Returns:
            ParsedCommand
        """
        from .llm_client import LLMMessage
        
        prompt = f"""Parse this user command into structured format.

User command: "{user_input}"

Available intents:
- add_asset: Add a new target asset
- remove_asset: Remove an asset
- list_assets: List all assets
- run_tool: Execute a security tool
- generate_report: Generate a security report
- show_findings: Show findings for a target
- help: Get help
- exit: Exit the application

Extract the intent and any parameters (name, type, value, tool, target).

Respond with JSON:
{{
  "intent": "intent_name",
  "parameters": {{"param": "value"}},
  "confidence": 0.9
}}"""
        
        try:
            messages = [LLMMessage(role="user", content=prompt)]
            response = self.llm_client.generate(messages)
            
            # Parse JSON response
            import json
            import re
            response_text = response.content
            json_match = re.search(r'\{.*\}', response_text, re.DOTALL)
            if json_match:
                data = json.loads(json_match.group())
                intent_str = data.get("intent", "unknown")
                try:
                    intent = CommandIntent(intent_str)
                except ValueError:
                    intent = CommandIntent.UNKNOWN
                
                return ParsedCommand(
                    intent=intent,
                    parameters=data.get("parameters", {}),
                    confidence=data.get("confidence", 0.5),
                    raw_input=user_input
                )
        except Exception as e:
            self.logger.error(f"LLM parsing failed: {e}")
        
        # Fallback to unknown
        return ParsedCommand(
            intent=CommandIntent.UNKNOWN,
            confidence=0.0,
            raw_input=user_input
        )
    
    def prompt_for_missing_params(self, parsed: ParsedCommand) -> str:
        """
        Generate a prompt to request missing parameters.
        
        Args:
            parsed: ParsedCommand with missing parameters
            
        Returns:
            Prompt string
        """
        if not parsed.missing_params:
            return ""
        
        param_descriptions = {
            "name": "asset name",
            "type": "asset type (domain, host, or vm)",
            "value": "target value (IP address or domain)",
            "tool": "tool name (whois, nmap, gobuster, etc.)",
            "target": "target to scan"
        }
        
        prompts = []
        for param in parsed.missing_params:
            desc = param_descriptions.get(param, param)
            prompts.append(f"What is the {desc}?")
        
        return " ".join(prompts)
