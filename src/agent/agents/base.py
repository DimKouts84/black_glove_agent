"""
Base Agent class for Black Glove pentest agent.
Provides common interface and utilities for all agent types.
"""

import logging
from typing import Dict, List, Any, Optional, Union
from abc import ABC, abstractmethod

from ..llm_client import LLMClient, LLMMessage, LLMResponse
from ..rag.manager import RAGDocument
from ..plugin_manager import PluginManager
from ..models import WorkflowStep, ScanPlan

class BaseAgent(ABC):
    """
    Abstract base class for all agents in the Black Glove system.
    
    Provides common functionality like LLM client access, logging, context management,
    RAG document handling, and tool registry access.
    """
    
    def __init__(self, llm_client: LLMClient, session_id: Optional[str] = None):
        """
        Initialize the base agent.
        
        Args:
            llm_client: LLM client for generating responses
            session_id: Optional session ID for context persistence
        """
        self.llm_client = llm_client
        self.session_id = session_id
        self.logger = logging.getLogger(f"black_glove.agent.{self.__class__.__name__}")
        self.context = ""
        self.rag_documents: List[RAGDocument] = []
        self.tools: List[str] = []
        
        # Create conversation memory for this agent
        self.conversation_memory = getattr(llm_client, 'conversation_memory', None)
    
    def add_rag_document(self, document: RAGDocument) -> None:
        """
        Add a document to the agent's RAG knowledge base.
        
        Args:
            document: Document to add
        """
        self.rag_documents.append(document)
        if hasattr(self.llm_client, 'add_rag_document'):
            self.llm_client.add_rag_document(document)
        self.logger.debug(f"Added RAG document: {document.title}")
    
    def update_context(self, new_context: str) -> None:
        """
        Update the agent's context with new information.
        
        Args:
            new_context: New context to add
        """
        if self.context:
            self.context += f"\n\n{new_context}"
        else:
            self.context = new_context
        self.logger.debug(f"Context updated: {new_context[:100]}...")
    
    def clear_context(self) -> None:
        """Clear the agent's context."""
        self.context = ""
        self.logger.debug("Context cleared")
    
    def set_tools(self, tools: List[str]) -> None:
        """
        Set the available tools for this agent.
        
        Args:
            tools: List of tool names this agent can use
        """
        self.tools = tools
        self.logger.debug(f"Tools set: {tools}")
    
    def add_tool(self, tool_name: str) -> None:
        """
        Add a tool to the available tools list.
        
        Args:
            tool_name: Name of the tool to add
        """
        if tool_name not in self.tools:
            self.tools.append(tool_name)
        self.logger.debug(f"Added tool: {tool_name}")
    
    def validate_tool(self, tool_name: str) -> bool:
        """
        Validate if a tool is available for this agent.
        
        Args:
            tool_name: Name of the tool to validate
            
        Returns:
            bool: True if tool is available
        """
        return tool_name in self.tools
    
    def get_available_tools(self) -> List[str]:
        """
        Get list of available tools for this agent.
        
        Returns:
            List[str]: Available tool names
        """
        return self.tools.copy()
    
    def create_message(self, role: str, content: str) -> LLMMessage:
        """
        Create an LLMMessage with proper timestamp and ID.
        
        Args:
            role: Message role (system, user, assistant)
            content: Message content
            
        Returns:
            LLMMessage: Created message
        """
        return LLMMessage(role=role, content=content)
    
    def add_to_memory(self, message: LLMMessage) -> None:
        """
        Add a message to the agent's conversation memory.
        
        Args:
            message: Message to add
        """
        if self.conversation_memory:
            self.conversation_memory.add_message(message)
        self.logger.debug(f"Added message to memory: {message.role}")
    
    def get_conversation_context(self) -> str:
        """
        Get current conversation context as a string.
        
        Returns:
            str: Conversation context
        """
        if self.conversation_memory:
            return self.conversation_memory.get_context_string()
        return ""
    
    def clear_memory(self) -> None:
        """Clear the agent's conversation memory."""
        if self.conversation_memory:
            self.conversation_memory.clear()
        self.logger.debug("Conversation memory cleared")
    
    def log_action(self, action: str, details: Dict[str, Any] = None) -> None:
        """
        Log an action taken by the agent.
        
        Args:
            action: Description of the action
            details: Additional details to log
        """
        if details:
            self.logger.info(f"{action}: {details}")
        else:
            self.logger.info(action)
    
    @abstractmethod
    def get_role_description(self) -> str:
        """
        Get a description of this agent's role and capabilities.
        
        Returns:
            str: Role description
        """
        pass
    
    def get_system_prompt(self) -> str:
        """
        Generate a system prompt for this agent.
        
        Returns:
            str: System prompt
        """
        role_desc = self.get_role_description()
        
        prompt = f"""You are a {self.__class__.__name__.lower()} agent in a cybersecurity testing system.

Your role: {role_desc}

Available tools: {', '.join(self.tools)}

Your capabilities:
1. You can execute security reconnaissance tools
2. You can analyze security findings
3. You can generate structured reports
4. You maintain context across conversations

Guidelines:
- Always follow safety and legal requirements
- Only test systems you are authorized to test
- Provide clear explanations of your actions
- Use structured JSON responses when requested
- Maintain professional cybersecurity terminology

Current context: {self.context if self.context else 'No additional context'}

Remember: You are helping with authorized security testing only."""
        
        return prompt

class ToolRegistry:
    """
    Registry for managing available tools across agents.
    """
    
    def __init__(self):
        """Initialize the tool registry."""
        self.tools: Dict[str, Dict[str, Any]] = {}
        self.logger = logging.getLogger("black_glove.tool_registry")
    
    def register_tool(self, name: str, description: str, category: str = "general", 
                     parameters: Dict[str, Any] = None, requires_approval: bool = False) -> None:
        """
        Register a tool in the registry.
        
        Args:
            name: Tool name
            description: Tool description
            category: Tool category (e.g., "reconnaissance", "analysis", "management")
            parameters: Tool parameters schema
            requires_approval: Whether the tool requires user approval
        """
        self.tools[name] = {
            "description": description,
            "category": category,
            "parameters": parameters or {},
            "requires_approval": requires_approval
        }
        self.logger.debug(f"Registered tool: {name} ({category})")
    
    def get_tool_info(self, name: str) -> Optional[Dict[str, Any]]:
        """
        Get information about a registered tool.
        
        Args:
            name: Tool name
            
        Returns:
            Optional[Dict[str, Any]]: Tool information if found
        """
        return self.tools.get(name)
    
    def list_tools(self, category: Optional[str] = None) -> List[str]:
        """
        List available tools, optionally filtered by category.
        
        Args:
            category: Optional category filter
            
        Returns:
            List[str]: Tool names
        """
        if category:
            return [name for name, info in self.tools.items() if info["category"] == category]
        return list(self.tools.keys())
    
    def get_tools_by_category(self) -> Dict[str, List[str]]:
        """
        Get all tools organized by category.
        
        Returns:
            Dict[str, List[str]]: Tools by category
        """
        categories: Dict[str, List[str]] = {}
        for name, info in self.tools.items():
            category = info["category"]
            if category not in categories:
                categories[category] = []
            categories[category].append(name)
        return categories
    
    def requires_approval(self, tool_name: str) -> bool:
        """
        Check if a tool requires user approval.
        
        Args:
            tool_name: Tool name
            
        Returns:
            bool: True if tool requires approval
        """
        info = self.get_tool_info(tool_name)
        return info.get("requires_approval", False) if info else False

# Global tool registry instance
_global_tool_registry = ToolRegistry()

def get_tool_registry() -> ToolRegistry:
    """
    Get the global tool registry instance.
    
    Returns:
        ToolRegistry: Global tool registry
    """
    return _global_tool_registry

def register_tool(name: str, description: str, category: str = "general", 
                 parameters: Dict[str, Any] = None, requires_approval: bool = False) -> None:
    """
    Convenience function to register a tool globally.
    
    Args:
        name: Tool name
        description: Tool description
        category: Tool category
        parameters: Tool parameters schema
        requires_approval: Whether the tool requires user approval
    """
    _global_tool_registry.register_tool(name, description, category, parameters, requires_approval)

# Default tool registrations
def _register_default_tools():
    """Register default tools in the registry."""
    
    # Reconnaissance tools
    register_tool("nmap", "Network discovery and security auditing", "reconnaissance", 
                 {"target": "str", "ports": "str", "scan_type": "str"}, requires_approval=True)
    register_tool("gobuster", "Directory/file scanning tool", "reconnaissance",
                 {"target": "str", "wordlist": "str", "extensions": "str"}, requires_approval=True)
    register_tool("whois", "Domain and IP information lookup", "reconnaissance",
                 {"target": "str"})
    register_tool("dns_lookup", "DNS record enumeration", "reconnaissance",
                 {"target": "str", "record_type": "str"})
    register_tool("ssl_check", "SSL certificate analysis", "reconnaissance",
                 {"target": "str", "port": "int"})
    
    # OSINT tools
    register_tool("sublist3r", "Subdomain enumeration", "osint",
                 {"domain": "str", "bruteforce": "bool"})
    register_tool("shodan", "Shodan API for external reconnaissance", "osint",
                 {"query": "str", "limit": "int"}, requires_approval=False)
    register_tool("wappalyzer", "Technology fingerprinting", "osint",
                 {"target": "str"})
    register_tool("viewdns", "External port scanning service", "osint",
                 {"target": "str", "ports": "str"})
    
    # Analysis tools
    register_tool("analyze_findings", "Analyze tool output for security findings", "analysis",
                 {"tool_output": "str", "context": "str"})
    register_tool("plan_workflow", "Create scanning workflow plan", "analysis",
                 {"goal": "str", "context": "str"})
    
    # Management tools
    register_tool("add_asset", "Add a new asset to scan", "management",
                 {"name": "str", "type": "str", "value": "str"})
    register_tool("list_assets", "List all assets", "management", {})
    register_tool("generate_report", "Generate security assessment report", "management",
                 {"asset": "str", "format": "str"})

# Register default tools on import
_register_default_tools()
