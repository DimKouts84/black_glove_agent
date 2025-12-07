from typing import Dict, Any, List, Optional
import json
import logging
import re
import datetime
import inspect

from agent.definitions import AgentDefinition, AgentInput
from agent.llm_client import LLMClient, LLMMessage
from agent.tools.registry import ToolRegistry

class AgentExecutor:
    def __init__(
        self, 
        agent_definition: AgentDefinition, 
        llm_client: LLMClient, 
        tool_registry: ToolRegistry,
        max_turns: int = 15,
        on_activity: Optional[Any] = None
    ):
        self.definition = agent_definition
        self.llm = llm_client
        self.tool_registry = tool_registry
        self.max_turns = max_turns
        self.on_activity = on_activity
        self.logger = logging.getLogger(f"black_glove.executor.{agent_definition.name}")
        
        # Inject the mandatory complete_task tool
        self._inject_complete_task_tool()

    def _inject_complete_task_tool(self):
        """Injects the complete_task tool based on the agent's output config."""
        
        output_schema = {}
        if self.definition.output_config:
             output_schema = self.definition.output_config.schema_model.model_json_schema()

        # We construct a synthetic tool definition for complete_task
        # In a real system we might make this a proper BaseTool instance
        self.complete_task_tool_def = {
            "name": "complete_task",
            "description": f"Call this tool to signal completion. {self.definition.output_config.description if self.definition.output_config else ''}",
            "parameters": {
                "type": "object",
                "properties": {
                     self.definition.output_config.output_name: output_schema
                } if self.definition.output_config else {},
                "required": [self.definition.output_config.output_name] if self.definition.output_config else []
            }
        }

    def _template_query(self, inputs: Dict[str, Any]) -> str:
        """Replace placeholders in initial_query_template with input values."""
        query = self.definition.prompt_config.initial_query_template
        for key, value in inputs.items():
            query = query.replace(f"${{{key}}}", str(value))
        return query

    def _build_system_prompt(self) -> str:
        """Constructs the system prompt including tool definitions."""
        
        # Get tool descriptions
        tools_desc = []
        
        # Add registered tools
        for tool_name in self.definition.tool_config.tools:
            tool_info = self.tool_registry.get_tool_info(tool_name)
            if tool_info:
                desc = tool_info.get('description', '')
                # Add parameter information if available
                params = tool_info.get('parameters', {})
                required = params.get('required', [])
                if required:
                    param_str = ', '.join(required)
                    tools_desc.append(f"- {tool_name}: {desc} (Required params: {param_str})")
                else:
                    tools_desc.append(f"- {tool_name}: {desc}")
            else:
                 # It might be in the plugin manager if it's a raw adapter
                 # We probably need a unified way to get descriptions, but for now:
                 tools_desc.append(f"- {tool_name}: External Tool")

        tools_desc.append(f"- complete_task: {self.complete_task_tool_def['description']}")
        
        # Determine output format for complete_task
        output_name = "final_answer"
        if self.definition.output_config:
            output_name = self.definition.output_config.output_name
        
        # DEBUG: Log tools being included in prompt
        self.logger.info(f"Building system prompt with tools: {[t.split(':')[0].strip('- ') for t in tools_desc]}")

        system_prompt = f"""{self.definition.prompt_config.system_prompt}

AVAILABLE TOOLS:
{chr(10).join(tools_desc)}

CRITICAL INSTRUCTIONS - YOU MUST FOLLOW THESE EXACTLY:

1. **ALWAYS USE TOOLS when you have them available.** Do NOT give generic advice like "visit a website" if you have a tool that can do it.

2. Every response MUST be valid JSON with "tool", "parameters", and "rationale" fields. No markdown, no plain text.

3. When the user asks for information that a tool can provide, USE THAT TOOL.

4. After getting tool results, use 'complete_task' to give the final answer.

REQUIRED JSON FORMAT:
{{
    "tool": "tool_name",
    "parameters": {{ ... }},
    "rationale": "Why you are taking this action"
}}

EXAMPLE 1 - User asks "What is my public IP?":
{{
    "tool": "public_ip",
    "parameters": {{}},
    "rationale": "Using public_ip tool to detect the user's IP address"
}}

EXAMPLE 2 - User says "Hello":
{{
    "tool": "complete_task",
    "parameters": {{
        "{output_name}": {{
            "answer": "Hello! I'm Black Glove..."
        }}
    }},
    "rationale": "Greeting the user"
}}

EXAMPLE 3 - After receiving tool results, provide the answer:
{{
    "tool": "complete_task",
    "parameters": {{
        "{output_name}": {{
            "answer": "Your public IP address is 1.2.3.4"
        }}
    }},
    "rationale": "Providing the IP address from tool results"
}}

IMPORTANT: NEVER tell users to "visit a website" or "use an external tool" if you have a tool that can do it. USE YOUR TOOLS.
"""
        return system_prompt

    def _emit(self, event_type: str, content: Any, **kwargs):
        if self.on_activity:
            self.on_activity({
                "agent": self.definition.name,
                "type": event_type,
                "content": content,
                **kwargs
            })

    async def run(self, inputs: Dict[str, Any], conversation_history: List[LLMMessage] = None) -> Dict[str, Any]:
        """Runs the agent loop."""
        
        # 1. Validate inputs
        # (Simple validation for now)
        for name, config in self.definition.input_config.items():
            if config.required and name not in inputs:
                raise ValueError(f"Missing required input: {name}")

        # 2. Setup Loop
        query = self._template_query(inputs)
        system_prompt = self._build_system_prompt()
        
        # Initialize history with system prompt
        current_history = [LLMMessage(role="system", content=system_prompt)]
        
        # Append previous conversation history if provided
        if conversation_history:
            # Filter out system messages from history to avoid duplication/confusion
            # (Though we might want to keep them if they were different, mostly we just want user/assistant turns)
            # Actually, let's just append the user/assistant messages.
            for msg in conversation_history:
                if msg.role != "system":
                   current_history.append(msg)
        
        # Add current user query
        current_history.append(LLMMessage(role="user", content=query))
        
        # Use current_history for the loop
        conversation_history = current_history
        
        # 3. Execution Loop
        for turn in range(self.max_turns):
            self.logger.info(f"Turn {turn+1}/{self.max_turns}")
            # self._emit("thinking", f"Reasoning (Turn {turn+1})")
            
            # Generate response
            response = self.llm.generate(conversation_history, add_to_memory=False)
            content = response.content
            
            # Parse response
            try:
                # 0. Strip <think> tags for reasoning models
                content = re.sub(r'<think>.*?</think>', '', content, flags=re.DOTALL).strip()
                
                # Basic JSON cleaning
                clean_content = content.replace("```json", "").replace("```", "").strip()
                # Find first { and last }
                start = clean_content.find("{")
                end = clean_content.rfind("}")
                if start != -1 and end != -1:
                    clean_content = clean_content[start:end+1]
                
                # Attempt to fix common JSON errors (unescaped newlines in strings)
                # This is a simple heuristic: if we see a newline that is NOT followed by a quote or whitespace+quote, it might be inside a string.
                # Better approach: Use a robust parser or just try/except.
                # Let's try a simple regex replacement for unescaped newlines inside values if json.loads fails.
                
                try:
                    action = json.loads(clean_content)
                except json.JSONDecodeError:
                    # Try to escape newlines
                    # This is risky but often fixes "text block" issues
                    # We replace actual newlines with \n, but we need to be careful not to break structure.
                    # A safer bet is to tell the agent to fix it (which we do below), but let's try one simple fix.
                    try:
                        # Replace newlines that are likely inside strings
                        # This is hard to do perfectly with regex.
                        # Let's just try strict=False if available (python standard lib doesn't support it fully for this)
                        pass
                    except:
                        pass
                    raise # Re-raise to hit the error handler below

                if not isinstance(action, dict):
                    msg = "Agent output valid JSON but it was not an object (dictionary)."
                    self.logger.warning(msg)
                    raise json.JSONDecodeError(msg, content, 0)

                # Validate common hallucination of tool=None or tool=null
                if not action.get("tool") or str(action.get("tool")).lower() == "none" or str(action.get("tool")).lower() == "null":
                     msg = "Agent returned invalid tool 'None' or empty."
                     self.logger.warning(msg)
                     self._emit("warning", msg) # Notify UI
                     conversation_history.append(LLMMessage(role="assistant", content=content))
                     conversation_history.append(LLMMessage(role="user", content="Error: You must specify a valid tool name from the usage list. 'None' is not a valid tool. If you have the answer, use 'complete_task'. \nVALID TOOLS: " + ", ".join(self.tool_registry.list_tools() + ["complete_task"])))
                     continue

            except json.JSONDecodeError:
                msg = f"Failed to parse JSON response: {content[:100]}..."
                self.logger.warning(msg)
                self._emit("warning", "Agent response was not valid JSON. Retrying...") # Notify UI cleanly
                
                # Heuristic: If the response is short plain text, maybe it's the final answer?
                # But we want strict JSON.
                conversation_history.append(LLMMessage(role="assistant", content=content))
                
                # Stronger error message to break "apology loops"
                error_msg = "SYSTEM ERROR: Your response was NOT valid JSON.\n"
                error_msg += "CRITICAL: Do NOT apologize. Do NOT explain. Output ONLY a valid JSON object.\n"
                error_msg += "If you are trying to give the final answer, use the 'complete_task' tool.\n"
                error_msg += "Example:\n{\n    \"tool\": \"complete_task\",\n    \"parameters\": {\n        \"final_answer\": \"Your answer here\"\n    }\n}"
                
                conversation_history.append(LLMMessage(role="user", content=error_msg))
                continue

            tool_name = action.get("tool")
            tool_params = action.get("parameters", {})
            rationale = action.get("rationale", "")

            # Add assistant message to history
            conversation_history.append(LLMMessage(role="assistant", content=content))
            
            self.logger.info(f"Agent chose tool: {tool_name} (Rationale: {rationale})")
            if rationale:
                self._emit("thinking", rationale)

            # Handle complete_task
            if tool_name == "complete_task":
                # Validate output
                if self.definition.output_config:
                    output_name = self.definition.output_config.output_name
                    if output_name not in tool_params:
                         conversation_history.append(LLMMessage(role="user", content=f"Error: complete_task missing required parameter '{output_name}'."))
                         continue
                    
                    # In a real implementation we would validate using Pydantic here
                    # self.definition.output_config.schema_model(**tool_params[output_name])
                    self.logger.info(f"complete_task returning: {tool_params}")
                    self._emit("answer", "Task Completed")
                    return tool_params
                else:
                    self._emit("answer", "Task Completed")
                    return {"result": "Task Completed"}

            # Handle other tools
            try:
                self._emit("tool_call", tool_name, params=tool_params)
                
                # Check if it's a subagent tool or simple tool
                if self.tool_registry.has_tool(tool_name):
                    # It's a subagent or wrapped tool
                    tool_instance = self.tool_registry.get_tool(tool_name)
                    # We assume tool_instance has an execute method. 
                    if inspect.iscoroutinefunction(tool_instance.execute):
                        result = await tool_instance.execute(tool_params)
                    else:
                        result = tool_instance.execute(tool_params)
                else:
                    # Fallback
                     conversation_history.append(LLMMessage(role="user", content=f"Error: Tool '{tool_name}' not found."))
                     continue

                # Add result to history
                result_str = str(result)
                self._emit("tool_result", "Tool execution completed") 
                
                # Truncate if too long
                if len(result_str) > 2000:
                    result_str = result_str[:2000] + "...[truncated]"
                
                conversation_history.append(LLMMessage(role="user", content=f"Tool Result ({tool_name}): {result_str}"))

            except Exception as e:
                self.logger.error(f"Tool execution error: {e}")
                conversation_history.append(LLMMessage(role="user", content=f"Error executing {tool_name}: {str(e)}"))

        raise TimeoutError("Max turns exceeded")
