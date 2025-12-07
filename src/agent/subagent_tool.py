from typing import Dict, Any, List
from agent.definitions import AgentDefinition
from agent.executor import AgentExecutor
from agent.llm_client import LLMClient
from agent.tools.registry import ToolRegistry, Tool

class SubagentTool:
    def __init__(
        self, 
        agent_definition: AgentDefinition, 
        llm_client: LLMClient, 
        parent_tool_registry: ToolRegistry
    ):
        self.definition = agent_definition
        self.llm = llm_client
        self.parent_tool_registry = parent_tool_registry
        
        self.name = agent_definition.name
        self.description = agent_definition.description

    def _generate_params_schema(self) -> Dict[str, Any]:
        """Generates JSON schema for tool parameters from input definition."""
        properties = {}
        required = []
        for name, input_def in self.definition.input_config.items():
            properties[name] = {
                "type": input_def.type,
                "description": input_def.description
            }
            if input_def.required:
                required.append(name)
        
        return {
            "type": "object",
            "properties": properties,
            "required": required
        }

    def get_info(self) -> Dict[str, Any]:
        return {
            "name": self.name,
            "description": self.description,
            "parameters": self._generate_params_schema()
        }

    async def execute(self, params: Dict[str, Any]) -> Any:
        # Create a scoped registry for this subagent
        subagent_registry = ToolRegistry()
        
        # Populate it with allowed tools from parent registry
        for tool_name in self.definition.tool_config.tools:
            if self.parent_tool_registry.has_tool(tool_name):
                subagent_registry.register(self.parent_tool_registry.get_tool(tool_name))
            else:
                 # Warn or fail? For now, we just skip incomplete tools which might fail execution
                 pass
        
        # Special handling for Planner Agent: Inject available tools from PARENT registry
        # The planner needs to know what the ROOT agent can do, not what the planner can do (which is nothing)
        if self.name == "planner_agent":
            available_tools_list = []
            for name in self.parent_tool_registry.list_tools():
                # Skip the planner itself to avoid confusion
                if name == "planner_agent":
                    continue
                    
                info = self.parent_tool_registry.get_tool_info(name)
                desc = info.get("description", "No description") if info else "No description"
                available_tools_list.append(f"- {name}: {desc}")
            
            # print(f"DEBUG: Injecting available tools into planner: {available_tools_list}")
            params["executor_tools"] = "\n".join(available_tools_list)

        # Create executor
        executor = AgentExecutor(
            agent_definition=self.definition,
            llm_client=self.llm,
            tool_registry=subagent_registry
        )
        
        # Run it
        result = await executor.run(params)
        return result
