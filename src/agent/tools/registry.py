from typing import Dict, Any, Optional, Protocol, List

class Tool(Protocol):
    name: str
    description: str
    def execute(self, params: Dict[str, Any]) -> Any: ...
    def get_info(self) -> Dict[str, Any]: ...

class ToolRegistry:
    def __init__(self):
        self._tools: Dict[str, Tool] = {}

    def register(self, tool: Tool):
        self._tools[tool.name] = tool

    def get_tool(self, name: str) -> Optional[Tool]:
        return self._tools.get(name)

    def has_tool(self, name: str) -> bool:
        return name in self._tools

    def get_tool_info(self, name: str) -> Optional[Dict[str, Any]]:
        tool = self.get_tool(name)
        if tool:
            if hasattr(tool, "get_info"):
                return tool.get_info()
            return {"name": tool.name, "description": tool.description}
        return None

    def list_tools(self) -> List[str]:
        return list(self._tools.keys())
