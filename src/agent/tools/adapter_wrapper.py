from typing import Dict, Any
from src.agent.plugin_manager import PluginManager

class AdapterToolWrapper:
    def __init__(self, adapter_name: str, plugin_manager: PluginManager):
        self.name = adapter_name
        self.plugin_manager = plugin_manager
        
        info = self.plugin_manager.get_adapter_info(adapter_name) or {}
        self.description = info.get("description", f"Executes {adapter_name}")

    def execute(self, params: Dict[str, Any]) -> Any:
        result = self.plugin_manager.run_adapter(self.name, params)
        return result.data if result.status.value == "success" else f"Error: {result.error_message}"

    def get_info(self) -> Dict[str, Any]:
        return self.plugin_manager.get_adapter_info(self.name) or {
            "name": self.name,
            "description": self.description
        }
