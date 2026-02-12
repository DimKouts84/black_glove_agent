from typing import Dict, Any, Optional
from agent.plugin_manager import PluginManager
from agent.reporting import ReportingManager
from agent.db import init_db
from agent.models import DatabaseManager, AssetModel, AssetType

class AdapterToolWrapper:
    def __init__(self, adapter_name: str, plugin_manager: PluginManager):
        self.name = adapter_name
        self.plugin_manager = plugin_manager
        
        info = self.plugin_manager.get_adapter_info(adapter_name) or {}
        self.description = info.get("description", f"Executes {adapter_name}")
        
        # Initialize managers for finding persistence
        init_db()
        self.reporting_manager = ReportingManager()
        self.db_manager = DatabaseManager()

    def execute(self, params: Dict[str, Any]) -> Any:
        result = self.plugin_manager.run_adapter(self.name, params)
        
        if hasattr(result.status, 'value') and result.status.value == "success":
            # Attempt to normalize and save findings
            try:
                # 1. Extract target from params to identify asset
                target = (
                    params.get("target") or 
                    params.get("domain") or 
                    params.get("host") or 
                    params.get("url") or
                    params.get("target_url")
                )
                
                if target:
                    # Clean target for lookup (simple)
                    target_val = target.replace("https://", "").replace("http://", "").strip("/")
                    
                    # 2. Find or Create Asset
                    asset = self.db_manager.get_asset_by_name(target_val)
                    if not asset:
                        # Infer type
                        asset_type = AssetType.HOST
                        if "http" in target or "www" in target_val or "." in target_val:
                            asset_type = AssetType.DOMAIN
                        
                        # Create new asset
                        asset_model = AssetModel(name=target_val, type=asset_type, value=target_val)
                        asset_id = self.db_manager.add_asset(asset_model)
                        asset = self.db_manager.get_asset(asset_id)
                    
                    if asset:
                        # 3. Normalize Output
                        findings = self.reporting_manager.findings_normalizer.normalize_tool_output(
                            self.name, result.data, asset
                        )
                        
                        # 4. Save to DB
                        if findings:
                            self.reporting_manager.save_findings_to_database(findings)
            except Exception:
                # Don't fail the tool execution just because reporting failed
                pass
            
            # Add interpretation to the result data
            try:
                # Load adapter instance (cached) to access interpret_result
                adapter_instance = self.plugin_manager.load_adapter(self.name)
                if hasattr(adapter_instance, 'interpret_result'):
                    interpretation = adapter_instance.interpret_result(result)
                    
                    if isinstance(result.data, dict):
                        # Inject into the dictionary
                        result.data['interpretation'] = interpretation
                    # If it's not a dict, we pass it as is, and the interpretation is lost 
                    # (unless we change return type, but we want to fail open)
            except Exception as e:
                # Log but don't fail execution
                # self.plugin_manager.logger.warning(f"Failed to interpret result for {self.name}: {e}")
                pass

            return result.data
        else:
            return f"Error: {result.error_message}"

    def get_info(self) -> Dict[str, Any]:
        return self.plugin_manager.get_adapter_info(self.name) or {
            "name": self.name,
            "description": self.description
        }
