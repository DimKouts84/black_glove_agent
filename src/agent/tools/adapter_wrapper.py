import logging

from typing import Dict, Any, Optional



from agent.plugin_manager import PluginManager

from agent.reporting import ReportingManager

from agent.db import init_db

from agent.models import DatabaseManager, AssetModel, AssetType

from agent.target_scope import is_valid_ip, strip_host

from agent.execution_provenance import get_run_context

from agent.tool_result import ToolResultEnvelope



WEB_SCAN_TOOLS = {"web_vuln_scanner", "sqli_scanner", "web_server_scanner"}

LARGE_OUTPUT_TOOLS = WEB_SCAN_TOOLS | {"passive_recon", "osint_harvester"}

SESSION_TOOLS = {"public_ip"}

SESSION_ASSET_NAME = "local-agent"

SESSION_ASSET_VALUE = "local"





class AdapterToolWrapper:

    def __init__(self, adapter_name: str, plugin_manager: PluginManager):

        self.name = adapter_name

        self.plugin_manager = plugin_manager

        self.logger = logging.getLogger(f"black_glove.tool.{adapter_name}")



        info = self.plugin_manager.get_adapter_info(adapter_name) or {}

        self.description = info.get("description", f"Executes {adapter_name}")



        init_db()

        self.reporting_manager = ReportingManager()

        self.db_manager = DatabaseManager()



    def _is_successful_result(self, result) -> bool:

        if not hasattr(result.status, "value"):

            return False

        return result.status.value in ("success", "partial")



    def _format_adapter_error(self, result) -> str:

        if result.error_message:

            return f"Error: {result.error_message}"

        if isinstance(result.data, dict):

            errors = result.data.get("errors")

            if errors:

                if isinstance(errors, dict):

                    parts = [f"{k}: {v}" for k, v in errors.items()]

                    return f"Error: {'; '.join(parts)}"

                return f"Error: {errors}"

        status = getattr(result.status, "value", "failure")

        return f"Error: {self.name} returned {status}"



    def _resolve_asset(self, params: Dict[str, Any]):

        if self.name in SESSION_TOOLS:

            asset = self.db_manager.get_asset_by_name(SESSION_ASSET_NAME)

            if not asset:

                asset_model = AssetModel(

                    name=SESSION_ASSET_NAME,

                    type=AssetType.HOST,

                    value=SESSION_ASSET_VALUE,

                )

                asset_id = self.db_manager.add_asset(asset_model)

                asset = self.db_manager.get_asset(asset_id)

            return asset

        target = (

            params.get("target_url")

            or params.get("target")

            or params.get("domain")

            or params.get("host")

            or params.get("url")

        )



        if not target:

            return None



        target_val = strip_host(
            target.replace("https://", "").replace("http://", "").strip("/")
        )

        asset = self.db_manager.get_asset_by_name(target_val)

        if not asset:

            asset = self.db_manager.get_asset_by_value(target_val)

        if not asset:

            asset_type = AssetType.HOST

            if is_valid_ip(target_val):

                asset_type = AssetType.HOST

            elif "http" in target or "www" in target_val:

                asset_type = AssetType.DOMAIN

            elif "." in target_val:

                asset_type = AssetType.DOMAIN

            asset_model = AssetModel(name=target_val, type=asset_type, value=target_val)

            asset_id = self.db_manager.add_asset(asset_model)

            asset = self.db_manager.get_asset(asset_id)

        return asset



    def _apply_provenance(self, findings, provenance: Dict[str, Any]):

        run_id = provenance.get("run_id")

        step_id = provenance.get("step_id")

        for finding in findings:

            finding.source_tool = finding.source_tool or self.name

            if run_id:

                finding.run_id = run_id

            if step_id:

                finding.step_id = step_id



    def _conflict_note(self, findings, mutated) -> str:
        titles = []
        for finding in list(findings) + list(mutated):
            if getattr(finding, "verification_state", None) != "conflicted":
                continue
            title = getattr(finding, "title", None)
            if title and title not in titles:
                titles.append(title)
        if not titles:
            return ""
        return "Reconciled observations (not confirmed findings): " + "; ".join(titles)

    def execute(self, params: Dict[str, Any]) -> Any:
        result = self.plugin_manager.run_adapter(self.name, params)
        provenance = get_run_context()
        interpretation = None
        finding_ids = []

        try:
            adapter_instance = self.plugin_manager.load_adapter(self.name)
            if hasattr(adapter_instance, "interpret_result"):
                candidate = adapter_instance.interpret_result(result)
                if isinstance(candidate, str):
                    interpretation = candidate
                    if isinstance(result.data, dict):
                        result.data["interpretation"] = interpretation
        except Exception as exc:
            self.logger.debug("interpret_result failed for %s: %s", self.name, exc)

        if self._is_successful_result(result):
            try:
                asset = self._resolve_asset(params)
                if asset and isinstance(result.data, dict):
                    output_for_normalization = dict(result.data)
                    if interpretation:
                        output_for_normalization["interpretation"] = interpretation

                    findings = self.reporting_manager.findings_normalizer.normalize_tool_output(
                        self.name, output_for_normalization, asset
                    )
                    self._apply_provenance(findings, provenance)
                    run_id = provenance.get("run_id") if provenance else None
                    peers = self.reporting_manager.get_findings_for_asset(
                        asset.id, run_id=run_id
                    )
                    mutated = (
                        self.reporting_manager.findings_normalizer
                        .reconcile_cross_tool_conflicts(
                            peers + findings,
                            run_id=run_id,
                            current_findings=findings,
                        )
                    )
                    to_save = list(findings)
                    for peer in mutated:
                        if peer not in to_save:
                            to_save.append(peer)
                    if to_save:
                        self.reporting_manager.save_findings_to_database(to_save)
                        finding_ids = [
                            finding.id for finding in to_save if getattr(finding, "id", None)
                        ]

                    note = self._conflict_note(findings, mutated)
                    if note:
                        interpretation = (note + "\n" + (interpretation or "")).strip()
                        if isinstance(result.data, dict):
                            result.data["interpretation"] = interpretation
            except Exception as exc:
                self.logger.warning(
                    "Finding normalization/persistence failed for %s: %s", self.name, exc
                )
        elif not interpretation:
            interpretation = self._format_adapter_error(result)

        payload = dict(result.data) if isinstance(result.data, dict) else {"value": result.data}
        if interpretation:
            payload["interpretation"] = interpretation
        if isinstance(result.metadata, dict):
            for key, value in result.metadata.items():
                payload.setdefault(key, value)
            retry_warnings = result.metadata.get("transient_retry_warnings") or []
            if retry_warnings:
                warnings = list(payload.get("warnings") or [])
                for item in retry_warnings:
                    text = str(item)
                    if text and text not in warnings:
                        warnings.append(text)
                payload["warnings"] = warnings
        if result.evidence_path:
            payload["evidence_path"] = result.evidence_path
        if result.error_message:
            payload.setdefault("error_message", result.error_message)
        payload["adapter_status"] = getattr(result.status, "value", "success")
        if finding_ids:
            payload["finding_ids"] = finding_ids
        if provenance:
            payload["provenance"] = provenance

        envelope = ToolResultEnvelope.from_adapter_result(
            self.name, result, payload, interpretation=interpretation
        )
        if finding_ids:
            envelope.finding_ids = finding_ids
        payload["envelope"] = envelope.model_dump()
        payload["finding_ids"] = envelope.finding_ids
        return payload



    def get_info(self) -> Dict[str, Any]:

        return self.plugin_manager.get_adapter_info(self.name) or {

            "name": self.name,

            "description": self.description,

        }


