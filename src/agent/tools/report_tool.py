from typing import Dict, Any, List
from agent.reporting import ReportingManager, ReportFormat
from agent.db import init_db
from agent.execution_provenance import get_run_context


class ReportTool:
    def __init__(self, db_connection=None):
        self.name = "generate_report"
        self.description = (
            "Generates a comprehensive security assessment report based on findings "
            "from executed tools. Use this tool when the user asks for a report or "
            "after completing a scan."
        )

        init_db()
        self.reporting_manager = ReportingManager(db_connection)

    def execute(self, params: Dict[str, Any]) -> str:
        """
        Execute report generation.

        Params:
            format (str): Output format (markdown, json, html, csv). Default: markdown
            include_evidence (bool): Whether to include evidence paths. Default: True
            run_id (str): Optional run scope; defaults to current run context
        """
        format_str = params.get("format", "markdown").lower()
        include_evidence = params.get("include_evidence", True)
        run_id = params.get("run_id") or get_run_context().get("run_id")

        try:
            report_format = ReportFormat(format_str)
        except ValueError:
            report_format = ReportFormat.MARKDOWN

        try:
            report_content = self.reporting_manager.generate_assessment_report(
                format_type=report_format,
                include_evidence=include_evidence,
                run_id=run_id,
            )
            return report_content
        except Exception as e:
            return f"Error generating report: {str(e)}"

    def get_info(self) -> Dict[str, Any]:
        return {
            "name": self.name,
            "description": self.description,
            "parameters": {
                "type": "object",
                "properties": {
                    "format": {
                        "type": "string",
                        "enum": ["markdown", "json", "html", "csv"],
                        "description": "The format of the report (default: markdown)"
                    },
                    "include_evidence": {
                        "type": "boolean",
                        "description": "Whether to include evidence paths in the report"
                    },
                    "run_id": {
                        "type": "string",
                        "description": "Optional run ID to scope findings (defaults to current run)"
                    }
                }
            }
        }
