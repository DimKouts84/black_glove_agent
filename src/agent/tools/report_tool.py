import re
from pathlib import Path
from typing import Dict, Any, Union

from agent.reporting import ReportingManager, ReportFormat
from agent.db import init_db
from agent.execution_provenance import get_run_context

_FORMAT_EXTENSIONS = {
    "markdown": "md",
    "json": "json",
    "html": "html",
    "csv": "csv",
}


def _reports_dir() -> Path:
    return Path.home() / ".homepentest" / "evidence" / "reports"


def _build_report_summary(content: str) -> str:
    target_match = re.search(r"\*\*Target:\*\*\s*(.+)", content)
    issues_match = re.search(r"Found (\d+) issues", content)
    risk_match = re.search(r"Risk Score:\s*([\d.]+)", content)
    target = target_match.group(1).strip() if target_match else "unknown target"
    issues = issues_match.group(1) if issues_match else "?"
    risk = risk_match.group(1) if risk_match else "?"
    return f"Pentest report for {target} - {issues} issues (risk {risk}/10)"


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

    def execute(self, params: Dict[str, Any]) -> Union[Dict[str, Any], str]:
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
            ext = _FORMAT_EXTENSIONS.get(format_str, "md")
            reports_dir = _reports_dir()
            reports_dir.mkdir(parents=True, exist_ok=True)
            file_stem = run_id or "latest"
            report_path = reports_dir / f"{file_stem}.{ext}"
            report_path.write_text(report_content, encoding="utf-8")

            return {
                "report_path": str(report_path),
                "format": format_str,
                "summary": _build_report_summary(report_content),
                "report_preview": report_content[:1500],
            }
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
                        "description": "The format of the report (default: markdown)",
                    },
                    "include_evidence": {
                        "type": "boolean",
                        "description": "Whether to include evidence paths in the report",
                    },
                    "run_id": {
                        "type": "string",
                        "description": "Optional run ID to scope findings (defaults to current run)",
                    },
                },
            },
        }
