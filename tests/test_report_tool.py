import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent))
sys.path.insert(0, str(Path(__file__).parent.parent / "src"))

import pytest
from unittest.mock import MagicMock, patch

from agent.tools.report_tool import ReportTool
from agent.reporting import ReportFormat


class TestReportTool:
    @patch("agent.tools.report_tool.get_run_context")
    @patch("agent.tools.report_tool.ReportingManager")
    @patch("agent.tools.report_tool.init_db")
    def test_execute_markdown_default(self, mock_init_db, mock_rm_cls, mock_ctx, tmp_path):
        mock_ctx.return_value = {"run_id": "run-abc"}
        mock_rm = MagicMock()
        mock_rm.generate_assessment_report.return_value = "# Pentest Report\n"
        mock_rm_cls.return_value = mock_rm

        tool = ReportTool()
        with patch("agent.tools.report_tool._reports_dir", return_value=tmp_path):
            output = tool.execute({})

        assert output["report_preview"].startswith("# Pentest Report")
        assert (tmp_path / "run-abc.md").read_text(encoding="utf-8").startswith("# Pentest Report")
        mock_rm.generate_assessment_report.assert_called_once_with(
            format_type=ReportFormat.MARKDOWN,
            include_evidence=True,
            run_id="run-abc",
        )

    @patch("agent.tools.report_tool.get_run_context")
    @patch("agent.tools.report_tool.ReportingManager")
    @patch("agent.tools.report_tool.init_db")
    def test_execute_json_format(self, mock_init_db, mock_rm_cls, mock_ctx, tmp_path):
        mock_ctx.return_value = {}
        mock_rm = MagicMock()
        mock_rm.generate_assessment_report.return_value = '{"findings": []}'
        mock_rm_cls.return_value = mock_rm

        tool = ReportTool()
        with patch("agent.tools.report_tool._reports_dir", return_value=tmp_path):
            output = tool.execute({"format": "json", "include_evidence": False})

        assert "findings" in output["report_preview"]
        assert "findings" in (tmp_path / "latest.json").read_text(encoding="utf-8")
        mock_rm.generate_assessment_report.assert_called_once_with(
            format_type=ReportFormat.JSON,
            include_evidence=False,
            run_id=None,
        )

    @patch("agent.tools.report_tool.ReportingManager")
    @patch("agent.tools.report_tool.init_db")
    def test_execute_handles_errors(self, mock_init_db, mock_rm_cls):
        mock_rm = MagicMock()
        mock_rm.generate_assessment_report.side_effect = RuntimeError("db unavailable")
        mock_rm_cls.return_value = mock_rm

        tool = ReportTool()
        output = tool.execute({})

        assert "Error generating report" in output
