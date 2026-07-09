import pytest
from src.agent.reporting import ReportGenerator, ReportFormat, Finding
from src.agent.models import SeverityLevel, AssetModel, AssetType


class TestReportTemplate:
    def test_markdown_template_renders_sections(self):
        generator = ReportGenerator()
        findings = [
            Finding(
                id=1,
                title="Open SSH",
                description="Port 22 is open",
                severity=SeverityLevel.HIGH,
                confidence=0.9,
                asset_id=1,
                asset_name="example.com",
                recommended_fix="Restrict SSH access",
            )
        ]
        assets = [
            AssetModel(id=1, name="example.com", type=AssetType.DOMAIN, value="example.com")
        ]
        content = generator.generate_report(findings, assets, {}, ReportFormat.MARKDOWN)
        assert "# Pentest Report" in content
        assert "Executive Summary" in content
        assert "Detailed Findings" in content
        assert "Open SSH" in content
