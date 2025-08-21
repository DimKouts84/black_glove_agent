"""
Tests for Reporting Module

This module contains tests for the reporting functionality including
findings normalization, evidence storage, and report generation.
"""

import pytest
import json
import tempfile
import os
from pathlib import Path
from datetime import datetime
from unittest.mock import Mock, patch
from enum import Enum

from src.agent.reporting import (
    EvidenceStorage, FindingsNormalizer, ReportGenerator, ReportingManager,
    Finding, ReportFormat, SeverityLevel
)
from src.agent.models import AssetModel, AssetType


class TestEvidenceStorage:
    """Test cases for EvidenceStorage class."""
    
    def test_evidence_storage_initialization(self):
        """Test EvidenceStorage initialization with default path."""
        with tempfile.TemporaryDirectory() as temp_dir:
            storage_path = Path(temp_dir) / "test_evidence"
            storage = EvidenceStorage(str(storage_path))
            
            assert storage.storage_path == storage_path
            assert storage_path.exists()
    
    def test_store_evidence_string_content(self):
        """Test storing evidence with string content."""
        with tempfile.TemporaryDirectory() as temp_dir:
            storage = EvidenceStorage(temp_dir)
            content = "Test evidence content"
            filename = "test_evidence.txt"
            
            metadata = storage.store_evidence(content, filename)
            
            # Check metadata
            assert "path" in metadata
            assert "hash" in metadata
            assert "size" in metadata
            assert "timestamp" in metadata
            assert metadata["filename"] == filename
            assert metadata["size"] == len(content.encode('utf-8'))
            
            # Check file was created
            evidence_path = Path(metadata["path"])
            assert evidence_path.exists()
            assert evidence_path.read_text() == content
    
    def test_store_evidence_with_asset_directory(self):
        """Test storing evidence in asset-specific directory."""
        with tempfile.TemporaryDirectory() as temp_dir:
            storage = EvidenceStorage(temp_dir)
            content = "Test evidence content"
            filename = "test_evidence.txt"
            asset_name = "test_asset"
            
            metadata = storage.store_evidence(content, filename, asset_name)
            
            # Check file was created in asset directory
            evidence_path = Path(metadata["path"])
            assert asset_name in str(evidence_path)
            assert evidence_path.exists()
            assert evidence_path.read_text() == content
    
    def test_verify_integrity_valid(self):
        """Test integrity verification with valid hash."""
        with tempfile.TemporaryDirectory() as temp_dir:
            storage = EvidenceStorage(temp_dir)
            content = "Test evidence content"
            filename = "test_evidence.txt"
            
            metadata = storage.store_evidence(content, filename)
            evidence_path = metadata["path"]
            expected_hash = metadata["hash"]
            
            # Verify integrity
            result = storage.verify_integrity(evidence_path, expected_hash)
            assert result is True
    
    def test_verify_integrity_invalid(self):
        """Test integrity verification with invalid hash."""
        with tempfile.TemporaryDirectory() as temp_dir:
            storage = EvidenceStorage(temp_dir)
            content = "Test evidence content"
            filename = "test_evidence.txt"
            
            metadata = storage.store_evidence(content, filename)
            evidence_path = metadata["path"]
            invalid_hash = "invalid_hash"
            
            # Verify integrity with wrong hash
            result = storage.verify_integrity(evidence_path, invalid_hash)
            assert result is False
    
    def test_verify_integrity_missing_file(self):
        """Test integrity verification with missing file."""
        with tempfile.TemporaryDirectory() as temp_dir:
            storage = EvidenceStorage(temp_dir)
            missing_path = str(Path(temp_dir) / "missing_file.txt")
            expected_hash = "some_hash"
            
            # Verify integrity of missing file
            result = storage.verify_integrity(missing_path, expected_hash)
            assert result is False
    
    def test_get_evidence_metadata(self):
        """Test getting evidence file metadata."""
        with tempfile.TemporaryDirectory() as temp_dir:
            storage = EvidenceStorage(temp_dir)
            content = "Test evidence content"
            filename = "test_evidence.txt"
            
            metadata = storage.store_evidence(content, filename)
            evidence_path = metadata["path"]
            
            # Get metadata
            file_metadata = storage.get_evidence_metadata(evidence_path)
            
            assert file_metadata is not None
            assert "path" in file_metadata
            assert "size" in file_metadata
            assert "modified" in file_metadata
            assert "created" in file_metadata
            assert file_metadata["size"] == len(content.encode('utf-8'))


class TestFinding:
    """Test cases for Finding dataclass."""
    
    def test_finding_creation(self):
        """Test creating a finding with default values."""
        finding = Finding(
            title="Test Finding",
            description="Test description",
            severity=SeverityLevel.HIGH,
            confidence=0.95,
            asset_id=1,
            asset_name="test_asset"
        )
        
        assert finding.title == "Test Finding"
        assert finding.description == "Test description"
        assert finding.severity == SeverityLevel.HIGH
        assert finding.confidence == 0.95
        assert finding.asset_id == 1
        assert finding.asset_name == "test_asset"
        assert finding.references == []  # Default value
        assert finding.created_at is not None  # Auto-generated
    
    def test_finding_to_dict(self):
        """Test converting finding to dictionary."""
        finding = Finding(
            id=1,
            title="Test Finding",
            description="Test description",
            severity=SeverityLevel.HIGH,
            confidence=0.95,
            asset_id=1,
            asset_name="test_asset",
            evidence_path="/path/to/evidence.txt",
            evidence_hash="abc123",
            recommended_fix="Fix the issue",
            references=["https://example.com"],
            cvss_score=7.5
        )
        
        data = finding.to_dict()
        
        assert data["id"] == 1
        assert data["title"] == "Test Finding"
        assert data["severity"] == "high"
        assert data["confidence"] == 0.95
        assert data["asset_id"] == 1
        assert data["asset_name"] == "test_asset"
        assert data["evidence_path"] == "/path/to/evidence.txt"
        assert data["evidence_hash"] == "abc123"
        assert data["recommended_fix"] == "Fix the issue"
        assert data["references"] == ["https://example.com"]
        assert data["cvss_score"] == 7.5
    
    def test_finding_from_dict(self):
        """Test creating finding from dictionary."""
        data = {
            "id": 1,
            "title": "Test Finding",
            "description": "Test description",
            "severity": "high",
            "confidence": 0.95,
            "asset_id": 1,
            "asset_name": "test_asset",
            "evidence_path": "/path/to/evidence.txt",
            "evidence_hash": "abc123",
            "recommended_fix": "Fix the issue",
            "references": ["https://example.com"],
            "cvss_score": 7.5
        }
        
        finding = Finding.from_dict(data)
        
        assert finding.id == 1
        assert finding.title == "Test Finding"
        assert finding.severity == SeverityLevel.HIGH
        assert finding.confidence == 0.95
        assert finding.asset_id == 1
        assert finding.asset_name == "test_asset"
        assert finding.evidence_path == "/path/to/evidence.txt"
        assert finding.evidence_hash == "abc123"
        assert finding.recommended_fix == "Fix the issue"
        assert finding.references == ["https://example.com"]
        assert finding.cvss_score == 7.5


class TestFindingsNormalizer:
    """Test cases for FindingsNormalizer class."""
    
    def test_findings_normalizer_initialization(self):
        """Test FindingsNormalizer initialization."""
        normalizer = FindingsNormalizer()
        assert normalizer is not None
        assert normalizer.logger is not None
        assert normalizer.evidence_storage is not None
    
    def test_normalize_tool_output_generic(self):
        """Test normalizing generic tool output."""
        normalizer = FindingsNormalizer()
        asset = AssetModel(
            id=1,
            name="test_asset",
            type=AssetType.HOST,
            value="192.168.1.100"
        )
        tool_output = {"test": "output"}
        
        with patch.object(normalizer.evidence_storage, 'store_evidence') as mock_store:
            mock_store.return_value = {
                "path": "/test/path/evidence.txt",
                "hash": "test_hash"
            }
            
            findings = normalizer.normalize_tool_output("unknown_tool", tool_output, asset)
            
            assert len(findings) == 1
            finding = findings[0]
            assert finding.title == "unknown_tool scan completed on test_asset"
            assert finding.severity == SeverityLevel.MEDIUM
            assert finding.confidence == 0.9
            assert finding.asset_id == 1
            assert finding.asset_name == "test_asset"
    
    def test_normalize_port_scan_output(self):
        """Test normalizing port scan output."""
        normalizer = FindingsNormalizer()
        asset = AssetModel(
            id=1,
            name="test_asset",
            type=AssetType.HOST,
            value="192.168.1.100"
        )
        tool_output = {"ports": [{"port": 22, "state": "open"}, {"port": 80, "state": "open"}]}
        
        with patch.object(normalizer.evidence_storage, 'store_evidence') as mock_store:
            mock_store.return_value = {
                "path": "/test/path/evidence.txt",
                "hash": "test_hash"
            }
            
            findings = normalizer.normalize_tool_output("nmap", tool_output, asset)
            
            # Should find high-risk port 22 (SSH)
            assert len(findings) >= 1
            ssh_finding = next((f for f in findings if "port 22" in f.title), None)
            assert ssh_finding is not None
            assert ssh_finding.severity == SeverityLevel.HIGH
            assert "SSH" in ssh_finding.description
    
    def test_normalize_directory_scan_output(self):
        """Test normalizing directory scan output."""
        normalizer = FindingsNormalizer()
        asset = AssetModel(
            id=1,
            name="test_asset",
            type=AssetType.HOST,
            value="192.168.1.100"
        )
        tool_output = {"paths": ["/admin", "/login", "/config"]}
        
        with patch.object(normalizer.evidence_storage, 'store_evidence') as mock_store:
            mock_store.return_value = {
                "path": "/test/path/evidence.txt",
                "hash": "test_hash"
            }
            
            findings = normalizer.normalize_tool_output("gobuster", tool_output, asset)
            
            # Should find sensitive paths
            assert len(findings) >= 1
            admin_finding = next((f for f in findings if "/admin" in f.title), None)
            assert admin_finding is not None
            assert admin_finding.severity == SeverityLevel.MEDIUM
            assert "sensitive path" in admin_finding.description
    
    def test_normalize_error_handling(self):
        """Test error handling in tool output normalization."""
        normalizer = FindingsNormalizer()
        asset = AssetModel(
            id=1,
            name="test_asset",
            type=AssetType.HOST,
            value="192.168.1.100"
        )
        
        # Simulate an error during normalization
        with patch.object(normalizer.evidence_storage, 'store_evidence', 
                         side_effect=Exception("Storage error")):
            findings = normalizer.normalize_tool_output("test_tool", "test_output", asset)
            
            # Should create error finding
            assert len(findings) == 1
            error_finding = findings[0]
            assert "Error processing" in error_finding.title
            assert error_finding.severity == SeverityLevel.LOW


class TestReportGenerator:
    """Test cases for ReportGenerator class."""
    
    def test_report_generator_initialization(self):
        """Test ReportGenerator initialization."""
        generator = ReportGenerator()
        assert generator is not None
        assert generator.logger is not None
        assert generator.evidence_storage is not None
    
    def test_generate_json_report(self):
        """Test generating JSON report."""
        generator = ReportGenerator()
        findings = [
            Finding(
                id=1,
                title="Test Finding",
                description="Test description",
                severity=SeverityLevel.HIGH,
                confidence=0.95,
                asset_id=1,
                asset_name="test_asset"
            )
        ]
        assets = [
            AssetModel(
                id=1,
                name="test_asset",
                type=AssetType.HOST,
                value="192.168.1.100"
            )
        ]
        metadata = {"test": "metadata"}
        
        report_content = generator.generate_report(findings, assets, metadata, ReportFormat.JSON)
        
        # Parse JSON to verify structure
        report_data = json.loads(report_content)
        assert "report_info" in report_data
        assert "summary" in report_data
        assert "assets" in report_data
        assert "findings" in report_data
        assert len(report_data["findings"]) == 1
        assert report_data["findings"][0]["title"] == "Test Finding"
    
    def test_generate_markdown_report(self):
        """Test generating Markdown report."""
        generator = ReportGenerator()
        findings = [
            Finding(
                id=1,
                title="Test Finding",
                description="Test description",
                severity=SeverityLevel.HIGH,
                confidence=0.95,
                asset_id=1,
                asset_name="test_asset"
            )
        ]
        assets = [
            AssetModel(
                id=1,
                name="test_asset",
                type=AssetType.HOST,
                value="192.168.1.100"
            )
        ]
        metadata = {"test": "metadata"}
        
        report_content = generator.generate_report(findings, assets, metadata, ReportFormat.MARKDOWN)
        
        # Check basic Markdown structure
        assert "# Black Glove Security Assessment Report" in report_content
        assert "Test Finding" in report_content
        assert "test_asset" in report_content
        assert "High Severity Findings" in report_content
    
    def test_generate_html_report(self):
        """Test generating HTML report."""
        generator = ReportGenerator()
        findings = [
            Finding(
                id=1,
                title="Test Finding",
                description="Test description",
                severity=SeverityLevel.HIGH,
                confidence=0.95,
                asset_id=1,
                asset_name="test_asset"
            )
        ]
        assets = [
            AssetModel(
                id=1,
                name="test_asset",
                type=AssetType.HOST,
                value="192.168.1.100"
            )
        ]
        metadata = {"test": "metadata"}
        
        report_content = generator.generate_report(findings, assets, metadata, ReportFormat.HTML)
        
        # Check basic HTML structure
        assert "<!DOCTYPE html>" in report_content
        assert "<title>Black Glove Security Assessment Report</title>" in report_content
        assert "Test Finding" in report_content
        assert "test_asset" in report_content
        assert "high" in report_content  # CSS class for high severity
    
    def test_generate_csv_report(self):
        """Test generating CSV report."""
        generator = ReportGenerator()
        findings = [
            Finding(
                id=1,
                title="Test Finding",
                description="Test description",
                severity=SeverityLevel.HIGH,
                confidence=0.95,
                asset_id=1,
                asset_name="test_asset"
            )
        ]
        assets = [
            AssetModel(
                id=1,
                name="test_asset",
                type=AssetType.HOST,
                value="192.168.1.100"
            )
        ]
        metadata = {"test": "metadata"}
        
        report_content = generator.generate_report(findings, assets, metadata, ReportFormat.CSV)
        
        # Check basic CSV structure
        lines = report_content.strip().split('\n')
        assert "Black Glove Security Assessment Report" in lines[0]
        assert "Test Finding" in report_content
        assert "test_asset" in report_content
        assert "high" in report_content.lower()
    
    def test_generate_unsupported_format(self):
        """Test generating report with unsupported format."""
        generator = ReportGenerator()
        findings = []
        assets = []
        metadata = {}
        
        # Test with a format that's not supported by the generator
        # We'll mock the ReportFormat enum to create an unsupported value
        with pytest.raises(ValueError, match="Unsupported report format"):
            generator.generate_report(findings, assets, metadata, ReportFormat.PDF)


class TestReportingManager:
    """Test cases for ReportingManager class."""
    
    def test_reporting_manager_initialization(self):
        """Test ReportingManager initialization."""
        manager = ReportingManager()
        assert manager is not None
        assert manager.logger is not None
        assert manager.findings_normalizer is not None
        assert manager.report_generator is not None
        assert manager.evidence_storage is not None
    
    def test_get_findings_from_database(self):
        """Test retrieving findings from database."""
        # Create mock database connection
        mock_conn = Mock()
        mock_cursor = Mock()
        mock_conn.cursor.return_value = mock_cursor
        mock_cursor.fetchall.return_value = [
            (1, "Test Finding", "high", 0.95, 1, "/path/evidence.txt", "Fix it", "2023-01-01T00:00:00")
        ]
        
        manager = ReportingManager(mock_conn)
        findings = manager.get_findings_from_database()
        
        assert len(findings) == 1
        finding = findings[0]
        assert finding.id == 1
        assert finding.title == "Test Finding"
        assert finding.severity == SeverityLevel.HIGH
        assert finding.confidence == 0.95
        assert finding.asset_id == 1
        assert finding.evidence_path == "/path/evidence.txt"
        assert finding.recommended_fix == "Fix it"
    
    def test_get_assets_from_database(self):
        """Test retrieving assets from database."""
        # Create mock database connection
        mock_conn = Mock()
        mock_cursor = Mock()
        mock_conn.cursor.return_value = mock_cursor
        mock_cursor.fetchall.return_value = [
            (1, "test_asset", "host", "192.168.1.100")
        ]
        
        manager = ReportingManager(mock_conn)
        assets = manager.get_assets_from_database()
        
        assert len(assets) == 1
        asset = assets[0]
        assert asset.id == 1
        assert asset.name == "test_asset"
        assert asset.type == AssetType.HOST
        assert asset.value == "192.168.1.100"
    
    def test_save_findings_to_database(self):
        """Test saving findings to database."""
        # Create mock database connection
        mock_conn = Mock()
        mock_cursor = Mock()
        mock_conn.cursor.return_value = mock_cursor
        
        manager = ReportingManager(mock_conn)
        findings = [
            Finding(
                title="Test Finding",
                description="Test description",
                severity=SeverityLevel.HIGH,
                confidence=0.95,
                asset_id=1,
                asset_name="test_asset",
                evidence_path="/path/evidence.txt",
                evidence_hash="test_hash",
                recommended_fix="Fix it"
            )
        ]
        
        manager.save_findings_to_database(findings)
        
        # Check that execute was called with correct parameters
        mock_cursor.execute.assert_called()
        mock_conn.commit.assert_called()
    
    def test_save_findings_to_database_error(self):
        """Test error handling when saving findings to database."""
        # Create mock database connection that raises an exception
        mock_conn = Mock()
        mock_cursor = Mock()
        mock_conn.cursor.return_value = mock_cursor
        mock_cursor.execute.side_effect = Exception("Database error")
        
        manager = ReportingManager(mock_conn)
        findings = [
            Finding(title="Test Finding", severity=SeverityLevel.HIGH, confidence=0.95, asset_id=1)
        ]
        
        # Should not raise exception, but should log error
        manager.save_findings_to_database(findings)
        mock_conn.rollback.assert_called()
    
    def test_generate_assessment_report(self):
        """Test generating assessment report."""
        # Create mock database connection
        mock_conn = Mock()
        mock_cursor = Mock()
        mock_conn.cursor.return_value = mock_cursor
        mock_cursor.fetchall.return_value = []  # Empty results for simplicity
        
        manager = ReportingManager(mock_conn)
        
        # Mock the report generator
        with patch.object(manager.report_generator, 'generate_report') as mock_generate:
            mock_generate.return_value = "Test report content"
            
            report_content = manager.generate_assessment_report(ReportFormat.JSON)
            
            assert report_content == "Test report content"
            mock_generate.assert_called()


# Integration tests
class TestReportingIntegration:
    """Integration tests for reporting components."""
    
    def test_full_reporting_workflow(self):
        """Test complete reporting workflow from tool output to final report."""
        with tempfile.TemporaryDirectory() as temp_dir:
            # Patch the EvidenceStorage to use our temp directory
            with patch('src.agent.reporting.EvidenceStorage') as mock_storage_class:
                mock_storage = Mock()
                mock_storage_class.return_value = mock_storage
                mock_storage.store_evidence.return_value = {
                    "path": f"{temp_dir}/test_evidence.txt",
                    "hash": "test_hash"
                }
                mock_storage.verify_integrity.return_value = True
                
                # Create test asset
                asset = AssetModel(
                    id=1,
                    name="test_server",
                    type=AssetType.HOST,
                    value="192.168.1.100"
                )
                
                # Create findings normalizer
                normalizer = FindingsNormalizer()
                
                # Normalize tool output
                tool_output = {
                    "ports": [
                        {"port": 22, "state": "open", "service": "ssh"},
                        {"port": 80, "state": "open", "service": "http"}
                    ]
                }
                
                findings = normalizer.normalize_tool_output("nmap", tool_output, asset)
                assert len(findings) >= 1
                
                # Verify evidence was stored
                ssh_finding = next((f for f in findings if "port 22" in f.title), None)
                assert ssh_finding is not None
                assert ssh_finding.evidence_path is not None
                
                # Verify evidence integrity
                evidence_path = ssh_finding.evidence_path
                integrity_check = mock_storage.verify_integrity(
                    evidence_path, ssh_finding.evidence_hash
                )
                assert integrity_check is True
            
            # Generate report
            generator = ReportGenerator()
            metadata = {
                "scan_duration": "10.5s",
                "total_scans": 1,
                "report_format": "json"
            }
            
            report_content = generator.generate_report(
                findings, [asset], metadata, ReportFormat.JSON
            )
            
            # Verify report structure
            report_data = json.loads(report_content)
            assert "report_info" in report_data
            assert "summary" in report_data
            assert "findings" in report_data
            assert len(report_data["findings"]) >= 1
            
            # Check finding details
            report_finding = report_data["findings"][0]
            assert "port 22" in report_finding["title"]
            assert report_finding["severity"] == "high"
            assert report_finding["asset_name"] == "test_server"
    
    def test_multiple_format_generation(self):
        """Test generating reports in multiple formats."""
        findings = [
            Finding(
                id=1,
                title="Critical Security Issue",
                description="A critical security vulnerability was found",
                severity=SeverityLevel.CRITICAL,
                confidence=0.99,
                asset_id=1,
                asset_name="web_server",
                evidence_path="/evidence/critical_issue.txt",
                evidence_hash="abc123",
                recommended_fix="Apply security patch immediately",
                cvss_score=9.8
            )
        ]
        assets = [
            AssetModel(
                id=1,
                name="web_server",
                type=AssetType.HOST,
                value="192.168.1.200"
            )
        ]
        metadata = {
            "scan_duration": "15.2s",
            "total_scans": 1,
            "generated_by": "Black Glove v1.0"
        }
        
        generator = ReportGenerator()
        
        # Test all supported formats
        formats_to_test = [
            ReportFormat.JSON,
            ReportFormat.MARKDOWN,
            ReportFormat.HTML,
            ReportFormat.CSV
        ]
        
        for format_type in formats_to_test:
            report_content = generator.generate_report(findings, assets, metadata, format_type)
            assert len(report_content) > 0
            assert isinstance(report_content, str)
            
            # Format-specific checks
            if format_type == ReportFormat.JSON:
                # Should be valid JSON
                json.loads(report_content)
            elif format_type == ReportFormat.MARKDOWN:
                assert "# Black Glove Security Assessment Report" in report_content
            elif format_type == ReportFormat.HTML:
                assert "<!DOCTYPE html>" in report_content
            elif format_type == ReportFormat.CSV:
                lines = report_content.strip().split('\n')
                assert len(lines) > 0


if __name__ == "__main__":
    pytest.main([__file__])
