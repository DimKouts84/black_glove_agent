"""Regression tests for session cb9f7682 remediation."""

import sqlite3
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).parent.parent / "src"))
sys.path.insert(0, str(Path(__file__).parent.parent))

from adapters.gobuster import create_gobuster_adapter
from agent.db import create_assets_table, create_findings_table, create_finding_observations_table
from agent.models import AssetModel, AssetType, SeverityLevel
from agent.reporting import FindingsNormalizer, Finding, ReportingManager, ReportGenerator, ReportFormat
from agent.plugin_manager import PluginManager


def _memory_db():
    conn = sqlite3.connect(":memory:")
    create_assets_table(conn)
    create_findings_table(conn)
    create_finding_observations_table(conn)
    conn.execute(
        "INSERT INTO assets (id, name, type, value) VALUES (1, 'dimkouts.dev', 'domain', 'dimkouts.dev')"
    )
    conn.commit()
    return conn


class TestGobusterWordlistResolve:
    def test_gobuster_resolves_bare_wordlist_filename(self):
        adapter = create_gobuster_adapter()
        resolved = adapter._resolve_wordlist_path("common.txt")
        assert Path(resolved).name == "common.txt"
        assert Path(resolved).is_file()

    def test_plugin_manager_resolves_bare_wordlist(self):
        pm = PluginManager()
        normalized = pm._normalize_params(
            "gobuster",
            {"mode": "dir", "url": "https://dimkouts.dev", "wordlist": "common.txt"},
        )
        assert Path(normalized["wordlist"]).is_file()


class TestAssetTableFromDb:
    def test_get_findings_populates_asset_name(self):
        conn = _memory_db()
        manager = ReportingManager(conn)
        manager.save_findings_to_database([
            Finding(
                title="DNS A records for dimkouts.dev",
                description="A: 104.21.61.1",
                severity=SeverityLevel.LOW,
                asset_id=1,
                asset_name="dimkouts.dev",
                source_tool="dns_lookup",
                run_id="run-1",
            )
        ])
        loaded = manager.get_findings_from_database(run_id="run-1")
        assert len(loaded) == 1
        assert loaded[0].asset_name == "dimkouts.dev"

    def test_asset_table_populated_from_db_findings(self):
        conn = _memory_db()
        manager = ReportingManager(conn)
        findings = [
            Finding(
                title="DNS A records for dimkouts.dev",
                description="A: 104.21.61.1, 172.67.208.240",
                severity=SeverityLevel.LOW,
                asset_id=1,
                asset_name="dimkouts.dev",
                source_tool="dns_lookup",
                run_id="run-1",
            ),
            Finding(
                title="Technology detected: Cloudflare",
                description="CDN",
                severity=SeverityLevel.LOW,
                asset_id=1,
                asset_name="dimkouts.dev",
                source_tool="wappalyzer",
                run_id="run-1",
            ),
        ]
        manager.save_findings_to_database(findings)
        loaded = manager.get_findings_from_database(run_id="run-1")
        assets = manager.get_assets_for_findings(loaded)
        report = ReportGenerator().generate_report(
            loaded,
            assets,
            {"primary_target": "dimkouts.dev"},
            ReportFormat.MARKDOWN,
        )
        assert "104.21.61.1" in report
        assert "Cloudflare" in report


class TestNmapPortInventory:
    @pytest.fixture
    def normalizer(self):
        return FindingsNormalizer()

    @pytest.fixture
    def asset(self):
        return AssetModel(id=1, name="dimkouts.dev", type=AssetType.DOMAIN, value="dimkouts.dev")

    def test_nmap_emits_open_ports_inventory_finding(self, normalizer, asset, tmp_path, monkeypatch):
        monkeypatch.setattr(normalizer.evidence_storage, "storage_path", tmp_path)
        output = {
            "hosts": [
                {
                    "address": "172.67.208.240",
                    "ports": [
                        {"port": "80", "state": "open", "service": "http"},
                        {"port": "443", "state": "open", "service": "https"},
                        {"port": "8080", "state": "open", "service": "http"},
                    ],
                }
            ]
        }
        findings = normalizer.normalize_tool_output("nmap", output, asset)
        inventory = [f for f in findings if f.title.startswith("Open ports discovered")]
        assert len(inventory) == 1
        assert inventory[0].severity == SeverityLevel.INFO
        assert inventory[0].verification_state == "informational"
        assert "80/http" in inventory[0].description
        assert "443/https" in inventory[0].description
        assert "8080/http" in inventory[0].description


class TestObservationDedup:
    def test_skip_duplicate_observation_same_run(self):
        conn = _memory_db()
        manager = ReportingManager(conn)
        finding = Finding(
            title="Subdomains discovered (2)",
            description="Sources: osint_harvester; sample: dimkouts.dev",
            severity=SeverityLevel.LOW,
            asset_id=1,
            asset_name="dimkouts.dev",
            source_tool="osint_harvester",
            run_id="run-dup",
        )
        manager.save_findings_to_database([finding])
        manager.save_findings_to_database([finding])

        cur = conn.cursor()
        cur.execute(
            "SELECT COUNT(*) FROM finding_observations WHERE run_id = ?",
            ("run-dup",),
        )
        assert cur.fetchone()[0] == 1
