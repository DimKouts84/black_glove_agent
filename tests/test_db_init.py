"""
Tests for database initialization and schema creation.
"""
import pytest
import tempfile
import os
import sys
from pathlib import Path
from unittest.mock import patch

# Add src to path for imports
sys.path.insert(0, 'src')

from agent.db import init_db, create_assets_table, create_findings_table, create_audit_log_table, DB_PATH

class TestDatabaseInitialization:
    """Test suite for database initialization functionality."""
    
    def test_init_db_creates_file(self):
        """Test that init_db creates the database file."""
        with tempfile.TemporaryDirectory() as temp_dir:
            with patch('agent.db.DB_PATH', Path(temp_dir) / ".homepentest" / "homepentest.db"):
                init_db()
                db_file = Path(temp_dir) / ".homepentest" / "homepentest.db"
                assert db_file.exists()
    
    def test_create_assets_table(self):
        """Test assets table creation."""
        with tempfile.TemporaryDirectory() as temp_dir:
            db_path = Path(temp_dir) / "test.db"
            import sqlite3
            conn = sqlite3.connect(db_path)
            
            try:
                create_assets_table(conn)
                
                # Check that table exists
                cursor = conn.cursor()
                cursor.execute("SELECT name FROM sqlite_master WHERE type='table' AND name='assets';")
                result = cursor.fetchone()
                assert result is not None
                
                # Check table schema
                cursor.execute("PRAGMA table_info(assets);")
                columns = [row[1] for row in cursor.fetchall()]
                expected_columns = ['id', 'name', 'type', 'value', 'created_at']
                for col in expected_columns:
                    assert col in columns
                    
            finally:
                conn.close()
                db_path.unlink(missing_ok=True)
    
    def test_create_findings_table(self):
        """Test findings table creation."""
        with tempfile.TemporaryDirectory() as temp_dir:
            db_path = Path(temp_dir) / "test.db"
            import sqlite3
            conn = sqlite3.connect(db_path)
            
            try:
                # Create assets table first (foreign key reference)
                create_assets_table(conn)
                create_findings_table(conn)
                
                # Check that table exists
                cursor = conn.cursor()
                cursor.execute("SELECT name FROM sqlite_master WHERE type='table' AND name='findings';")
                result = cursor.fetchone()
                assert result is not None
                
                # Check table schema
                cursor.execute("PRAGMA table_info(findings);")
                columns = [row[1] for row in cursor.fetchall()]
                expected_columns = ['id', 'asset_id', 'title', 'severity', 'confidence', 'evidence_path', 'recommended_fix', 'created_at']
                for col in expected_columns:
                    assert col in columns
                    
            finally:
                conn.close()
                db_path.unlink(missing_ok=True)
    
    def test_create_audit_log_table(self):
        """Test audit_log table creation."""
        with tempfile.TemporaryDirectory() as temp_dir:
            db_path = Path(temp_dir) / "test.db"
            import sqlite3
            conn = sqlite3.connect(db_path)
            
            try:
                create_audit_log_table(conn)
                
                # Check that table exists
                cursor = conn.cursor()
                cursor.execute("SELECT name FROM sqlite_master WHERE type='table' AND name='audit_log';")
                result = cursor.fetchone()
                assert result is not None
                
                # Check table schema
                cursor.execute("PRAGMA table_info(audit_log);")
                columns = [row[1] for row in cursor.fetchall()]
                expected_columns = ['id', 'ts', 'actor', 'event_type', 'data']
                for col in expected_columns:
                    assert col in columns
                    
            finally:
                conn.close()
                db_path.unlink(missing_ok=True)
    
    def test_full_schema_creation(self):
        """Test complete schema creation."""
        with tempfile.TemporaryDirectory() as temp_dir:
            with patch('agent.db.DB_PATH', Path(temp_dir) / ".homepentest" / "homepentest.db"):
                init_db()
                
                # Check that all tables exist
                import sqlite3
                conn = sqlite3.connect(DB_PATH)
                
                try:
                    cursor = conn.cursor()
                    cursor.execute("SELECT name FROM sqlite_master WHERE type='table';")
                    tables = [row[0] for row in cursor.fetchall()]
                    
                    expected_tables = ['assets', 'findings', 'audit_log']
                    for table in expected_tables:
                        assert table in tables
                        
                finally:
                    conn.close()

if __name__ == "__main__":
    pytest.main([__file__])
