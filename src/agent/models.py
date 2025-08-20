"""
Pydantic models for Black Glove pentest agent.
Provides data validation and configuration management.
"""
from pydantic import BaseModel, Field
from typing import Optional, Dict, Any
from enum import Enum

class AssetType(str, Enum):
    """Enumeration of supported asset types."""
    HOST = "host"
    DOMAIN = "domain"
    VM = "vm"

class SeverityLevel(str, Enum):
    """Enumeration of severity levels for findings."""
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"

class EventType(str, Enum):
    """Enumeration of audit log event types."""
    APPROVAL = "approval"
    LLM_FAILURE = "llm_failure"
    ADAPTER_INVOCATION = "adapter_invocation"
    SCAN_START = "scan_start"
    SCAN_COMPLETE = "scan_complete"
    FINDING_CREATED = "finding_created"
    ERROR = "error"
    INFO = "info"

class AssetModel(BaseModel):
    """
    Model for asset data validation.
    Represents an asset that can be scanned (host, domain, or VM).
    """
    name: str = Field(..., description="Human-readable name for the asset")
    type: AssetType = Field(..., description="Type of asset (host, domain, or vm)")
    value: str = Field(..., description="IP address, domain name, or VM identifier")
    id: Optional[int] = Field(None, description="Database ID (auto-generated)")

class ConfigModel(BaseModel):
    """
    Model for configuration validation.
    Represents the agent's configuration settings.
    """
    # LLM settings
    llm_provider: str = Field(default="lmstudio", description="LLM provider (lmstudio, ollama, openrouter)")
    llm_endpoint: str = Field(default="http://localhost:1234/v1", description="LLM API endpoint")
    llm_model: str = Field(default="local-model", description="LLM model name")
    llm_temperature: float = Field(default=0.7, ge=0.0, le=1.0, description="LLM temperature setting")
    
    # Scan settings
    default_rate_limit: int = Field(default=50, ge=1, description="Default packets per second rate limit")
    max_rate_limit: int = Field(default=100, ge=1, description="Maximum allowed rate limit")
    scan_timeout: int = Field(default=300, ge=1, description="Scan timeout in seconds")
    
    # Logging settings
    log_level: str = Field(default="INFO", description="Logging level (DEBUG, INFO, WARNING, ERROR)")
    log_retention_days: int = Field(default=90, ge=1, description="Log retention period in days")
    
    # Safety settings
    require_lab_mode_for_exploits: bool = Field(default=True, description="Require lab mode for exploit tools")
    enable_exploit_adapters: bool = Field(default=False, description="Enable exploit adapters (disabled by default)")
    
    # Evidence storage
    evidence_storage_path: str = Field(default="~/.homepentest/evidence", description="Path to store evidence files")
    
    # Additional settings
    extra_settings: Optional[Dict[str, Any]] = Field(default=None, description="Additional configuration settings")

class DatabaseManager:
    """
    Class to handle database operations and connections.
    Provides a higher-level interface for database interactions.
    """
    def __init__(self):
        """Initialize the database manager."""
        from .db import get_db_connection
        self.get_db_connection = get_db_connection
    
    def add_asset(self, asset: AssetModel) -> int:
        """
        Add an asset to the database.
        
        Args:
            asset: AssetModel instance to add
            
        Returns:
            int: ID of the newly created asset
        """
        conn = self.get_db_connection()
        try:
            cursor = conn.cursor()
            cursor.execute(
                "INSERT INTO assets (name, type, value) VALUES (?, ?, ?)",
                (asset.name, asset.type.value, asset.value)
            )
            asset_id = cursor.lastrowid
            conn.commit()
            return asset_id
        finally:
            conn.close()
    
    def get_asset(self, asset_id: int) -> Optional[AssetModel]:
        """
        Retrieve an asset from the database by ID.
        
        Args:
            asset_id: ID of the asset to retrieve
            
        Returns:
            AssetModel: Asset model instance, or None if not found
        """
        conn = self.get_db_connection()
        try:
            cursor = conn.cursor()
            cursor.execute(
                "SELECT id, name, type, value FROM assets WHERE id = ?",
                (asset_id,)
            )
            row = cursor.fetchone()
            if row:
                return AssetModel(
                    id=row[0],
                    name=row[1],
                    type=AssetType(row[2]),
                    value=row[3]
                )
            return None
        finally:
            conn.close()
    
    def list_assets(self) -> list[AssetModel]:
        """
        List all assets in the database.
        
        Returns:
            list[AssetModel]: List of all assets
        """
        conn = self.get_db_connection()
        try:
            cursor = conn.cursor()
            cursor.execute("SELECT id, name, type, value FROM assets")
            rows = cursor.fetchall()
            return [
                AssetModel(
                    id=row[0],
                    name=row[1],
                    type=AssetType(row[2]),
                    value=row[3]
                )
                for row in rows
            ]
        finally:
            conn.close()
