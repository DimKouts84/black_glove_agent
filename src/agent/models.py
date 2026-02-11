"""
Pydantic models for Black Glove pentest agent.
Provides data validation and configuration management.
"""
from pydantic import BaseModel, Field
from typing import Optional, Dict, Any, List
from enum import Enum
from dataclasses import dataclass, asdict
from datetime import datetime
from pathlib import Path
import yaml

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
    INFO = "info"

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
    llm_api_key: Optional[str] = Field(default=None, description="LLM Provider API Key")
    llm_timeout: int = Field(default=240, ge=30, description="LLM request timeout in seconds")
    llm_retry_attempts: int = Field(default=5, ge=0, description="Number of retry attempts for LLM requests")
    llm_retry_backoff_factor: float = Field(default=2.0, ge=0.0, description="Exponential backoff factor for retries")

    
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
    
    # Asset management settings
    authorized_networks: List[str] = Field(
        default=["192.168.0.0/16", "10.0.0.0/8", "172.16.0.0/12"],
        description="Authorized IP networks for scanning"
    )
    authorized_domains: List[str] = Field(
        default=[],
        description="Authorized domains for scanning"
    )
    blocked_targets: List[str] = Field(
        default=[],
        description="Explicitly blocked targets"
    )
    
    # Additional settings
    extra_settings: Optional[Dict[str, Any]] = Field(default=None, description="Additional configuration settings")

@dataclass
class Asset:
    """
    Simple asset class for policy engine usage.
    
    Attributes:
        target: Target IP address, domain, or identifier
        tool_name: Name of the tool/adapter to use
        parameters: Tool execution parameters
    """
    target: str
    tool_name: str
    parameters: Dict[str, Any]
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert asset to dictionary."""
        return asdict(self)

@dataclass
class WorkflowStep:
    """
    Represents a single step in the reconnaissance workflow.

    This dataclass is compatible with Planner and other agents. Fields:
      - tool: Tool/adapter to use
      - target: Target for the scan
      - parameters: Tool execution parameters
      - priority: Step priority (lower numbers run earlier)
      - rationale: Explanation or reasoning for the step (used by Planner)
      - name / description: Optional display fields for UI or ordering
    """
    tool: str
    target: str
    parameters: Dict[str, Any]
    priority: int = 0
    rationale: str = ""
    name: Optional[str] = None
    description: Optional[str] = None

@dataclass
class ScanPlan:
    """
    Represents a scan plan produced by the PlannerAgent.
    """
    goal: str
    created_at: str
    steps: List[WorkflowStep]

@dataclass
class ScanResult:
    """
    Represents the result of a scan operation.
    
    Attributes:
        asset: Asset that was scanned
        tool_name: Name of the tool used
        status: Scan status (completed, failed, timeout)
        findings: Security findings identified
        raw_output: Raw tool output
        metadata: Additional result metadata
        evidence_path: Path to stored evidence
        execution_time: Time taken to execute
        error_message: Error details if applicable
    """
    asset: Asset
    tool_name: str
    status: str
    findings: List[Dict[str, Any]]
    raw_output: Any
    metadata: Dict[str, Any]
    evidence_path: Optional[str] = None
    execution_time: Optional[float] = None
    error_message: Optional[str] = None
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert scan result to dictionary."""
        return {
            "asset": self.asset.to_dict(),
            "tool_name": self.tool_name,
            "status": self.status,
            "findings": self.findings,
            "raw_output": self.raw_output,
            "metadata": self.metadata,
            "evidence_path": self.evidence_path,
            "execution_time": self.execution_time,
            "error_message": self.error_message
        }

@dataclass
class OrchestrationContext:
    """
    Contains orchestration context for workflow execution.
    
    Attributes:
        assets: List of assets to scan
        current_workflow_state: Current workflow state
        llm_client: LLM client instance
        database_connection: Database connection
        configuration: Agent configuration
    """
    assets: List[Asset]
    current_workflow_state: str
    llm_client: Any  # LLM client instance
    database_connection: Any  # Database connection
    configuration: Dict[str, Any]

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
    
    def get_asset_by_name(self, name: str) -> Optional[AssetModel]:
        """
        Retrieve an asset from the database by name.
        
        Args:
            name: Name of the asset to retrieve
            
        Returns:
            AssetModel: Asset model instance, or None if not found
        """
        conn = self.get_db_connection()
        try:
            cursor = conn.cursor()
            cursor.execute(
                "SELECT id, name, type, value FROM assets WHERE name = ?",
                (name,)
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
    
    def remove_asset(self, asset_id: int) -> bool:
        """
        Remove an asset from the database by ID.
        
        Args:
            asset_id: ID of the asset to remove
            
        Returns:
            bool: True if asset was removed, False if not found
        """
        from .db import remove_asset
        conn = self.get_db_connection()
        try:
            return remove_asset(conn, asset_id)
        finally:
            conn.close()


def load_config_from_file() -> ConfigModel:
    """
    Load configuration from YAML file with error handling.
    
    Returns:
        ConfigModel: Loaded configuration
    """
    import logging
    from dotenv import load_dotenv
    
    # Load environment variables from .env file
    load_dotenv()
    
    logger = logging.getLogger("black_glove.config")
    
    # Check current directory first, then home directory
    config_path = Path.cwd() / "config.yaml"
    if not config_path.exists():
        config_path = Path.home() / ".homepentest" / "config.yaml"
    
    if not config_path.exists():
        logger.warning(f"Configuration file not found at {config_path}, using defaults")
        return ConfigModel()
    
    try:
        with open(config_path, 'r') as f:
            config_data = yaml.safe_load(f)
        
        if not isinstance(config_data, dict):
            logger.warning("Invalid configuration file format, using defaults")
            return ConfigModel()
        
        # Create ConfigModel instance with loaded data
        # Environment variables will override file config if set (pydantic behavior if using BaseSettings, 
        # but here we are using BaseModel, so we might need manual handling if we want env vars to take precedence.
        # For now, we'll assume config file is primary, but we can populate missing keys from env if needed.)
        
        config = ConfigModel(**config_data)
        logger.info("Configuration loaded successfully from file")
        return config
        
    except Exception as e:
        logger.error(f"Failed to load configuration from {config_path}: {e}")
        logger.info("Using default configuration")
        return ConfigModel()
