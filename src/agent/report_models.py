from pydantic import BaseModel, Field
from typing import List, Optional, Dict, Any
from enum import Enum
from datetime import datetime

class Severity(str, Enum):
    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"
    INFO = "INFO"

class Finding(BaseModel):
    title: str
    severity: Severity
    description: str
    remediation: Optional[str] = None
    evidence: Optional[List[str]] = None
    affected_assets: List[str] = Field(default_factory=list)

class KeyValue(BaseModel):
    key: str
    value: str

class Section(BaseModel):
    title: str
    content: Optional[str] = None
    key_values: List[KeyValue] = Field(default_factory=list)
    subsections: List["Section"] = Field(default_factory=list)

class ExecutiveSummary(BaseModel):
    overview: str
    risk_score: float = Field(..., ge=0, le=10)
    key_findings: List[Finding]
    recommendations: List[str]

class AssetReport(BaseModel):
    target: str
    ip_addresses: List[str] = Field(default_factory=list)
    open_ports: List[int] = Field(default_factory=list)
    tech_stack: List[str] = Field(default_factory=list)
    findings: List[Finding] = Field(default_factory=list)

class FullReport(BaseModel):
    title: str = "Pentest Report"
    date: datetime = Field(default_factory=datetime.now)
    target: str
    executive_summary: ExecutiveSummary
    assets: List[AssetReport]
    all_findings: List[Finding]
