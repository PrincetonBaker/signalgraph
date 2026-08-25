"""
Canonical data models for the SignalGraph platform.
All connector data is normalized into these types.
"""

from datetime import datetime
from enum import Enum
from typing import Optional, Dict, Any, List
from pydantic import BaseModel, Field, ConfigDict


class IdentityType(str, Enum):
    HUMAN = "human"
    SERVICE = "service"
    SYSTEM = "system"


class AssetType(str, Enum):
    CLOUD_ACCOUNT = "cloud_account"
    STORAGE = "storage"
    COMPUTE = "compute"
    ENDPOINT = "endpoint"
    REPOSITORY = "repository"
    APPLICATION = "application"


class FindingSeverity(str, Enum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


class TicketStatus(str, Enum):
    OPEN = "open"
    IN_PROGRESS = "in_progress"
    RESOLVED = "resolved"
    CLOSED = "closed"


class ControlStatus(str, Enum):
    PASS = "pass"
    FAIL = "fail"
    EXCEPTION = "exception"
    NOT_EVALUATED = "not_evaluated"


class Framework(str, Enum):
    SOC2 = "soc2"
    ISO27001 = "iso27001"
    PCI = "pci"
    HIPAA = "hipaa"


class Identity(BaseModel):
    """
    Canonical identity record. May represent a person across multiple systems
    or a service/system identity.
    """

    model_config = ConfigDict(extra="allow")

    id: str = Field(..., description="Global unique ID for this identity")
    identity_type: IdentityType
    source_system: str = Field(..., description="e.g. 'okta', 'aws', 'github'")
    source_id: str = Field(..., description="ID in the source system")
    email: Optional[str] = None
    username: Optional[str] = None
    display_name: Optional[str] = None
    employee_id: Optional[str] = None
    is_active: bool = True
    is_admin: bool = False
    has_mfa: bool = False
    last_activity: Optional[datetime] = None
    created_at: Optional[datetime] = None
    deactivated_at: Optional[datetime] = None
    groups: List[str] = Field(default_factory=list)
    roles: List[str] = Field(default_factory=list)
    attributes: Dict[str, Any] = Field(default_factory=dict)
    ingested_at: datetime = Field(default_factory=datetime.utcnow)


class Asset(BaseModel):
    """
    Canonical asset record (cloud resources, endpoints, repositories, etc.).
    """

    model_config = ConfigDict(extra="allow")

    id: str = Field(..., description="Global unique ID for this asset")
    asset_type: AssetType
    source_system: str
    source_id: str
    name: str
    description: Optional[str] = None
    owner_email: Optional[str] = None
    owner_identity_id: Optional[str] = None
    is_production: bool = False
    is_public: bool = False
    is_encrypted: bool = False
    tags: Dict[str, str] = Field(default_factory=dict)
    attributes: Dict[str, Any] = Field(default_factory=dict)
    created_at: Optional[datetime] = None
    ingested_at: datetime = Field(default_factory=datetime.utcnow)


class Finding(BaseModel):
    """
    Security/compliance finding from any source.
    """

    model_config = ConfigDict(extra="allow")

    id: str
    source_system: str
    source_id: str
    title: str
    description: Optional[str] = None
    severity: FindingSeverity
    resource_id: Optional[str] = None
    resource_type: Optional[str] = None
    affected_identity_id: Optional[str] = None
    affected_asset_id: Optional[str] = None
    remediation: Optional[str] = None
    is_open: bool = True
    first_seen: datetime
    last_seen: datetime
    resolved_at: Optional[datetime] = None
    attributes: Dict[str, Any] = Field(default_factory=dict)
    ingested_at: datetime = Field(default_factory=datetime.utcnow)


class Ticket(BaseModel):
    """
    Remediation ticket from issue tracker.
    """

    model_config = ConfigDict(extra="allow")

    id: str
    source_system: str
    source_id: str
    title: str
    description: Optional[str] = None
    status: TicketStatus
    assignee_email: Optional[str] = None
    assignee_identity_id: Optional[str] = None
    priority: Optional[str] = None
    labels: List[str] = Field(default_factory=list)
    linked_control: Optional[str] = None
    linked_asset: Optional[str] = None
    linked_finding: Optional[str] = None
    sla_days: Optional[int] = None
    age_days: Optional[int] = None
    created_at: datetime
    updated_at: datetime
    resolved_at: Optional[datetime] = None
    attributes: Dict[str, Any] = Field(default_factory=dict)
    ingested_at: datetime = Field(default_factory=datetime.utcnow)


class Evidence(BaseModel):
    """
    Evidence artifact for audit/compliance.
    """

    model_config = ConfigDict(extra="allow")

    id: str
    control_id: Optional[str] = None
    source_system: str
    artifact_type: str
    artifact_path: str
    description: Optional[str] = None
    collected_at: datetime
    attributes: Dict[str, Any] = Field(default_factory=dict)


class Control(BaseModel):
    """
    GRC control definition with mappings to frameworks.
    """

    model_config = ConfigDict(extra="allow")

    id: str = Field(..., description="Control ID like MFA-001")
    title: str
    description: str
    frameworks: Dict[str, List[str]] = Field(
        default_factory=dict, 
        description="Framework mappings like {'soc2': ['CC6.1'], 'iso27001': ['A.9.4.2'], 'pci': ['8.3.1']}"
    )
    severity: str = Field(default="medium", description="critical, high, medium, low")
    query_type: str = Field(..., description="Type of evaluation: identity_graph, asset, finding, etc.")
    query_params: Dict[str, Any] = Field(default_factory=dict)
    rationale: Optional[str] = None
    
    def applies_to_framework(self, framework: str) -> bool:
        """Check if this control applies to a given framework."""
        return framework.lower() in self.frameworks


class ControlResult(BaseModel):
    """
    Result of evaluating a control.
    """

    model_config = ConfigDict(extra="allow")

    control_id: str
    status: ControlStatus
    evaluated_at: datetime = Field(default_factory=datetime.utcnow)
    passed_count: int = 0
    failed_count: int = 0
    exception_count: int = 0
    failure_details: List[Dict[str, Any]] = Field(default_factory=list)
    evidence_ids: List[str] = Field(default_factory=list)
    message: Optional[str] = None
