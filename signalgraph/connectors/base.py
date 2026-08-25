"""
Base connector interface for all source system integrations.
"""

from abc import ABC, abstractmethod
from datetime import datetime
from typing import List, Dict, Any, Optional
from pydantic import BaseModel, Field

from signalgraph.models import Identity, Asset, Finding, Ticket


class ConnectorHealth(BaseModel):
    """Health status of a connector."""

    connector_name: str
    is_healthy: bool
    last_successful_pull: Optional[datetime] = None
    last_error: Optional[str] = None
    watermark: Optional[str] = None
    checked_at: datetime = Field(default_factory=datetime.utcnow)


class ConnectorResult(BaseModel):
    """Result of a connector pull operation."""

    connector_name: str
    identities: List[Identity] = Field(default_factory=list)
    assets: List[Asset] = Field(default_factory=list)
    findings: List[Finding] = Field(default_factory=list)
    tickets: List[Ticket] = Field(default_factory=list)
    health: ConnectorHealth
    evidence_paths: List[str] = Field(
        default_factory=list, description="Paths to JSON evidence artifacts"
    )
    pulled_at: datetime = Field(default_factory=datetime.utcnow)


class BaseConnector(ABC):
    """
    Base class for all connectors.
    
    Each connector must implement:
    - pull(): Fetch data from source and return canonical records
    - health_check(): Return current health status
    """

    def __init__(self, name: str, config: Optional[Dict[str, Any]] = None):
        self.name = name
        self.config = config or {}

    @abstractmethod
    async def pull(self) -> ConnectorResult:
        """
        Pull data from the source system and normalize to canonical models.
        Must generate evidence artifacts (JSON) for audit trails.
        """
        pass

    @abstractmethod
    async def health_check(self) -> ConnectorHealth:
        """Check if the connector is healthy and can communicate with source."""
        pass

    def _generate_id(self, prefix: str, source_id: str) -> str:
        """Generate a globally unique ID for a canonical record."""
        return f"{self.name}:{prefix}:{source_id}"
