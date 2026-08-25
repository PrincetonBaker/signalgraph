"""
Connector registry for plugin-style connector management.
"""

from typing import Dict, Type, List, Optional
from signalgraph.connectors.base import BaseConnector


class ConnectorRegistry:
    """Registry for managing available connectors."""

    _connectors: Dict[str, Type[BaseConnector]] = {}

    @classmethod
    def register(cls, name: str, connector_class: Type[BaseConnector]):
        """Register a connector class."""
        cls._connectors[name] = connector_class

    @classmethod
    def get(cls, name: str) -> Optional[Type[BaseConnector]]:
        """Get a connector class by name."""
        return cls._connectors.get(name)

    @classmethod
    def list(cls) -> List[str]:
        """List all registered connector names."""
        return list(cls._connectors.keys())

    @classmethod
    def create(cls, name: str, config: Optional[dict] = None) -> BaseConnector:
        """Create a connector instance."""
        connector_class = cls.get(name)
        if not connector_class:
            raise ValueError(f"Connector '{name}' not found in registry")
        return connector_class(name=name, config=config)
