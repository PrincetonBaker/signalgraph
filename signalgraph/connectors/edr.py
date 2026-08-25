"""
EDR (CrowdStrike-shaped) connector for endpoint security data.
"""

import json
from datetime import datetime
from pathlib import Path
from typing import Optional, Dict, Any

from signalgraph.connectors.base import BaseConnector, ConnectorResult, ConnectorHealth
from signalgraph.models import Asset, Finding, AssetType, FindingSeverity


class EDRConnector(BaseConnector):
    """EDR connector for endpoint hosts and detections."""

    def __init__(self, name: str = "edr", config: Optional[Dict[str, Any]] = None):
        super().__init__(name, config)
        self.use_fixtures = config.get("use_fixtures", True) if config else True
        self.fixture_path = Path(config.get("fixture_path", "fixtures/edr")) if config else Path("fixtures/edr")

    async def pull(self) -> ConnectorResult:
        """Pull data from EDR."""
        if self.use_fixtures:
            return await self._pull_from_fixtures()
        else:
            raise NotImplementedError("Live EDR API integration not implemented (use fixtures)")

    async def _pull_from_fixtures(self) -> ConnectorResult:
        """Load data from fixture files."""
        hosts_file = self.fixture_path / "hosts.json"
        detections_file = self.fixture_path / "detections.json"

        with open(hosts_file) as f:
            hosts_data = json.load(f)

        with open(detections_file) as f:
            detections_data = json.load(f)

        assets = []
        for host in hosts_data:
            owner_email = host.get("owner", {}).get("email")

            is_healthy = (
                host.get("sensor_health") == "healthy" and
                host.get("status") == "normal"
            )

            asset = Asset(
                id=self._generate_id("asset", host["device_id"]),
                asset_type=AssetType.ENDPOINT,
                source_system=self.name,
                source_id=host["device_id"],
                name=host["hostname"],
                description=f"{host['platform']} endpoint: {host['hostname']}",
                owner_email=owner_email,
                is_production=False,
                is_public=False,
                is_encrypted=host.get("disk_encryption", False),
                tags={
                    "platform": host["platform"],
                    "status": host["status"],
                    "sensor_health": host["sensor_health"],
                },
                attributes={
                    "os_version": host.get("os_version"),
                    "agent_version": host.get("agent_version"),
                    "last_seen": host.get("last_seen"),
                    "local_ip": host.get("local_ip"),
                    "external_ip": host.get("external_ip"),
                    "mac_address": host.get("mac_address"),
                    "owner_employee_id": host.get("owner", {}).get("employee_id"),
                    "tags": host.get("tags", []),
                },
                created_at=datetime.fromisoformat(host["first_seen"].replace("Z", "+00:00"))
            )
            assets.append(asset)

        findings = []
        severity_map = {
            "critical": FindingSeverity.CRITICAL,
            "high": FindingSeverity.HIGH,
            "medium": FindingSeverity.MEDIUM,
            "low": FindingSeverity.LOW,
        }

        for detection in detections_data:
            severity = severity_map.get(detection.get("severity", "medium").lower(), FindingSeverity.MEDIUM)

            finding = Finding(
                id=self._generate_id("finding", detection["detection_id"]),
                source_system=self.name,
                source_id=detection["detection_id"],
                title=detection.get("detection_name", "EDR Detection"),
                description=detection.get("description", ""),
                severity=severity,
                resource_id=detection.get("hostname"),
                resource_type="endpoint",
                is_open=(detection.get("status") != "resolved"),
                first_seen=datetime.fromisoformat(detection["created_timestamp"].replace("Z", "+00:00")),
                last_seen=datetime.fromisoformat(detection["updated_timestamp"].replace("Z", "+00:00")),
                attributes={
                    "device_id": detection.get("device_id"),
                    "hostname": detection.get("hostname"),
                    "status": detection.get("status"),
                    "assigned_to": detection.get("assigned_to"),
                }
            )
            findings.append(finding)

        evidence_path = Path("evidence") / f"edr_data_{datetime.utcnow().isoformat()}.json"
        evidence_path.parent.mkdir(parents=True, exist_ok=True)
        with open(evidence_path, "w") as f:
            json.dump(
                {
                    "connector": self.name,
                    "pulled_at": datetime.utcnow().isoformat(),
                    "hosts": hosts_data,
                    "detections": detections_data,
                },
                f,
                indent=2
            )

        health = ConnectorHealth(
            connector_name=self.name,
            is_healthy=True,
            last_successful_pull=datetime.utcnow(),
        )

        return ConnectorResult(
            connector_name=self.name,
            assets=assets,
            findings=findings,
            health=health,
            evidence_paths=[str(evidence_path)]
        )

    async def health_check(self) -> ConnectorHealth:
        """Check connector health."""
        if self.use_fixtures:
            hosts_file = self.fixture_path / "hosts.json"
            is_healthy = hosts_file.exists()
            return ConnectorHealth(
                connector_name=self.name,
                is_healthy=is_healthy,
                last_error=None if is_healthy else "Fixture file not found"
            )
        else:
            return ConnectorHealth(
                connector_name=self.name,
                is_healthy=False,
                last_error="Live API not configured"
            )
