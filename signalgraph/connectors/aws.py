"""
AWS connector for IAM, S3, and security findings.
"""

import json
from datetime import datetime
from pathlib import Path
from typing import Optional, Dict, Any

from signalgraph.connectors.base import BaseConnector, ConnectorResult, ConnectorHealth
from signalgraph.models import (
    Identity,
    Asset,
    Finding,
    IdentityType,
    AssetType,
    FindingSeverity
)


class AWSConnector(BaseConnector):
    """AWS connector for IAM users, S3 buckets, and GuardDuty findings."""

    def __init__(self, name: str = "aws", config: Optional[Dict[str, Any]] = None):
        super().__init__(name, config)
        self.use_fixtures = config.get("use_fixtures", True) if config else True
        self.fixture_path = Path(config.get("fixture_path", "fixtures/aws")) if config else Path("fixtures/aws")

    async def pull(self) -> ConnectorResult:
        """Pull data from AWS."""
        if self.use_fixtures:
            return await self._pull_from_fixtures()
        else:
            raise NotImplementedError("Live AWS API integration not implemented (use fixtures)")

    async def _pull_from_fixtures(self) -> ConnectorResult:
        """Load data from fixture files."""
        users_file = self.fixture_path / "iam_users.json"
        mfa_file = self.fixture_path / "iam_mfa.json"
        buckets_file = self.fixture_path / "s3_buckets.json"
        findings_file = self.fixture_path / "guardduty_findings.json"

        with open(users_file) as f:
            users_data = json.load(f)

        with open(mfa_file) as f:
            mfa_data = json.load(f)

        with open(buckets_file) as f:
            buckets_data = json.load(f)

        with open(findings_file) as f:
            findings_data = json.load(f)

        identities = []
        for user in users_data:
            username = user["UserName"]
            has_mfa = len(mfa_data.get(username, [])) > 0

            email = None
            employee_id = None
            for tag in user.get("Tags", []):
                if tag["Key"] == "Email":
                    email = tag["Value"]
                elif tag["Key"] == "EmployeeId":
                    employee_id = tag["Value"]

            last_activity = None
            if user.get("PasswordLastUsed"):
                last_activity = datetime.fromisoformat(user["PasswordLastUsed"].replace("Z", "+00:00"))

            identity = Identity(
                id=self._generate_id("identity", user["UserId"]),
                identity_type=IdentityType.HUMAN,
                source_system=self.name,
                source_id=user["UserId"],
                email=email,
                username=username,
                display_name=username.replace(".", " ").title(),
                employee_id=employee_id,
                is_active=True,
                is_admin=False,
                has_mfa=has_mfa,
                last_activity=last_activity,
                created_at=datetime.fromisoformat(user["CreateDate"].replace("Z", "+00:00")),
                attributes={
                    "aws_arn": user["Arn"],
                    "aws_user_id": user["UserId"],
                }
            )
            identities.append(identity)

        assets = []
        for bucket in buckets_data:
            owner_email = None
            is_production = False
            for tag in bucket.get("Tags", []):
                if tag["Key"] == "Owner":
                    owner_email = tag["Value"]
                elif tag["Key"] == "Environment" and tag["Value"] == "production":
                    is_production = True

            asset = Asset(
                id=self._generate_id("asset", bucket["Name"]),
                asset_type=AssetType.STORAGE,
                source_system=self.name,
                source_id=bucket["Name"],
                name=bucket["Name"],
                description=f"S3 bucket in {bucket.get('Region', 'unknown')}",
                owner_email=owner_email,
                is_production=is_production,
                is_public=bucket.get("Public", False),
                is_encrypted=bucket.get("Encryption", {}).get("Enabled", False),
                tags={tag["Key"]: tag["Value"] for tag in bucket.get("Tags", [])},
                attributes={
                    "region": bucket.get("Region"),
                    "versioning": bucket.get("Versioning", False),
                    "encryption_algorithm": bucket.get("Encryption", {}).get("Algorithm"),
                },
                created_at=datetime.fromisoformat(bucket["CreationDate"].replace("Z", "+00:00"))
            )
            assets.append(asset)

        findings = []
        severity_map = {
            (8.0, 10.0): FindingSeverity.CRITICAL,
            (7.0, 8.0): FindingSeverity.HIGH,
            (4.0, 7.0): FindingSeverity.MEDIUM,
            (1.0, 4.0): FindingSeverity.LOW,
            (0.0, 1.0): FindingSeverity.INFO,
        }

        for finding_data in findings_data:
            severity_score = finding_data.get("Severity", 0.0)
            severity = FindingSeverity.INFO
            for (low, high), sev in severity_map.items():
                if low <= severity_score < high:
                    severity = sev
                    break

            resource_id = None
            if finding_data.get("Resource", {}).get("AccessKeyDetails"):
                resource_id = finding_data["Resource"]["AccessKeyDetails"].get("UserName")

            finding = Finding(
                id=self._generate_id("finding", finding_data["Id"]),
                source_system=self.name,
                source_id=finding_data["Id"],
                title=finding_data.get("Title", finding_data["Type"]),
                description=finding_data.get("Description", ""),
                severity=severity,
                resource_id=resource_id,
                resource_type=finding_data.get("Resource", {}).get("ResourceType"),
                is_open=not finding_data.get("Service", {}).get("Archived", False),
                first_seen=datetime.fromisoformat(finding_data["CreatedAt"].replace("Z", "+00:00")),
                last_seen=datetime.fromisoformat(finding_data["UpdatedAt"].replace("Z", "+00:00")),
                attributes={
                    "aws_account_id": finding_data.get("AccountId"),
                    "aws_region": finding_data.get("Region"),
                    "finding_type": finding_data["Type"],
                }
            )
            findings.append(finding)

        evidence_path = Path("evidence") / f"aws_data_{datetime.utcnow().isoformat()}.json"
        evidence_path.parent.mkdir(parents=True, exist_ok=True)
        with open(evidence_path, "w") as f:
            json.dump(
                {
                    "connector": self.name,
                    "pulled_at": datetime.utcnow().isoformat(),
                    "iam_users": users_data,
                    "iam_mfa": mfa_data,
                    "s3_buckets": buckets_data,
                    "guardduty_findings": findings_data,
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
            identities=identities,
            assets=assets,
            findings=findings,
            health=health,
            evidence_paths=[str(evidence_path)]
        )

    async def health_check(self) -> ConnectorHealth:
        """Check connector health."""
        if self.use_fixtures:
            users_file = self.fixture_path / "iam_users.json"
            is_healthy = users_file.exists()
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
