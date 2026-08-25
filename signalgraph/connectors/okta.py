"""
Okta/IdP connector for identity and group data.
"""

import json
from datetime import datetime
from pathlib import Path
from typing import Optional, Dict, Any

from signalgraph.connectors.base import BaseConnector, ConnectorResult, ConnectorHealth
from signalgraph.models import Identity, IdentityType


class OktaConnector(BaseConnector):
    """Okta identity provider connector."""

    def __init__(self, name: str = "okta", config: Optional[Dict[str, Any]] = None):
        super().__init__(name, config)
        self.use_fixtures = config.get("use_fixtures", True) if config else True
        self.fixture_path = Path(config.get("fixture_path", "fixtures/okta")) if config else Path("fixtures/okta")

    async def pull(self) -> ConnectorResult:
        """Pull identity data from Okta."""
        if self.use_fixtures:
            return await self._pull_from_fixtures()
        else:
            raise NotImplementedError("Live Okta API integration not implemented (use fixtures)")

    async def _pull_from_fixtures(self) -> ConnectorResult:
        """Load data from fixture files."""
        users_file = self.fixture_path / "users.json"
        groups_file = self.fixture_path / "groups.json"
        memberships_file = self.fixture_path / "group_memberships.json"

        with open(users_file) as f:
            users_data = json.load(f)

        with open(groups_file) as f:
            groups_data = json.load(f)

        with open(memberships_file) as f:
            memberships_data = json.load(f)

        identities = []
        for user in users_data:
            groups = []
            for group_id, members in memberships_data.items():
                if user["id"] in members:
                    group_name = next(
                        (g["profile"]["name"] for g in groups_data if g["id"] == group_id),
                        None
                    )
                    if group_name:
                        groups.append(group_name)

            is_admin = "Admins" in groups
            last_login = None
            if user.get("lastLogin"):
                last_login = datetime.fromisoformat(user["lastLogin"].replace("Z", "+00:00"))

            deactivated_at = None
            if user.get("statusChanged") and user["status"] in ["DEPROVISIONED", "SUSPENDED"]:
                deactivated_at = datetime.fromisoformat(user["statusChanged"].replace("Z", "+00:00"))

            identity = Identity(
                id=self._generate_id("identity", user["id"]),
                identity_type=IdentityType.HUMAN,
                source_system=self.name,
                source_id=user["id"],
                email=user["profile"].get("email"),
                username=user["profile"].get("login"),
                display_name=f"{user['profile'].get('firstName', '')} {user['profile'].get('lastName', '')}".strip(),
                employee_id=user["profile"].get("employeeNumber"),
                is_active=(user["status"] == "ACTIVE"),
                is_admin=is_admin,
                has_mfa=user.get("mfaEnrolled", False),
                last_activity=last_login,
                created_at=datetime.fromisoformat(user["created"].replace("Z", "+00:00")),
                deactivated_at=deactivated_at,
                groups=groups,
                attributes={
                    "okta_status": user["status"],
                    "okta_id": user["id"],
                }
            )
            identities.append(identity)

        evidence_path = Path("evidence") / f"okta_identities_{datetime.utcnow().isoformat()}.json"
        evidence_path.parent.mkdir(parents=True, exist_ok=True)
        with open(evidence_path, "w") as f:
            json.dump(
                {
                    "connector": self.name,
                    "pulled_at": datetime.utcnow().isoformat(),
                    "users": users_data,
                    "groups": groups_data,
                    "memberships": memberships_data,
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
            health=health,
            evidence_paths=[str(evidence_path)]
        )

    async def health_check(self) -> ConnectorHealth:
        """Check connector health."""
        if self.use_fixtures:
            users_file = self.fixture_path / "users.json"
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
