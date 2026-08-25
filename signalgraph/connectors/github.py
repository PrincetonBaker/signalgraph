"""
GitHub connector for organization members and repositories.
"""

import json
from datetime import datetime
from pathlib import Path
from typing import Optional, Dict, Any

from signalgraph.connectors.base import BaseConnector, ConnectorResult, ConnectorHealth
from signalgraph.models import Identity, Asset, IdentityType, AssetType


class GitHubConnector(BaseConnector):
    """GitHub connector for org members and repositories."""

    def __init__(self, name: str = "github", config: Optional[Dict[str, Any]] = None):
        super().__init__(name, config)
        self.use_fixtures = config.get("use_fixtures", True) if config else True
        self.fixture_path = Path(config.get("fixture_path", "fixtures/github")) if config else Path("fixtures/github")

    async def pull(self) -> ConnectorResult:
        """Pull data from GitHub."""
        if self.use_fixtures:
            return await self._pull_from_fixtures()
        else:
            raise NotImplementedError("Live GitHub API integration not implemented (use fixtures)")

    async def _pull_from_fixtures(self) -> ConnectorResult:
        """Load data from fixture files."""
        members_file = self.fixture_path / "org_members.json"
        repos_file = self.fixture_path / "repositories.json"
        protection_file = self.fixture_path / "branch_protection.json"

        with open(members_file) as f:
            members_data = json.load(f)

        with open(repos_file) as f:
            repos_data = json.load(f)

        with open(protection_file) as f:
            protection_data = json.load(f)

        identities = []
        for member in members_data:
            identity = Identity(
                id=self._generate_id("identity", member["login"]),
                identity_type=IdentityType.HUMAN,
                source_system=self.name,
                source_id=member["login"],
                email=member.get("email"),
                username=member["login"],
                display_name=member["login"].replace("-", " ").title(),
                is_active=True,
                is_admin=(member.get("role") == "admin"),
                has_mfa=member.get("two_factor_authentication", False),
                roles=[member.get("role", "member")],
                attributes={
                    "github_id": member["id"],
                    "github_node_id": member["node_id"],
                }
            )
            identities.append(identity)

        assets = []
        for repo in repos_data:
            is_production = repo.get("is_production", False)
            repo_name = repo["name"]
            protection = protection_data.get(repo_name, {})
            has_protection = protection.get("protected", False)

            admin_emails = []
            for admin_login in repo.get("admin_users", []):
                admin_member = next((m for m in members_data if m["login"] == admin_login), None)
                if admin_member and admin_member.get("email"):
                    admin_emails.append(admin_member["email"])

            owner_email = admin_emails[0] if admin_emails else None

            asset = Asset(
                id=self._generate_id("asset", repo["full_name"]),
                asset_type=AssetType.REPOSITORY,
                source_system=self.name,
                source_id=repo["full_name"],
                name=repo["full_name"],
                description=f"GitHub repository: {repo['full_name']}",
                owner_email=owner_email,
                is_production=is_production,
                is_public=not repo.get("private", True),
                tags={
                    "default_branch": repo.get("default_branch", "main"),
                },
                attributes={
                    "branch_protection_enabled": has_protection,
                    "branch_protection": protection,
                    "admin_users": repo.get("admin_users", []),
                    "admin_emails": admin_emails,
                },
                created_at=datetime.fromisoformat(repo["created_at"].replace("Z", "+00:00"))
            )
            assets.append(asset)

        evidence_path = Path("evidence") / f"github_data_{datetime.utcnow().isoformat()}.json"
        evidence_path.parent.mkdir(parents=True, exist_ok=True)
        with open(evidence_path, "w") as f:
            json.dump(
                {
                    "connector": self.name,
                    "pulled_at": datetime.utcnow().isoformat(),
                    "org_members": members_data,
                    "repositories": repos_data,
                    "branch_protection": protection_data,
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
            health=health,
            evidence_paths=[str(evidence_path)]
        )

    async def health_check(self) -> ConnectorHealth:
        """Check connector health."""
        if self.use_fixtures:
            members_file = self.fixture_path / "org_members.json"
            is_healthy = members_file.exists()
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
