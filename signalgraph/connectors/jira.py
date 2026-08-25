"""
Jira connector for security and compliance tickets.
"""

import json
from datetime import datetime
from pathlib import Path
from typing import Optional, Dict, Any

from signalgraph.connectors.base import BaseConnector, ConnectorResult, ConnectorHealth
from signalgraph.models import Ticket, TicketStatus


class JiraConnector(BaseConnector):
    """Jira connector for issue tracking."""

    def __init__(self, name: str = "jira", config: Optional[Dict[str, Any]] = None):
        super().__init__(name, config)
        self.use_fixtures = config.get("use_fixtures", True) if config else True
        self.fixture_path = Path(config.get("fixture_path", "fixtures/jira")) if config else Path("fixtures/jira")

    async def pull(self) -> ConnectorResult:
        """Pull data from Jira."""
        if self.use_fixtures:
            return await self._pull_from_fixtures()
        else:
            raise NotImplementedError("Live Jira API integration not implemented (use fixtures)")

    async def _pull_from_fixtures(self) -> ConnectorResult:
        """Load data from fixture files."""
        issues_file = self.fixture_path / "issues.json"

        with open(issues_file) as f:
            issues_data = json.load(f)

        tickets = []
        status_map = {
            "Open": TicketStatus.OPEN,
            "In Progress": TicketStatus.IN_PROGRESS,
            "Resolved": TicketStatus.RESOLVED,
            "Closed": TicketStatus.CLOSED,
        }

        for issue in issues_data:
            fields = issue.get("fields", {})
            status_name = fields.get("status", {}).get("name", "Open")
            status = status_map.get(status_name, TicketStatus.OPEN)

            assignee_email = None
            if fields.get("assignee"):
                assignee_email = fields["assignee"].get("emailAddress")

            created_at = datetime.fromisoformat(fields["created"].replace("+0000", "+00:00").replace("Z", "+00:00"))
            updated_at = datetime.fromisoformat(fields["updated"].replace("+0000", "+00:00").replace("Z", "+00:00"))

            resolved_at = None
            if fields.get("resolutiondate"):
                resolved_at = datetime.fromisoformat(fields["resolutiondate"].replace("+0000", "+00:00").replace("Z", "+00:00"))

            age_days = (datetime.now(created_at.tzinfo) - created_at).days

            linked_control = fields.get("customfield_10100")
            sla_days = fields.get("customfield_10101")

            ticket = Ticket(
                id=self._generate_id("ticket", issue["key"]),
                source_system=self.name,
                source_id=issue["key"],
                title=fields.get("summary", ""),
                description=fields.get("description", ""),
                status=status,
                assignee_email=assignee_email,
                priority=fields.get("priority", {}).get("name"),
                labels=fields.get("labels", []),
                linked_control=linked_control,
                sla_days=sla_days,
                age_days=age_days,
                created_at=created_at,
                updated_at=updated_at,
                resolved_at=resolved_at,
                attributes={
                    "jira_key": issue["key"],
                    "jira_id": issue["id"],
                }
            )
            tickets.append(ticket)

        evidence_path = Path("evidence") / f"jira_tickets_{datetime.utcnow().isoformat()}.json"
        evidence_path.parent.mkdir(parents=True, exist_ok=True)
        with open(evidence_path, "w") as f:
            json.dump(
                {
                    "connector": self.name,
                    "pulled_at": datetime.utcnow().isoformat(),
                    "issues": issues_data,
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
            tickets=tickets,
            health=health,
            evidence_paths=[str(evidence_path)]
        )

    async def health_check(self) -> ConnectorHealth:
        """Check connector health."""
        if self.use_fixtures:
            issues_file = self.fixture_path / "issues.json"
            is_healthy = issues_file.exists()
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
