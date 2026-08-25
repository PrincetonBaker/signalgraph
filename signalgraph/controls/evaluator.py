"""
Control evaluation engine with graph queries.
"""

import json
from datetime import datetime, timedelta
from typing import List, Dict, Any, Optional
from pathlib import Path

from signalgraph.models import Control, ControlResult, ControlStatus, FindingSeverity
from signalgraph.storage.database import Database
from signalgraph.correlation.engine import CorrelationEngine


class ControlEvaluator:
    """
    Evaluates controls against correlated data.
    """

    def __init__(self, db: Database, exceptions_path: Optional[str] = None):
        self.db = db
        self.correlation_engine = CorrelationEngine(db)
        self.exceptions = self._load_exceptions(exceptions_path) if exceptions_path else {}

    def _load_exceptions(self, path: str) -> Dict[str, Any]:
        """Load risk acceptance exceptions."""
        try:
            with open(path) as f:
                return json.load(f)
        except FileNotFoundError:
            return {}

    def evaluate(self, control: Control) -> ControlResult:
        """Evaluate a single control."""
        method_name = f"_evaluate_{control.query_type}"
        if hasattr(self, method_name):
            method = getattr(self, method_name)
            return method(control)
        else:
            return ControlResult(
                control_id=control.id,
                status=ControlStatus.NOT_EVALUATED,
                message=f"No evaluator for query_type: {control.query_type}"
            )

    def _check_exception(self, control_id: str, entity_id: str) -> bool:
        """Check if an entity is excepted for a control."""
        exceptions = self.exceptions.get(control_id, [])
        for exc in exceptions:
            if exc.get("entity_id") == entity_id:
                expiry = exc.get("expiry")
                if expiry:
                    try:
                        expiry_dt = datetime.fromisoformat(expiry)
                        if datetime.utcnow() > expiry_dt:
                            return False
                    except:
                        return False
                return True
        return False

    def _evaluate_identity_mfa_admin(self, control: Control) -> ControlResult:
        """Admins must have MFA everywhere."""
        correlated = self.correlation_engine.correlate_identities()
        
        failures = []
        passed = 0
        excepted = 0
        
        for identity in correlated:
            if not identity.is_admin_in_any:
                continue
            
            if not identity.has_mfa_everywhere and identity.mfa_gaps:
                if self._check_exception(control.id, identity.correlated_id):
                    excepted += 1
                else:
                    failures.append({
                        "identity": identity.email or identity.correlated_id,
                        "systems_without_mfa": identity.mfa_gaps,
                        "reason": f"Admin user missing MFA in: {', '.join(identity.mfa_gaps)}"
                    })
            else:
                passed += 1
        
        status = ControlStatus.PASS if len(failures) == 0 else ControlStatus.FAIL
        if excepted > 0 and len(failures) == 0:
            status = ControlStatus.EXCEPTION
        
        return ControlResult(
            control_id=control.id,
            status=status,
            passed_count=passed,
            failed_count=len(failures),
            exception_count=excepted,
            failure_details=failures
        )

    def _evaluate_identity_mfa_all(self, control: Control) -> ControlResult:
        """All active users should have MFA in Okta."""
        identities = self.db.get_all_identities()
        okta_users = [i for i in identities if i["source_system"] == "okta"]
        
        failures = []
        passed = 0
        excepted = 0
        
        for user in okta_users:
            if not user.get("is_active"):
                continue
            
            if not user.get("has_mfa"):
                if self._check_exception(control.id, user["id"]):
                    excepted += 1
                else:
                    failures.append({
                        "identity": user.get("email") or user.get("username"),
                        "reason": "Active Okta user without MFA enabled"
                    })
            else:
                passed += 1
        
        status = ControlStatus.PASS if len(failures) == 0 else ControlStatus.FAIL
        if excepted > 0 and len(failures) == 0:
            status = ControlStatus.EXCEPTION
        
        return ControlResult(
            control_id=control.id,
            status=status,
            passed_count=passed,
            failed_count=len(failures),
            exception_count=excepted,
            failure_details=failures
        )

    def _evaluate_jml_leaver(self, control: Control) -> ControlResult:
        """Terminated employees must not have active access."""
        jml_issues = self.correlation_engine.detect_jml_issues()
        leaver_issues = [i for i in jml_issues if "leaver" in i.issue_type]
        
        failures = []
        excepted = 0
        
        for issue in leaver_issues:
            if self._check_exception(control.id, issue.correlated_id):
                excepted += 1
            else:
                failures.append({
                    "identity": issue.email or issue.correlated_id,
                    "reason": issue.description,
                    "systems": issue.affected_systems,
                    "severity": issue.severity
                })
        
        passed = 1 if len(failures) == 0 and excepted == 0 else 0
        status = ControlStatus.PASS if len(failures) == 0 else ControlStatus.FAIL
        if excepted > 0 and len(failures) == 0:
            status = ControlStatus.EXCEPTION
        
        return ControlResult(
            control_id=control.id,
            status=status,
            passed_count=passed,
            failed_count=len(failures),
            exception_count=excepted,
            failure_details=failures
        )

    def _evaluate_jml_dormant(self, control: Control) -> ControlResult:
        """Dormant accounts should not have recent activity."""
        jml_issues = self.correlation_engine.detect_jml_issues()
        dormant_issues = [i for i in jml_issues if "dormant" in i.issue_type]
        
        failures = []
        excepted = 0
        
        for issue in dormant_issues:
            if self._check_exception(control.id, issue.correlated_id):
                excepted += 1
            else:
                failures.append({
                    "identity": issue.email or issue.correlated_id,
                    "reason": issue.description,
                    "systems": issue.affected_systems
                })
        
        passed = 1 if len(failures) == 0 and excepted == 0 else 0
        status = ControlStatus.PASS if len(failures) == 0 else ControlStatus.FAIL
        if excepted > 0 and len(failures) == 0:
            status = ControlStatus.EXCEPTION
        
        return ControlResult(
            control_id=control.id,
            status=status,
            passed_count=passed,
            failed_count=len(failures),
            exception_count=excepted,
            failure_details=failures
        )

    def _evaluate_orphan_identity(self, control: Control) -> ControlResult:
        """Orphan identities should not exist."""
        orphans = self.correlation_engine.detect_orphans()
        
        failures = []
        excepted = 0
        
        for orphan in orphans:
            if self._check_exception(control.id, orphan.identity_id):
                excepted += 1
            else:
                failures.append({
                    "identity": orphan.email or orphan.username or orphan.identity_id,
                    "system": orphan.source_system,
                    "is_admin": orphan.is_admin,
                    "reason": orphan.reason
                })
        
        passed = 1 if len(failures) == 0 and excepted == 0 else 0
        status = ControlStatus.PASS if len(failures) == 0 else ControlStatus.FAIL
        if excepted > 0 and len(failures) == 0:
            status = ControlStatus.EXCEPTION
        
        return ControlResult(
            control_id=control.id,
            status=status,
            passed_count=passed,
            failed_count=len(failures),
            exception_count=excepted,
            failure_details=failures
        )

    def _evaluate_asset_encryption(self, control: Control) -> ControlResult:
        """Production storage must be encrypted."""
        assets = self.db.get_all_assets()
        params = control.query_params
        
        asset_type = params.get("asset_type")
        is_production = params.get("is_production")
        
        relevant_assets = [
            a for a in assets
            if (not asset_type or a["asset_type"] == asset_type) and
               (is_production is None or a["is_production"] == is_production)
        ]
        
        failures = []
        passed = 0
        excepted = 0
        
        for asset in relevant_assets:
            if not asset.get("is_encrypted"):
                if self._check_exception(control.id, asset["id"]):
                    excepted += 1
                else:
                    failures.append({
                        "asset": asset["name"],
                        "type": asset["asset_type"],
                        "owner": asset.get("owner_email"),
                        "reason": "Encryption not enabled"
                    })
            else:
                passed += 1
        
        status = ControlStatus.PASS if len(failures) == 0 else ControlStatus.FAIL
        if excepted > 0 and len(failures) == 0:
            status = ControlStatus.EXCEPTION
        
        return ControlResult(
            control_id=control.id,
            status=status,
            passed_count=passed,
            failed_count=len(failures),
            exception_count=excepted,
            failure_details=failures
        )

    def _evaluate_asset_public(self, control: Control) -> ControlResult:
        """Production assets should not be public."""
        assets = self.db.get_all_assets()
        params = control.query_params
        
        is_production = params.get("is_production")
        
        relevant_assets = [
            a for a in assets
            if (is_production is None or a["is_production"] == is_production)
        ]
        
        failures = []
        passed = 0
        excepted = 0
        
        for asset in relevant_assets:
            if asset.get("is_public"):
                if self._check_exception(control.id, asset["id"]):
                    excepted += 1
                else:
                    failures.append({
                        "asset": asset["name"],
                        "type": asset["asset_type"],
                        "owner": asset.get("owner_email"),
                        "reason": "Asset is publicly accessible"
                    })
            else:
                passed += 1
        
        status = ControlStatus.PASS if len(failures) == 0 else ControlStatus.FAIL
        if excepted > 0 and len(failures) == 0:
            status = ControlStatus.EXCEPTION
        
        return ControlResult(
            control_id=control.id,
            status=status,
            passed_count=passed,
            failed_count=len(failures),
            exception_count=excepted,
            failure_details=failures
        )

    def _evaluate_repo_branch_protection(self, control: Control) -> ControlResult:
        """Production repos must have branch protection."""
        assets = self.db.get_all_assets()
        repos = [a for a in assets if a["asset_type"] == "repository"]
        
        failures = []
        passed = 0
        excepted = 0
        
        for repo in repos:
            attrs = json.loads(repo.get("attributes", "{}"))
            is_production = repo.get("is_production")
            has_protection = attrs.get("branch_protection_enabled", False)
            
            if is_production and not has_protection:
                if self._check_exception(control.id, repo["id"]):
                    excepted += 1
                else:
                    failures.append({
                        "repository": repo["name"],
                        "owner": repo.get("owner_email"),
                        "reason": "Production repository lacks branch protection"
                    })
            elif is_production and has_protection:
                passed += 1
        
        status = ControlStatus.PASS if len(failures) == 0 else ControlStatus.FAIL
        if excepted > 0 and len(failures) == 0:
            status = ControlStatus.EXCEPTION
        
        return ControlResult(
            control_id=control.id,
            status=status,
            passed_count=passed,
            failed_count=len(failures),
            exception_count=excepted,
            failure_details=failures
        )

    def _evaluate_repo_admin_correlation(self, control: Control) -> ControlResult:
        """Repo admins must be active Okta users."""
        assets = self.db.get_all_assets()
        repos = [a for a in assets if a["asset_type"] == "repository"]
        
        identities = self.db.get_all_identities()
        okta_active_emails = {
            i["email"].lower() for i in identities
            if i["source_system"] == "okta" and i.get("is_active") and i.get("email")
        }
        
        failures = []
        passed = 0
        excepted = 0
        
        for repo in repos:
            attrs = json.loads(repo.get("attributes", "{}"))
            admin_emails = attrs.get("admin_emails", [])
            
            for email in admin_emails:
                if email.lower() not in okta_active_emails:
                    if self._check_exception(control.id, f"{repo['id']}:{email}"):
                        excepted += 1
                    else:
                        failures.append({
                            "repository": repo["name"],
                            "admin_email": email,
                            "reason": "Repository admin not found as active Okta user"
                        })
                else:
                    passed += 1
        
        status = ControlStatus.PASS if len(failures) == 0 else ControlStatus.FAIL
        if excepted > 0 and len(failures) == 0:
            status = ControlStatus.EXCEPTION
        
        return ControlResult(
            control_id=control.id,
            status=status,
            passed_count=passed,
            failed_count=len(failures),
            exception_count=excepted,
            failure_details=failures
        )

    def _evaluate_endpoint_encryption(self, control: Control) -> ControlResult:
        """Endpoints must have disk encryption."""
        assets = self.db.get_all_assets()
        endpoints = [a for a in assets if a["asset_type"] == "endpoint"]
        
        failures = []
        passed = 0
        excepted = 0
        
        for endpoint in endpoints:
            if not endpoint.get("is_encrypted"):
                if self._check_exception(control.id, endpoint["id"]):
                    excepted += 1
                else:
                    failures.append({
                        "endpoint": endpoint["name"],
                        "owner": endpoint.get("owner_email"),
                        "reason": "Disk encryption not enabled"
                    })
            else:
                passed += 1
        
        status = ControlStatus.PASS if len(failures) == 0 else ControlStatus.FAIL
        if excepted > 0 and len(failures) == 0:
            status = ControlStatus.EXCEPTION
        
        return ControlResult(
            control_id=control.id,
            status=status,
            passed_count=passed,
            failed_count=len(failures),
            exception_count=excepted,
            failure_details=failures
        )

    def _evaluate_endpoint_sensor_health(self, control: Control) -> ControlResult:
        """Endpoints must have healthy EDR sensors."""
        assets = self.db.get_all_assets()
        endpoints = [a for a in assets if a["asset_type"] == "endpoint"]
        
        failures = []
        passed = 0
        excepted = 0
        
        for endpoint in endpoints:
            tags = json.loads(endpoint.get("tags", "{}"))
            sensor_health = tags.get("sensor_health")
            status_tag = tags.get("status")
            
            if sensor_health != "healthy" or status_tag not in ["normal"]:
                if self._check_exception(control.id, endpoint["id"]):
                    excepted += 1
                else:
                    failures.append({
                        "endpoint": endpoint["name"],
                        "owner": endpoint.get("owner_email"),
                        "sensor_health": sensor_health,
                        "status": status_tag,
                        "reason": f"Sensor unhealthy: {sensor_health}, status: {status_tag}"
                    })
            else:
                passed += 1
        
        status = ControlStatus.PASS if len(failures) == 0 else ControlStatus.FAIL
        if excepted > 0 and len(failures) == 0:
            status = ControlStatus.EXCEPTION
        
        return ControlResult(
            control_id=control.id,
            status=status,
            passed_count=passed,
            failed_count=len(failures),
            exception_count=excepted,
            failure_details=failures
        )

    def _evaluate_finding_has_ticket(self, control: Control) -> ControlResult:
        """Critical findings must have tickets."""
        findings = self.db.get_all_findings()
        tickets = self.db.get_all_tickets()
        
        params = control.query_params
        severity_filter = params.get("severity")
        
        relevant_findings = [
            f for f in findings
            if f.get("is_open") and
               (not severity_filter or f.get("severity") == severity_filter)
        ]
        
        failures = []
        passed = 0
        excepted = 0
        
        for finding in relevant_findings:
            has_ticket = any(
                t.get("linked_finding") == finding["id"] or
                finding["title"].lower() in t.get("title", "").lower()
                for t in tickets
            )
            
            if not has_ticket:
                if self._check_exception(control.id, finding["id"]):
                    excepted += 1
                else:
                    failures.append({
                        "finding": finding["title"],
                        "severity": finding["severity"],
                        "system": finding["source_system"],
                        "reason": "No corresponding ticket found"
                    })
            else:
                passed += 1
        
        status = ControlStatus.PASS if len(failures) == 0 else ControlStatus.FAIL
        if excepted > 0 and len(failures) == 0:
            status = ControlStatus.EXCEPTION
        
        return ControlResult(
            control_id=control.id,
            status=status,
            passed_count=passed,
            failed_count=len(failures),
            exception_count=excepted,
            failure_details=failures
        )

    def _evaluate_finding_sla(self, control: Control) -> ControlResult:
        """High/critical findings must be resolved within SLA."""
        tickets = self.db.get_all_tickets()
        
        failures = []
        passed = 0
        excepted = 0
        
        for ticket in tickets:
            priority = ticket.get("priority", "").lower()
            age_days = ticket.get("age_days", 0)
            status = ticket.get("status")
            
            sla_exceeded = False
            if priority == "critical" and age_days > 7 and status in ["open", "in_progress"]:
                sla_exceeded = True
            elif priority == "high" and age_days > 30 and status in ["open", "in_progress"]:
                sla_exceeded = True
            
            if sla_exceeded:
                if self._check_exception(control.id, ticket["id"]):
                    excepted += 1
                else:
                    failures.append({
                        "ticket": ticket["source_id"],
                        "title": ticket["title"],
                        "priority": priority,
                        "age_days": age_days,
                        "reason": f"SLA exceeded: {priority} issue open for {age_days} days"
                    })
            elif priority in ["critical", "high"]:
                passed += 1
        
        status = ControlStatus.PASS if len(failures) == 0 else ControlStatus.FAIL
        if excepted > 0 and len(failures) == 0:
            status = ControlStatus.EXCEPTION
        
        return ControlResult(
            control_id=control.id,
            status=status,
            passed_count=passed,
            failed_count=len(failures),
            exception_count=excepted,
            failure_details=failures
        )

    def _evaluate_guardduty_ticket(self, control: Control) -> ControlResult:
        """GuardDuty findings >= 7.0 must have tickets."""
        findings = self.db.get_all_findings()
        tickets = self.db.get_all_tickets()
        
        guardduty_findings = [
            f for f in findings
            if f["source_system"] == "aws" and f.get("is_open")
        ]
        
        failures = []
        passed = 0
        excepted = 0
        
        for finding in guardduty_findings:
            if finding["severity"] in ["high", "critical"]:
                has_ticket = any(
                    "guardduty" in t.get("title", "").lower() or
                    finding.get("resource_id", "").lower() in t.get("description", "").lower()
                    for t in tickets
                )
                
                if not has_ticket:
                    if self._check_exception(control.id, finding["id"]):
                        excepted += 1
                    else:
                        failures.append({
                            "finding": finding["title"],
                            "severity": finding["severity"],
                            "reason": "High-severity GuardDuty finding without ticket"
                        })
                else:
                    passed += 1
        
        status = ControlStatus.PASS if len(failures) == 0 else ControlStatus.FAIL
        if excepted > 0 and len(failures) == 0:
            status = ControlStatus.EXCEPTION
        
        return ControlResult(
            control_id=control.id,
            status=status,
            passed_count=passed,
            failed_count=len(failures),
            exception_count=excepted,
            failure_details=failures
        )

    def _evaluate_admin_group_review(self, control: Control) -> ControlResult:
        """Admin group membership review."""
        identities = self.db.get_all_identities()
        okta_admins = [
            i for i in identities
            if i["source_system"] == "okta" and i.get("is_admin")
        ]
        
        passed = len(okta_admins)
        
        return ControlResult(
            control_id=control.id,
            status=ControlStatus.PASS,
            passed_count=passed,
            message=f"{passed} users in admin groups (manual review required)"
        )

    def _evaluate_cloudtrail_enabled(self, control: Control) -> ControlResult:
        """CloudTrail enabled check."""
        evidence_dir = Path("evidence")
        if evidence_dir.exists():
            aws_files = list(evidence_dir.glob("aws_data_*.json"))
            if aws_files:
                return ControlResult(
                    control_id=control.id,
                    status=ControlStatus.PASS,
                    passed_count=1,
                    message="CloudTrail data present in evidence artifacts"
                )
        
        return ControlResult(
            control_id=control.id,
            status=ControlStatus.FAIL,
            failed_count=1,
            failure_details=[{"reason": "No CloudTrail evidence found"}]
        )

    def _evaluate_root_usage(self, control: Control) -> ControlResult:
        """AWS root usage check."""
        findings = self.db.get_all_findings()
        root_findings = [
            f for f in findings
            if f["source_system"] == "aws" and "root" in f.get("title", "").lower()
        ]
        
        if root_findings:
            return ControlResult(
                control_id=control.id,
                status=ControlStatus.FAIL,
                failed_count=len(root_findings),
                failure_details=[
                    {"finding": f["title"], "reason": "Root account usage detected"}
                    for f in root_findings
                ]
            )
        
        return ControlResult(
            control_id=control.id,
            status=ControlStatus.PASS,
            passed_count=1,
            message="No root account usage detected"
        )

    def _evaluate_github_2fa(self, control: Control) -> ControlResult:
        """GitHub 2FA requirement."""
        identities = self.db.get_all_identities()
        github_users = [i for i in identities if i["source_system"] == "github"]
        
        failures = []
        passed = 0
        excepted = 0
        
        for user in github_users:
            if not user.get("has_mfa"):
                if self._check_exception(control.id, user["id"]):
                    excepted += 1
                else:
                    failures.append({
                        "username": user.get("username"),
                        "email": user.get("email"),
                        "reason": "2FA not enabled"
                    })
            else:
                passed += 1
        
        status = ControlStatus.PASS if len(failures) == 0 else ControlStatus.FAIL
        if excepted > 0 and len(failures) == 0:
            status = ControlStatus.EXCEPTION
        
        return ControlResult(
            control_id=control.id,
            status=status,
            passed_count=passed,
            failed_count=len(failures),
            exception_count=excepted,
            failure_details=failures
        )

    def _evaluate_endpoint_owner_correlation(self, control: Control) -> ControlResult:
        """Endpoints must have owners who are active Okta users."""
        assets = self.db.get_all_assets()
        endpoints = [a for a in assets if a["asset_type"] == "endpoint"]
        
        identities = self.db.get_all_identities()
        okta_active_emails = {
            i["email"].lower() for i in identities
            if i["source_system"] == "okta" and i.get("is_active") and i.get("email")
        }
        
        failures = []
        passed = 0
        excepted = 0
        
        for endpoint in endpoints:
            owner_email = endpoint.get("owner_email")
            
            if not owner_email:
                if self._check_exception(control.id, endpoint["id"]):
                    excepted += 1
                else:
                    failures.append({
                        "endpoint": endpoint["name"],
                        "reason": "No owner assigned"
                    })
            elif owner_email.lower() not in okta_active_emails:
                if self._check_exception(control.id, endpoint["id"]):
                    excepted += 1
                else:
                    failures.append({
                        "endpoint": endpoint["name"],
                        "owner": owner_email,
                        "reason": "Owner not found as active Okta user"
                    })
            else:
                passed += 1
        
        status = ControlStatus.PASS if len(failures) == 0 else ControlStatus.FAIL
        if excepted > 0 and len(failures) == 0:
            status = ControlStatus.EXCEPTION
        
        return ControlResult(
            control_id=control.id,
            status=status,
            passed_count=passed,
            failed_count=len(failures),
            exception_count=excepted,
            failure_details=failures
        )

    def _evaluate_production_asset_owner(self, control: Control) -> ControlResult:
        """Production assets must have owners."""
        assets = self.db.get_all_assets()
        prod_assets = [a for a in assets if a.get("is_production")]
        
        failures = []
        passed = 0
        excepted = 0
        
        for asset in prod_assets:
            if not asset.get("owner_email"):
                if self._check_exception(control.id, asset["id"]):
                    excepted += 1
                else:
                    failures.append({
                        "asset": asset["name"],
                        "type": asset["asset_type"],
                        "reason": "Production asset has no assigned owner"
                    })
            else:
                passed += 1
        
        status = ControlStatus.PASS if len(failures) == 0 else ControlStatus.FAIL
        if excepted > 0 and len(failures) == 0:
            status = ControlStatus.EXCEPTION
        
        return ControlResult(
            control_id=control.id,
            status=status,
            passed_count=passed,
            failed_count=len(failures),
            exception_count=excepted,
            failure_details=failures
        )
