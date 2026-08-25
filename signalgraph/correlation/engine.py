"""
Identity correlation engine for cross-system identity mapping.
"""

from collections import defaultdict
from datetime import datetime, timedelta
from typing import List, Dict, Set, Optional, Any
from pydantic import BaseModel

from signalgraph.storage.database import Database


class CorrelatedIdentity(BaseModel):
    """A correlated identity across multiple systems."""
    correlated_id: str
    email: Optional[str] = None
    employee_id: Optional[str] = None
    usernames: List[str] = []
    systems: List[str] = []
    identity_ids: List[str] = []
    is_active_in_any: bool = False
    is_admin_in_any: bool = False
    has_mfa_everywhere: bool = True
    mfa_gaps: List[str] = []
    system_details: Dict[str, Dict[str, Any]] = {}


class OrphanIdentity(BaseModel):
    """An identity that exists in one system but not in the primary IdP."""
    identity_id: str
    source_system: str
    email: Optional[str] = None
    username: Optional[str] = None
    is_admin: bool = False
    reason: str


class JMLIssue(BaseModel):
    """Joiner-Mover-Leaver issue detected."""
    correlated_id: str
    email: Optional[str] = None
    issue_type: str
    description: str
    severity: str
    affected_systems: List[str] = []


class CorrelationEngine:
    """
    Correlates identities across multiple systems.
    
    Correlation keys (in priority order):
    1. Employee ID (strongest signal)
    2. Email address
    3. Username normalization (alex.rivera -> alex-rivera, AlexRivera, etc.)
    """

    def __init__(self, db: Database):
        self.db = db

    def correlate_identities(self) -> List[CorrelatedIdentity]:
        """
        Correlate identities across all systems.
        Returns list of correlated identity groups.
        """
        identities = self.db.get_all_identities()
        
        email_map: Dict[str, List[Dict]] = defaultdict(list)
        empid_map: Dict[str, List[Dict]] = defaultdict(list)
        username_map: Dict[str, List[Dict]] = defaultdict(list)
        
        for identity in identities:
            if identity.get("email"):
                email_map[identity["email"].lower()].append(identity)
            if identity.get("employee_id"):
                empid_map[identity["employee_id"]].append(identity)
            if identity.get("username"):
                normalized = self._normalize_username(identity["username"])
                username_map[normalized].append(identity)
        
        correlated_groups = []
        seen_ids: Set[str] = set()
        
        for emp_id, group in empid_map.items():
            group_ids = {i["id"] for i in group}
            if group_ids & seen_ids:
                continue
            
            seen_ids.update(group_ids)
            correlated = self._build_correlated_identity(group, emp_id)
            correlated_groups.append(correlated)
            self.db.save_correlation(
                correlated.correlated_id,
                correlated.identity_ids,
                correlated.email,
                correlated.employee_id,
                correlated.usernames
            )
        
        for email, group in email_map.items():
            group_ids = {i["id"] for i in group}
            if group_ids & seen_ids:
                continue
            
            seen_ids.update(group_ids)
            correlated = self._build_correlated_identity(group, email)
            correlated_groups.append(correlated)
            self.db.save_correlation(
                correlated.correlated_id,
                correlated.identity_ids,
                correlated.email,
                correlated.employee_id,
                correlated.usernames
            )
        
        for username, group in username_map.items():
            group_ids = {i["id"] for i in group}
            if group_ids & seen_ids:
                continue
            
            seen_ids.update(group_ids)
            correlated = self._build_correlated_identity(group, username)
            correlated_groups.append(correlated)
            self.db.save_correlation(
                correlated.correlated_id,
                correlated.identity_ids,
                correlated.email,
                correlated.employee_id,
                correlated.usernames
            )
        
        return correlated_groups

    def _normalize_username(self, username: str) -> str:
        """Normalize username for matching."""
        return username.lower().replace(".", "").replace("-", "").replace("_", "")

    def _build_correlated_identity(self, group: List[Dict], base_key: str) -> CorrelatedIdentity:
        """Build a correlated identity from a group of identities."""
        import hashlib
        
        identity_ids = [i["id"] for i in group]
        correlated_id = f"corr:{hashlib.md5(base_key.encode()).hexdigest()[:16]}"
        
        emails = {i.get("email") for i in group if i.get("email")}
        employee_ids = {i.get("employee_id") for i in group if i.get("employee_id")}
        usernames = [i.get("username") for i in group if i.get("username")]
        systems = list({i["source_system"] for i in group})
        
        email = list(emails)[0] if emails else None
        employee_id = list(employee_ids)[0] if employee_ids else None
        
        is_active_in_any = any(i.get("is_active") for i in group)
        is_admin_in_any = any(i.get("is_admin") for i in group)
        
        mfa_gaps = []
        for identity in group:
            if not identity.get("has_mfa") and (identity.get("is_admin") or identity.get("is_active")):
                mfa_gaps.append(identity["source_system"])
        
        has_mfa_everywhere = len(mfa_gaps) == 0
        
        system_details = {}
        for identity in group:
            system = identity["source_system"]
            system_details[system] = {
                "is_active": bool(identity.get("is_active")),
                "is_admin": bool(identity.get("is_admin")),
                "has_mfa": bool(identity.get("has_mfa")),
                "username": identity.get("username"),
                "last_activity": identity.get("last_activity"),
                "deactivated_at": identity.get("deactivated_at"),
            }
        
        return CorrelatedIdentity(
            correlated_id=correlated_id,
            email=email,
            employee_id=employee_id,
            usernames=usernames,
            systems=systems,
            identity_ids=identity_ids,
            is_active_in_any=is_active_in_any,
            is_admin_in_any=is_admin_in_any,
            has_mfa_everywhere=has_mfa_everywhere,
            mfa_gaps=mfa_gaps,
            system_details=system_details
        )

    def detect_orphans(self) -> List[OrphanIdentity]:
        """
        Detect orphan identities (exist in AWS/GitHub/EDR but not in Okta).
        """
        identities = self.db.get_all_identities()
        
        okta_emails = {
            i["email"].lower() for i in identities 
            if i["source_system"] == "okta" and i.get("email")
        }
        okta_employee_ids = {
            i["employee_id"] for i in identities 
            if i["source_system"] == "okta" and i.get("employee_id")
        }
        
        orphans = []
        for identity in identities:
            if identity["source_system"] == "okta":
                continue
            
            email = identity.get("email", "").lower() if identity.get("email") else None
            employee_id = identity.get("employee_id")
            
            is_orphan = False
            reason = ""
            
            if email and email not in okta_emails:
                is_orphan = True
                reason = f"Email {email} not found in Okta"
            elif employee_id and employee_id not in okta_employee_ids:
                is_orphan = True
                reason = f"Employee ID {employee_id} not found in Okta"
            elif not email and not employee_id:
                is_orphan = True
                reason = "No email or employee ID to correlate with Okta"
            
            if is_orphan:
                orphans.append(OrphanIdentity(
                    identity_id=identity["id"],
                    source_system=identity["source_system"],
                    email=identity.get("email"),
                    username=identity.get("username"),
                    is_admin=bool(identity.get("is_admin")),
                    reason=reason
                ))
        
        return orphans

    def detect_jml_issues(self) -> List[JMLIssue]:
        """
        Detect Joiner-Mover-Leaver issues.
        
        Examples:
        - Terminated in Okta but still has AWS keys
        - Dormant Okta account with recent AWS activity
        - Deactivated Okta with active GitHub admin
        """
        issues = []
        correlated = self.db.get_correlated_identities()
        
        for corr_data in correlated:
            import json
            identity_ids = json.loads(corr_data["identity_ids"])
            identities = []
            for iid in identity_ids:
                identity = next(
                    (i for i in self.db.get_all_identities() if i["id"] == iid),
                    None
                )
                if identity:
                    identities.append(identity)
            
            okta_identity = next((i for i in identities if i["source_system"] == "okta"), None)
            
            if not okta_identity:
                continue
            
            okta_active = okta_identity.get("is_active")
            okta_deactivated_at = okta_identity.get("deactivated_at")
            
            if not okta_active or okta_deactivated_at:
                for identity in identities:
                    if identity["source_system"] == "okta":
                        continue
                    
                    if identity.get("is_active"):
                        issues.append(JMLIssue(
                            correlated_id=corr_data["correlated_id"],
                            email=corr_data.get("email"),
                            issue_type="leaver_access",
                            description=f"Deactivated in Okta but still active in {identity['source_system']}",
                            severity="critical",
                            affected_systems=[identity["source_system"]]
                        ))
                    
                    if identity.get("is_admin"):
                        issues.append(JMLIssue(
                            correlated_id=corr_data["correlated_id"],
                            email=corr_data.get("email"),
                            issue_type="leaver_admin_access",
                            description=f"Deactivated in Okta but still has admin in {identity['source_system']}",
                            severity="critical",
                            affected_systems=[identity["source_system"]]
                        ))
            
            else:
                okta_last_login = okta_identity.get("last_activity")
                if okta_last_login:
                    try:
                        last_login_dt = datetime.fromisoformat(okta_last_login.replace("Z", "+00:00"))
                        if datetime.utcnow() - last_login_dt > timedelta(days=90):
                            for identity in identities:
                                if identity["source_system"] == "okta":
                                    continue
                                
                                if identity.get("last_activity"):
                                    try:
                                        other_activity = datetime.fromisoformat(
                                            identity["last_activity"].replace("Z", "+00:00")
                                        )
                                        if datetime.utcnow() - other_activity < timedelta(days=30):
                                            issues.append(JMLIssue(
                                                correlated_id=corr_data["correlated_id"],
                                                email=corr_data.get("email"),
                                                issue_type="dormant_okta_active_elsewhere",
                                                description=f"Dormant in Okta (>90d) but recent activity in {identity['source_system']}",
                                                severity="high",
                                                affected_systems=[identity["source_system"]]
                                            ))
                                    except:
                                        pass
                    except:
                        pass
        
        return issues
