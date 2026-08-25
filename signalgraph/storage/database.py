"""
SQLite storage layer for canonical records.
"""

import sqlite3
import json
from datetime import datetime
from pathlib import Path
from typing import List, Optional, Dict, Any

from signalgraph.models import (
    Identity,
    Asset,
    Finding,
    Ticket,
    Evidence,
    ControlResult,
)


class Database:
    """SQLite database for storing canonical records."""

    def __init__(self, db_path: str = "signalgraph.db"):
        self.db_path = db_path
        self.conn = None
        self._init_db()

    def _init_db(self):
        """Initialize database schema."""
        self.conn = sqlite3.connect(self.db_path)
        self.conn.row_factory = sqlite3.Row
        
        cursor = self.conn.cursor()
        
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS identities (
                id TEXT PRIMARY KEY,
                identity_type TEXT,
                source_system TEXT,
                source_id TEXT,
                email TEXT,
                username TEXT,
                display_name TEXT,
                employee_id TEXT,
                is_active INTEGER,
                is_admin INTEGER,
                has_mfa INTEGER,
                last_activity TEXT,
                created_at TEXT,
                deactivated_at TEXT,
                groups TEXT,
                roles TEXT,
                attributes TEXT,
                ingested_at TEXT,
                correlated_identity_id TEXT
            )
        """)
        
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS assets (
                id TEXT PRIMARY KEY,
                asset_type TEXT,
                source_system TEXT,
                source_id TEXT,
                name TEXT,
                description TEXT,
                owner_email TEXT,
                owner_identity_id TEXT,
                is_production INTEGER,
                is_public INTEGER,
                is_encrypted INTEGER,
                tags TEXT,
                attributes TEXT,
                created_at TEXT,
                ingested_at TEXT
            )
        """)
        
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS findings (
                id TEXT PRIMARY KEY,
                source_system TEXT,
                source_id TEXT,
                title TEXT,
                description TEXT,
                severity TEXT,
                resource_id TEXT,
                resource_type TEXT,
                affected_identity_id TEXT,
                affected_asset_id TEXT,
                remediation TEXT,
                is_open INTEGER,
                first_seen TEXT,
                last_seen TEXT,
                resolved_at TEXT,
                attributes TEXT,
                ingested_at TEXT
            )
        """)
        
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS tickets (
                id TEXT PRIMARY KEY,
                source_system TEXT,
                source_id TEXT,
                title TEXT,
                description TEXT,
                status TEXT,
                assignee_email TEXT,
                assignee_identity_id TEXT,
                priority TEXT,
                labels TEXT,
                linked_control TEXT,
                linked_asset TEXT,
                linked_finding TEXT,
                sla_days INTEGER,
                age_days INTEGER,
                created_at TEXT,
                updated_at TEXT,
                resolved_at TEXT,
                attributes TEXT,
                ingested_at TEXT
            )
        """)
        
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS control_results (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                control_id TEXT,
                status TEXT,
                evaluated_at TEXT,
                passed_count INTEGER,
                failed_count INTEGER,
                exception_count INTEGER,
                failure_details TEXT,
                evidence_ids TEXT,
                message TEXT
            )
        """)
        
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS correlation_graph (
                correlated_id TEXT PRIMARY KEY,
                identity_ids TEXT,
                email TEXT,
                employee_id TEXT,
                usernames TEXT,
                created_at TEXT
            )
        """)
        
        self.conn.commit()

    def clear_all(self):
        """Clear all tables."""
        cursor = self.conn.cursor()
        cursor.execute("DELETE FROM identities")
        cursor.execute("DELETE FROM assets")
        cursor.execute("DELETE FROM findings")
        cursor.execute("DELETE FROM tickets")
        cursor.execute("DELETE FROM control_results")
        cursor.execute("DELETE FROM correlation_graph")
        self.conn.commit()

    def save_identities(self, identities: List[Identity]):
        """Save identities to database."""
        cursor = self.conn.cursor()
        for identity in identities:
            cursor.execute("""
                INSERT OR REPLACE INTO identities VALUES (
                    ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?
                )
            """, (
                identity.id,
                identity.identity_type.value,
                identity.source_system,
                identity.source_id,
                identity.email,
                identity.username,
                identity.display_name,
                identity.employee_id,
                int(identity.is_active),
                int(identity.is_admin),
                int(identity.has_mfa),
                identity.last_activity.isoformat() if identity.last_activity else None,
                identity.created_at.isoformat() if identity.created_at else None,
                identity.deactivated_at.isoformat() if identity.deactivated_at else None,
                json.dumps(identity.groups),
                json.dumps(identity.roles),
                json.dumps(identity.attributes),
                identity.ingested_at.isoformat(),
                None
            ))
        self.conn.commit()

    def save_assets(self, assets: List[Asset]):
        """Save assets to database."""
        cursor = self.conn.cursor()
        for asset in assets:
            cursor.execute("""
                INSERT OR REPLACE INTO assets VALUES (
                    ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?
                )
            """, (
                asset.id,
                asset.asset_type.value,
                asset.source_system,
                asset.source_id,
                asset.name,
                asset.description,
                asset.owner_email,
                asset.owner_identity_id,
                int(asset.is_production),
                int(asset.is_public),
                int(asset.is_encrypted),
                json.dumps(asset.tags),
                json.dumps(asset.attributes),
                asset.created_at.isoformat() if asset.created_at else None,
                asset.ingested_at.isoformat()
            ))
        self.conn.commit()

    def save_findings(self, findings: List[Finding]):
        """Save findings to database."""
        cursor = self.conn.cursor()
        for finding in findings:
            cursor.execute("""
                INSERT OR REPLACE INTO findings VALUES (
                    ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?
                )
            """, (
                finding.id,
                finding.source_system,
                finding.source_id,
                finding.title,
                finding.description,
                finding.severity.value,
                finding.resource_id,
                finding.resource_type,
                finding.affected_identity_id,
                finding.affected_asset_id,
                finding.remediation,
                int(finding.is_open),
                finding.first_seen.isoformat(),
                finding.last_seen.isoformat(),
                finding.resolved_at.isoformat() if finding.resolved_at else None,
                json.dumps(finding.attributes),
                finding.ingested_at.isoformat()
            ))
        self.conn.commit()

    def save_tickets(self, tickets: List[Ticket]):
        """Save tickets to database."""
        cursor = self.conn.cursor()
        for ticket in tickets:
            cursor.execute("""
                INSERT OR REPLACE INTO tickets VALUES (
                    ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?
                )
            """, (
                ticket.id,
                ticket.source_system,
                ticket.source_id,
                ticket.title,
                ticket.description,
                ticket.status.value,
                ticket.assignee_email,
                ticket.assignee_identity_id,
                ticket.priority,
                json.dumps(ticket.labels),
                ticket.linked_control,
                ticket.linked_asset,
                ticket.linked_finding,
                ticket.sla_days,
                ticket.age_days,
                ticket.created_at.isoformat(),
                ticket.updated_at.isoformat(),
                ticket.resolved_at.isoformat() if ticket.resolved_at else None,
                json.dumps(ticket.attributes),
                ticket.ingested_at.isoformat()
            ))
        self.conn.commit()

    def save_control_result(self, result: ControlResult):
        """Save control evaluation result."""
        cursor = self.conn.cursor()
        cursor.execute("""
            INSERT INTO control_results (
                control_id, status, evaluated_at, passed_count, failed_count,
                exception_count, failure_details, evidence_ids, message
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
        """, (
            result.control_id,
            result.status.value,
            result.evaluated_at.isoformat(),
            result.passed_count,
            result.failed_count,
            result.exception_count,
            json.dumps(result.failure_details),
            json.dumps(result.evidence_ids),
            result.message
        ))
        self.conn.commit()

    def get_all_identities(self) -> List[Dict[str, Any]]:
        """Get all identities as dictionaries."""
        cursor = self.conn.cursor()
        cursor.execute("SELECT * FROM identities")
        rows = cursor.fetchall()
        return [dict(row) for row in rows]

    def get_all_assets(self) -> List[Dict[str, Any]]:
        """Get all assets as dictionaries."""
        cursor = self.conn.cursor()
        cursor.execute("SELECT * FROM assets")
        rows = cursor.fetchall()
        return [dict(row) for row in rows]

    def get_all_findings(self) -> List[Dict[str, Any]]:
        """Get all findings as dictionaries."""
        cursor = self.conn.cursor()
        cursor.execute("SELECT * FROM findings")
        rows = cursor.fetchall()
        return [dict(row) for row in rows]

    def get_all_tickets(self) -> List[Dict[str, Any]]:
        """Get all tickets as dictionaries."""
        cursor = self.conn.cursor()
        cursor.execute("SELECT * FROM tickets")
        rows = cursor.fetchall()
        return [dict(row) for row in rows]

    def get_control_results(self, control_id: Optional[str] = None) -> List[Dict[str, Any]]:
        """Get control results, optionally filtered by control ID."""
        cursor = self.conn.cursor()
        if control_id:
            cursor.execute("SELECT * FROM control_results WHERE control_id = ? ORDER BY evaluated_at DESC", (control_id,))
        else:
            cursor.execute("SELECT * FROM control_results ORDER BY evaluated_at DESC")
        rows = cursor.fetchall()
        return [dict(row) for row in rows]

    def save_correlation(self, correlated_id: str, identity_ids: List[str], email: Optional[str], 
                        employee_id: Optional[str], usernames: List[str]):
        """Save a correlated identity."""
        cursor = self.conn.cursor()
        cursor.execute("""
            INSERT OR REPLACE INTO correlation_graph VALUES (?, ?, ?, ?, ?, ?)
        """, (
            correlated_id,
            json.dumps(identity_ids),
            email,
            employee_id,
            json.dumps(usernames),
            datetime.utcnow().isoformat()
        ))
        
        for identity_id in identity_ids:
            cursor.execute("""
                UPDATE identities SET correlated_identity_id = ? WHERE id = ?
            """, (correlated_id, identity_id))
        
        self.conn.commit()

    def get_correlated_identities(self) -> List[Dict[str, Any]]:
        """Get all correlated identity groups."""
        cursor = self.conn.cursor()
        cursor.execute("SELECT * FROM correlation_graph")
        rows = cursor.fetchall()
        return [dict(row) for row in rows]

    def get_identity_by_correlated_id(self, correlated_id: str) -> Optional[Dict[str, Any]]:
        """Get a correlated identity by ID."""
        cursor = self.conn.cursor()
        cursor.execute("SELECT * FROM correlation_graph WHERE correlated_id = ?", (correlated_id,))
        row = cursor.fetchone()
        return dict(row) if row else None

    def close(self):
        """Close database connection."""
        if self.conn:
            self.conn.close()
