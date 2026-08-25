"""
SignalGraph REST API.
"""

import json
from typing import List, Optional
from fastapi import FastAPI, HTTPException, Query
from fastapi.staticfiles import StaticFiles
from fastapi.responses import HTMLResponse
from fastapi.templating import Jinja2Templates
from starlette.requests import Request

from signalgraph.storage.database import Database
from signalgraph.controls.loader import load_control_catalog, filter_controls_by_framework
from signalgraph.controls.evaluator import ControlEvaluator
from signalgraph.correlation.engine import CorrelationEngine

app = FastAPI(
    title="SignalGraph API",
    description="Multi-source GRC posture platform with identity correlation",
    version="0.1.0"
)

templates = Jinja2Templates(directory="signalgraph/templates")

db = Database("signalgraph.db")


@app.get("/")
def root():
    """API root."""
    return {
        "name": "SignalGraph",
        "version": "0.1.0",
        "endpoints": [
            "/frameworks",
            "/frameworks/{framework_id}/controls",
            "/frameworks/{framework_id}/results",
            "/identities",
            "/identities/{correlated_id}",
            "/assets",
            "/findings",
            "/tickets",
            "/controls",
            "/results",
            "/dashboard",
        ]
    }


@app.get("/frameworks")
def list_frameworks():
    """List available compliance frameworks."""
    return {
        "frameworks": [
            {
                "id": "soc2",
                "name": "SOC 2 Type II",
                "description": "Trust Services Criteria",
                "categories": ["CC6", "CC7", "CC8"]
            },
            {
                "id": "iso27001",
                "name": "ISO 27001:2022",
                "description": "Information Security Management",
                "categories": ["A.9", "A.10", "A.12", "A.14", "A.16"]
            },
            {
                "id": "pci",
                "name": "PCI-DSS v4",
                "description": "Payment Card Industry Data Security Standard",
                "categories": ["Requirement 1-12"]
            },
            {
                "id": "hipaa",
                "name": "HIPAA Security Rule",
                "description": "Health Insurance Portability and Accountability Act",
                "categories": ["164.308", "164.310", "164.312"]
            }
        ]
    }


@app.get("/frameworks/{framework_id}/controls")
def get_framework_controls(framework_id: str):
    """Get controls for a specific framework."""
    controls = load_control_catalog()
    filtered = filter_controls_by_framework(controls, framework_id)
    
    if not filtered:
        raise HTTPException(status_code=404, detail=f"No controls found for framework: {framework_id}")
    
    return {
        "framework": framework_id,
        "count": len(filtered),
        "controls": [
            {
                "id": c.id,
                "title": c.title,
                "description": c.description,
                "severity": c.severity,
                "framework_mappings": c.frameworks.get(framework_id, []),
                "query_type": c.query_type,
            }
            for c in filtered
        ]
    }


@app.get("/frameworks/{framework_id}/results")
def get_framework_results(framework_id: str):
    """Get evaluation results for a specific framework."""
    controls = load_control_catalog()
    filtered = filter_controls_by_framework(controls, framework_id)
    
    if not filtered:
        raise HTTPException(status_code=404, detail=f"No controls found for framework: {framework_id}")
    
    all_results = db.get_control_results()
    
    results = []
    passed = 0
    failed = 0
    excepted = 0
    
    for control in filtered:
        control_results = [r for r in all_results if r["control_id"] == control.id]
        if control_results:
            latest = control_results[0]
            status = latest["status"]
            
            if status == "pass":
                passed += 1
            elif status == "fail":
                failed += 1
            elif status == "exception":
                excepted += 1
            
            results.append({
                "control_id": control.id,
                "title": control.title,
                "status": status,
                "passed_count": latest["passed_count"],
                "failed_count": latest["failed_count"],
                "exception_count": latest["exception_count"],
                "evaluated_at": latest["evaluated_at"],
            })
    
    return {
        "framework": framework_id,
        "summary": {
            "total": len(filtered),
            "passed": passed,
            "failed": failed,
            "excepted": excepted,
            "not_evaluated": len(filtered) - passed - failed - excepted
        },
        "results": results
    }


@app.get("/identities")
def list_identities(
    source_system: Optional[str] = Query(None),
    is_active: Optional[bool] = Query(None),
):
    """List all identities."""
    identities = db.get_all_identities()
    
    if source_system:
        identities = [i for i in identities if i["source_system"] == source_system]
    
    if is_active is not None:
        identities = [i for i in identities if i["is_active"] == is_active]
    
    return {
        "count": len(identities),
        "identities": identities
    }


@app.get("/identities/{correlated_id}")
def get_identity_360(correlated_id: str, framework: Optional[str] = Query(None)):
    """Get 360-degree view of a correlated identity."""
    correlation = db.get_identity_by_correlated_id(correlated_id)
    
    if not correlation:
        raise HTTPException(status_code=404, detail=f"Identity not found: {correlated_id}")
    
    identity_ids = json.loads(correlation["identity_ids"])
    identities = []
    for iid in identity_ids:
        identity = next((i for i in db.get_all_identities() if i["id"] == iid), None)
        if identity:
            identities.append(identity)
    
    assets = []
    for identity in identities:
        email = identity.get("email")
        if email:
            user_assets = [a for a in db.get_all_assets() if a.get("owner_email") == email]
            assets.extend(user_assets)
    
    findings = []
    for identity in identities:
        user_findings = [
            f for f in db.get_all_findings()
            if f.get("affected_identity_id") == identity["id"]
        ]
        findings.extend(user_findings)
    
    tickets = []
    for identity in identities:
        email = identity.get("email")
        if email:
            user_tickets = [
                t for t in db.get_all_tickets()
                if t.get("assignee_email") == email
            ]
            tickets.extend(user_tickets)
    
    controls = load_control_catalog()
    if framework:
        controls = filter_controls_by_framework(controls, framework)
    
    affected_controls = []
    all_results = db.get_control_results()
    for control in controls:
        control_results = [r for r in all_results if r["control_id"] == control.id]
        if control_results:
            latest = control_results[0]
            failure_details = json.loads(latest.get("failure_details", "[]"))
            
            email = correlation.get("email", "").lower()
            is_affected = any(
                email in json.dumps(detail).lower()
                for detail in failure_details
            )
            
            if is_affected:
                affected_controls.append({
                    "control_id": control.id,
                    "title": control.title,
                    "status": latest["status"],
                })
    
    return {
        "correlated_id": correlated_id,
        "email": correlation.get("email"),
        "employee_id": correlation.get("employee_id"),
        "usernames": json.loads(correlation.get("usernames", "[]")),
        "systems": [i["source_system"] for i in identities],
        "identities": identities,
        "assets": assets,
        "findings": findings,
        "tickets": tickets,
        "affected_controls": affected_controls
    }


@app.get("/assets")
def list_assets(
    asset_type: Optional[str] = Query(None),
    is_production: Optional[bool] = Query(None),
):
    """List all assets."""
    assets = db.get_all_assets()
    
    if asset_type:
        assets = [a for a in assets if a["asset_type"] == asset_type]
    
    if is_production is not None:
        assets = [a for a in assets if a["is_production"] == is_production]
    
    return {
        "count": len(assets),
        "assets": assets
    }


@app.get("/findings")
def list_findings(
    severity: Optional[str] = Query(None),
    is_open: Optional[bool] = Query(None),
):
    """List all findings."""
    findings = db.get_all_findings()
    
    if severity:
        findings = [f for f in findings if f["severity"] == severity]
    
    if is_open is not None:
        findings = [f for f in findings if f["is_open"] == is_open]
    
    return {
        "count": len(findings),
        "findings": findings
    }


@app.get("/tickets")
def list_tickets(
    status: Optional[str] = Query(None),
):
    """List all tickets."""
    tickets = db.get_all_tickets()
    
    if status:
        tickets = [t for t in tickets if t["status"] == status]
    
    return {
        "count": len(tickets),
        "tickets": tickets
    }


@app.get("/controls")
def list_controls(framework: Optional[str] = Query(None)):
    """List all controls, optionally filtered by framework."""
    controls = load_control_catalog()
    
    if framework:
        controls = filter_controls_by_framework(controls, framework)
    
    return {
        "count": len(controls),
        "controls": [
            {
                "id": c.id,
                "title": c.title,
                "description": c.description,
                "frameworks": c.frameworks,
                "severity": c.severity,
            }
            for c in controls
        ]
    }


@app.get("/results")
def list_results(framework: Optional[str] = Query(None)):
    """List control evaluation results."""
    controls = load_control_catalog()
    if framework:
        controls = filter_controls_by_framework(controls, framework)
    
    all_results = db.get_control_results()
    
    results = []
    for control in controls:
        control_results = [r for r in all_results if r["control_id"] == control.id]
        if control_results:
            latest = control_results[0]
            results.append({
                "control_id": control.id,
                "title": control.title,
                "status": latest["status"],
                "passed_count": latest["passed_count"],
                "failed_count": latest["failed_count"],
                "exception_count": latest["exception_count"],
                "evaluated_at": latest["evaluated_at"],
            })
    
    return {
        "count": len(results),
        "results": results
    }


@app.get("/dashboard", response_class=HTMLResponse)
async def dashboard(request: Request, framework: str = Query("soc2")):
    """Dashboard UI with framework selector."""
    controls = load_control_catalog()
    filtered_controls = filter_controls_by_framework(controls, framework)
    
    all_results = db.get_control_results()
    
    summary = {
        "passed": 0,
        "failed": 0,
        "excepted": 0,
        "not_evaluated": 0
    }
    
    control_data = []
    for control in filtered_controls:
        control_results = [r for r in all_results if r["control_id"] == control.id]
        if control_results:
            latest = control_results[0]
            status = latest["status"]
            
            if status == "pass":
                summary["passed"] += 1
            elif status == "fail":
                summary["failed"] += 1
            elif status == "exception":
                summary["excepted"] += 1
            else:
                summary["not_evaluated"] += 1
            
            control_data.append({
                "id": control.id,
                "title": control.title,
                "severity": control.severity,
                "status": status,
                "passed": latest["passed_count"],
                "failed": latest["failed_count"],
                "excepted": latest["exception_count"],
                "frameworks": control.frameworks.get(framework, []),
            })
        else:
            summary["not_evaluated"] += 1
            control_data.append({
                "id": control.id,
                "title": control.title,
                "severity": control.severity,
                "status": "not_evaluated",
                "passed": 0,
                "failed": 0,
                "excepted": 0,
                "frameworks": control.frameworks.get(framework, []),
            })
    
    correlated = db.get_correlated_identities()
    
    frameworks_list = [
        {"id": "soc2", "name": "SOC 2"},
        {"id": "iso27001", "name": "ISO 27001"},
        {"id": "pci", "name": "PCI-DSS"},
        {"id": "hipaa", "name": "HIPAA"},
    ]
    
    return templates.TemplateResponse("dashboard.html", {
        "request": request,
        "framework": framework,
        "frameworks": frameworks_list,
        "summary": summary,
        "controls": control_data,
        "identity_count": len(correlated),
    })


if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8000)
