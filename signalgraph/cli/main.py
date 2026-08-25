"""
SignalGraph CLI.
"""

import asyncio
import json
import sys
from pathlib import Path
from typing import Optional
import typer
from rich.console import Console
from rich.table import Table
from rich import print as rprint

from signalgraph.storage.database import Database
from signalgraph.connectors.registry import ConnectorRegistry
from signalgraph.connectors.loader import register_all_connectors
from signalgraph.correlation.engine import CorrelationEngine
from signalgraph.controls.loader import load_control_catalog, filter_controls_by_framework
from signalgraph.controls.evaluator import ControlEvaluator
from signalgraph.models import Framework, ControlStatus

app = typer.Typer(
    name="signalgraph",
    help="Multi-source GRC posture platform with identity correlation",
    no_args_is_help=True
)
console = Console()


@app.command()
def ingest(
    db_path: str = typer.Option("signalgraph.db", help="Database path"),
    connectors: Optional[str] = typer.Option(None, help="Comma-separated connector names (default: all)"),
):
    """
    Ingest data from all or specified connectors.
    """
    register_all_connectors()
    db = Database(db_path)
    
    connector_names = connectors.split(",") if connectors else ConnectorRegistry.list()
    
    console.print(f"[bold]Ingesting from connectors:[/bold] {', '.join(connector_names)}")
    
    total_identities = 0
    total_assets = 0
    total_findings = 0
    total_tickets = 0
    
    for name in connector_names:
        try:
            console.print(f"\n[cyan]→ {name}[/cyan]")
            connector = ConnectorRegistry.create(name)
            result = asyncio.run(connector.pull())
            
            db.save_identities(result.identities)
            db.save_assets(result.assets)
            db.save_findings(result.findings)
            db.save_tickets(result.tickets)
            
            total_identities += len(result.identities)
            total_assets += len(result.assets)
            total_findings += len(result.findings)
            total_tickets += len(result.tickets)
            
            console.print(f"  Identities: {len(result.identities)}")
            console.print(f"  Assets: {len(result.assets)}")
            console.print(f"  Findings: {len(result.findings)}")
            console.print(f"  Tickets: {len(result.tickets)}")
            console.print(f"  Evidence: {', '.join(result.evidence_paths)}")
        except Exception as e:
            console.print(f"  [red]Error: {e}[/red]")
    
    console.print(f"\n[bold green]✓ Ingestion complete[/bold green]")
    console.print(f"  Total identities: {total_identities}")
    console.print(f"  Total assets: {total_assets}")
    console.print(f"  Total findings: {total_findings}")
    console.print(f"  Total tickets: {total_tickets}")


@app.command()
def correlate(
    db_path: str = typer.Option("signalgraph.db", help="Database path"),
):
    """
    Correlate identities across systems and detect issues.
    """
    db = Database(db_path)
    engine = CorrelationEngine(db)
    
    console.print("[bold]Correlating identities...[/bold]")
    correlated = engine.correlate_identities()
    console.print(f"  Created {len(correlated)} correlated identity groups")
    
    console.print("\n[bold]Detecting orphans...[/bold]")
    orphans = engine.detect_orphans()
    console.print(f"  Found {len(orphans)} orphan identities")
    
    console.print("\n[bold]Detecting JML issues...[/bold]")
    jml_issues = engine.detect_jml_issues()
    console.print(f"  Found {len(jml_issues)} joiner-mover-leaver issues")
    
    if orphans:
        console.print("\n[yellow]Orphan Identities:[/yellow]")
        for orphan in orphans[:5]:
            console.print(f"  • {orphan.source_system}: {orphan.email or orphan.username} - {orphan.reason}")
        if len(orphans) > 5:
            console.print(f"  ... and {len(orphans) - 5} more")
    
    if jml_issues:
        console.print("\n[red]JML Issues:[/red]")
        for issue in jml_issues[:5]:
            console.print(f"  • {issue.email}: {issue.description}")
        if len(jml_issues) > 5:
            console.print(f"  ... and {len(jml_issues) - 5} more")
    
    console.print("\n[bold green]✓ Correlation complete[/bold green]")


@app.command()
def evaluate(
    db_path: str = typer.Option("signalgraph.db", help="Database path"),
    framework: Optional[str] = typer.Option(None, help="Filter by framework: soc2, iso27001, pci, hipaa"),
    exceptions: Optional[str] = typer.Option(None, help="Path to exceptions JSON file"),
):
    """
    Evaluate controls against the data.
    """
    db = Database(db_path)
    controls = load_control_catalog()
    
    if framework:
        framework_lower = framework.lower()
        controls = filter_controls_by_framework(controls, framework_lower)
        console.print(f"[bold]Evaluating {len(controls)} controls for framework: {framework_lower}[/bold]\n")
    else:
        console.print(f"[bold]Evaluating {len(controls)} controls (all frameworks)[/bold]\n")
    
    evaluator = ControlEvaluator(db, exceptions)
    
    results = []
    for control in controls:
        result = evaluator.evaluate(control)
        db.save_control_result(result)
        results.append((control, result))
    
    passed = sum(1 for _, r in results if r.status == ControlStatus.PASS)
    failed = sum(1 for _, r in results if r.status == ControlStatus.FAIL)
    excepted = sum(1 for _, r in results if r.status == ControlStatus.EXCEPTION)
    not_evaluated = sum(1 for _, r in results if r.status == ControlStatus.NOT_EVALUATED)
    
    table = Table(title="Control Evaluation Results")
    table.add_column("Control", style="cyan")
    table.add_column("Title")
    table.add_column("Status", style="bold")
    table.add_column("Pass/Fail/Except", justify="right")
    
    for control, result in results:
        status_style = {
            ControlStatus.PASS: "[green]PASS[/green]",
            ControlStatus.FAIL: "[red]FAIL[/red]",
            ControlStatus.EXCEPTION: "[yellow]EXCEPTED[/yellow]",
            ControlStatus.NOT_EVALUATED: "[dim]NOT EVAL[/dim]",
        }
        
        table.add_row(
            control.id,
            control.title[:50],
            status_style[result.status],
            f"{result.passed_count}/{result.failed_count}/{result.exception_count}"
        )
    
    console.print(table)
    console.print(f"\n[bold]Summary:[/bold]")
    console.print(f"  Passed: {passed}")
    console.print(f"  Failed: {failed}")
    console.print(f"  Excepted: {excepted}")
    console.print(f"  Not Evaluated: {not_evaluated}")
    
    critical_failures = sum(
        1 for c, r in results
        if r.status == ControlStatus.FAIL and c.severity == "critical"
    )
    
    if critical_failures > 0:
        console.print(f"\n[bold red]✗ {critical_failures} critical control(s) failing[/bold red]")
        sys.exit(1)
    elif failed > 0:
        console.print(f"\n[yellow]⚠ {failed} control(s) failing (non-critical)[/yellow]")
        sys.exit(0)
    else:
        console.print("\n[bold green]✓ All controls passing or excepted[/bold green]")
        sys.exit(0)


@app.command()
def report(
    db_path: str = typer.Option("signalgraph.db", help="Database path"),
    framework: Optional[str] = typer.Option(None, help="Filter by framework: soc2, iso27001, pci, hipaa"),
    output: Optional[str] = typer.Option(None, help="Output path for JSON report"),
    format: str = typer.Option("json", help="Output format: json, text"),
):
    """
    Generate a control evaluation report.
    """
    db = Database(db_path)
    controls = load_control_catalog()
    
    if framework:
        framework_lower = framework.lower()
        controls = filter_controls_by_framework(controls, framework_lower)
    
    results = db.get_control_results()
    
    report_data = {
        "framework": framework if framework else "all",
        "generated_at": str(asyncio.get_event_loop().time()),
        "controls": []
    }
    
    for control in controls:
        control_results = [r for r in results if r["control_id"] == control.id]
        if control_results:
            latest = control_results[0]
            report_data["controls"].append({
                "id": control.id,
                "title": control.title,
                "frameworks": control.frameworks,
                "severity": control.severity,
                "status": latest["status"],
                "passed_count": latest["passed_count"],
                "failed_count": latest["failed_count"],
                "exception_count": latest["exception_count"],
                "failure_details": json.loads(latest["failure_details"]) if latest["failure_details"] else [],
                "evaluated_at": latest["evaluated_at"],
            })
    
    if format == "json":
        output_str = json.dumps(report_data, indent=2)
        if output:
            Path(output).write_text(output_str)
            console.print(f"[green]Report written to {output}[/green]")
        else:
            console.print(output_str)
    else:
        console.print(f"[bold]Control Report[/bold]")
        console.print(f"Framework: {report_data['framework']}")
        console.print(f"Controls: {len(report_data['controls'])}")
        for ctrl in report_data["controls"]:
            console.print(f"\n{ctrl['id']}: {ctrl['title']}")
            console.print(f"  Status: {ctrl['status']}")
            console.print(f"  Pass/Fail/Except: {ctrl['passed_count']}/{ctrl['failed_count']}/{ctrl['exception_count']}")


@app.command()
def frameworks():
    """
    List available compliance frameworks.
    """
    table = Table(title="Available Frameworks")
    table.add_column("ID", style="cyan")
    table.add_column("Name")
    table.add_column("Description")
    
    frameworks_info = [
        ("soc2", "SOC 2 Type II", "Trust Services Criteria (CC6, CC7, CC8)"),
        ("iso27001", "ISO 27001:2022", "Information Security Management"),
        ("pci", "PCI-DSS v4", "Payment Card Industry Data Security Standard"),
        ("hipaa", "HIPAA Security Rule", "Health Insurance Portability and Accountability Act"),
    ]
    
    for fid, name, desc in frameworks_info:
        table.add_row(fid, name, desc)
    
    console.print(table)
    
    controls = load_control_catalog()
    console.print(f"\n[bold]Control Coverage by Framework:[/bold]")
    for fid, name, _ in frameworks_info:
        filtered = filter_controls_by_framework(controls, fid)
        console.print(f"  {name}: {len(filtered)} controls")


if __name__ == "__main__":
    app()
