"""Test control evaluation."""

import pytest
import asyncio
from signalgraph.connectors.registry import ConnectorRegistry
from signalgraph.correlation.engine import CorrelationEngine
from signalgraph.controls.loader import load_control_catalog, filter_controls_by_framework
from signalgraph.controls.evaluator import ControlEvaluator
from signalgraph.models import ControlStatus


@pytest.mark.asyncio
async def test_control_evaluation(temp_db, temp_evidence_dir):
    """Test that controls can be evaluated."""
    for connector_name in ["okta", "aws", "github", "edr", "jira"]:
        connector = ConnectorRegistry.create(connector_name)
        result = await connector.pull()
        temp_db.save_identities(result.identities)
        temp_db.save_assets(result.assets)
        temp_db.save_findings(result.findings)
        temp_db.save_tickets(result.tickets)
    
    engine = CorrelationEngine(temp_db)
    engine.correlate_identities()
    
    controls = load_control_catalog()
    evaluator = ControlEvaluator(temp_db)
    
    results = {}
    for control in controls:
        result = evaluator.evaluate(control)
        results[control.id] = result
    
    assert len(results) > 0
    assert results["TERM-001"].status == ControlStatus.FAIL
    
    assert results["ENCRYPT-001"].passed_count + results["ENCRYPT-001"].failed_count > 0


@pytest.mark.asyncio
async def test_framework_filtering(temp_db):
    """Test that controls can be filtered by framework."""
    controls = load_control_catalog()
    
    soc2_controls = filter_controls_by_framework(controls, "soc2")
    pci_controls = filter_controls_by_framework(controls, "pci")
    hipaa_controls = filter_controls_by_framework(controls, "hipaa")
    iso_controls = filter_controls_by_framework(controls, "iso27001")
    
    assert len(soc2_controls) > 0
    assert len(pci_controls) > 0
    assert len(hipaa_controls) > 0
    assert len(iso_controls) > 0
    
    # Framework-specific controls should make counts different
    assert len(soc2_controls) != len(pci_controls) or len(soc2_controls) != len(hipaa_controls)
    
    for control in soc2_controls:
        assert "soc2" in control.frameworks


@pytest.mark.asyncio
async def test_correlation_only_findings(temp_db, temp_evidence_dir):
    """Test that correlation-based findings exist (not visible in single source)."""
    for connector_name in ["okta", "aws", "github"]:
        connector = ConnectorRegistry.create(connector_name)
        result = await connector.pull()
        temp_db.save_identities(result.identities)
    
    engine = CorrelationEngine(temp_db)
    engine.correlate_identities()
    
    controls = load_control_catalog()
    evaluator = ControlEvaluator(temp_db)
    
    term_control = next(c for c in controls if c.id == "TERM-001")
    result = evaluator.evaluate(term_control)
    
    assert result.status == ControlStatus.FAIL
    assert result.failed_count > 0
    
    assert any(
        "deactivated" in detail.get("reason", "").lower()
        for detail in result.failure_details
    )
