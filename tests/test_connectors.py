"""Test connectors."""

import pytest
from signalgraph.connectors.registry import ConnectorRegistry


@pytest.mark.asyncio
async def test_okta_connector(temp_db, temp_evidence_dir):
    """Test Okta connector pulls identity data."""
    connector = ConnectorRegistry.create("okta")
    result = await connector.pull()
    
    assert len(result.identities) > 0
    assert result.health.is_healthy
    assert len(result.evidence_paths) > 0
    
    assert any(i.email == "alex.rivera@example.com" for i in result.identities)
    assert any(i.email == "sam.williams@example.com" and not i.is_active for i in result.identities)


@pytest.mark.asyncio
async def test_aws_connector(temp_db, temp_evidence_dir):
    """Test AWS connector pulls IAM, S3, and findings."""
    connector = ConnectorRegistry.create("aws")
    result = await connector.pull()
    
    assert len(result.identities) > 0
    assert len(result.assets) > 0
    assert len(result.findings) > 0
    
    assert any(a.asset_type.value == "storage" for a in result.assets)
    assert any(f.severity.value == "critical" for f in result.findings)


@pytest.mark.asyncio
async def test_github_connector(temp_db, temp_evidence_dir):
    """Test GitHub connector pulls members and repos."""
    connector = ConnectorRegistry.create("github")
    result = await connector.pull()
    
    assert len(result.identities) > 0
    assert len(result.assets) > 0
    
    assert any(i.is_admin for i in result.identities)
    assert any(not i.has_mfa for i in result.identities)


@pytest.mark.asyncio
async def test_edr_connector(temp_db, temp_evidence_dir):
    """Test EDR connector pulls endpoints."""
    connector = ConnectorRegistry.create("edr")
    result = await connector.pull()
    
    assert len(result.assets) > 0
    
    assert any(not a.is_encrypted for a in result.assets)
    assert any(a.owner_email == "morgan.taylor@example.com" for a in result.assets)


@pytest.mark.asyncio
async def test_jira_connector(temp_db, temp_evidence_dir):
    """Test Jira connector pulls tickets."""
    connector = ConnectorRegistry.create("jira")
    result = await connector.pull()
    
    assert len(result.tickets) > 0
    
    assert any(t.status.value == "open" for t in result.tickets)
    assert any(t.linked_control for t in result.tickets)
