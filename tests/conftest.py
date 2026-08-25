"""Pytest configuration and fixtures."""

import pytest
import tempfile
import shutil
from pathlib import Path

from signalgraph.storage.database import Database
from signalgraph.connectors.loader import register_all_connectors


@pytest.fixture
def temp_db():
    """Create a temporary database for testing."""
    with tempfile.NamedTemporaryFile(suffix=".db", delete=False) as f:
        db_path = f.name
    
    db = Database(db_path)
    yield db
    
    db.close()
    Path(db_path).unlink(missing_ok=True)


@pytest.fixture
def temp_evidence_dir():
    """Create temporary evidence directory."""
    temp_dir = Path(tempfile.mkdtemp())
    orig_evidence = Path("evidence")
    
    if orig_evidence.exists():
        backup = Path(tempfile.mkdtemp())
        shutil.copytree(orig_evidence, backup / "evidence")
    else:
        backup = None
    
    orig_evidence.mkdir(parents=True, exist_ok=True)
    
    yield temp_dir
    
    shutil.rmtree(temp_dir, ignore_errors=True)
    shutil.rmtree(orig_evidence, ignore_errors=True)
    
    if backup:
        shutil.copytree(backup / "evidence", orig_evidence)
        shutil.rmtree(backup)


@pytest.fixture(autouse=True)
def register_connectors():
    """Automatically register connectors for all tests."""
    register_all_connectors()
