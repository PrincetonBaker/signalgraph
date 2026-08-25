"""
Control catalog loader.
"""

import yaml
from pathlib import Path
from typing import List

from signalgraph.models import Control


def load_control_catalog(catalog_path: str = None) -> List[Control]:
    """Load controls from YAML catalog."""
    if catalog_path is None:
        catalog_path = Path(__file__).parent / "catalog.yaml"
    else:
        catalog_path = Path(catalog_path)
    
    with open(catalog_path) as f:
        data = yaml.safe_load(f)
    
    controls = []
    for ctrl_data in data.get("controls", []):
        control = Control(**ctrl_data)
        controls.append(control)
    
    return controls


def filter_controls_by_framework(controls: List[Control], framework: str) -> List[Control]:
    """Filter controls to only those applicable to a given framework."""
    return [c for c in controls if c.applies_to_framework(framework)]
