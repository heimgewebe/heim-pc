import sys
from pathlib import Path

repo_root = Path(__file__).resolve().parents[1]
scripts_path = repo_root / "scripts"
if str(scripts_path) not in sys.path:
    sys.path.insert(0, str(scripts_path))

from generate_software_inventory import inventory_header


def test_inventory_header_binds_point_in_time_authority():
    rendered = "\n".join(inventory_header("2026-09-12T13:00:00Z"))

    assert "status: canonical" in rendered
    assert "canonicality: observation" in rendered
    assert "temporal_scope: point_in_time" in rendered
    assert 'observed_at: "2026-09-12T13:00:00Z"' in rendered
    assert "last_reviewed: 2026-09-12" in rendered
    assert "does not establish current state after that timestamp" in rendered
    assert "system architecture" in rendered
    assert "preferred access path" in rendered
