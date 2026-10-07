import sys
from pathlib import Path

repo_root = Path(__file__).resolve().parents[1]
scripts_path = repo_root / "scripts"
if str(scripts_path) not in sys.path:
    sys.path.insert(0, str(scripts_path))

import generate_software_inventory as inventory
from generate_software_inventory import inventory_header, taildrop_summary


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


def test_taildrop_summary_never_emits_file_or_target_names(tmp_path, monkeypatch):
    inbox = tmp_path / "Taildrop"
    inbox.mkdir()
    private_name = "private-medical-document.pdf"
    (inbox / private_name).write_bytes(b"secret-bytes")

    def fake_run(argv, timeout=10, max_lines=6):
        if argv[:3] == ["systemctl", "--user", "is-active"]:
            return 0, "active"
        if argv[:4] == ["tailscale", "file", "cp", "--targets"]:
            return 0, "100.1.2.3\tprivate-phone\n100.2.3.4\twork-laptop"
        return 1, "unavailable"

    monkeypatch.setattr(inventory, "run", fake_run)
    rendered = "\n".join(taildrop_summary(inbox))

    assert private_name not in rendered
    assert "private-phone" not in rendered
    assert "work-laptop" not in rendered
    assert "100.1.2.3" not in rendered
    assert "recent_files_count 1" in rendered
    assert "recent_files_total_bytes 12" in rendered
    assert "targets_available_count 2" in rendered


def test_inventory_header_exposes_binding_provenance():
    rendered = "\n".join(
        inventory_header(
            "2026-10-07T12:00:00Z",
            observation_id="a" * 64,
            binding_eligible=True,
            collector_sha256="b" * 64,
            host="heim-pc",
        )
    )
    assert 'observation_id: "' + ("a" * 64) + '"' in rendered
    assert "binding_eligible: true" in rendered
    assert 'collector_sha256: "' + ("b" * 64) + '"' in rendered
    assert 'observed_host: "heim-pc"' in rendered
