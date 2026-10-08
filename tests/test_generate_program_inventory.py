import csv
from datetime import datetime, timezone
import hashlib
import json
import subprocess
import sys
from pathlib import Path

import pytest

repo_root = Path(__file__).resolve().parents[1]
scripts_path = repo_root / "scripts"
if str(scripts_path) not in sys.path:
    sys.path.insert(0, str(scripts_path))

from generate_program_inventory import build_snapshot, render_markdown, write_outputs


def write_csv(path: Path, rows: list[dict[str, str]], fields: list[str]) -> None:
    with path.open("w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=fields)
        writer.writeheader()
        writer.writerows(rows)


def test_build_snapshot_compacts_raw_inventory(tmp_path):
    raw = tmp_path / "raw"
    raw.mkdir()
    (raw / "run-result.json").write_text(json.dumps({"process_rows": 3, "executables": 7, "desktop_apps": 2, "observed_at": "2026-07-09T18:15:00Z", "observation_id": "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", "binding_eligible": True, "host": "heim-pc", "collector_sha256": "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb", "raw_manifest_sha256": "cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc", "raw_artifact_count": 7}), encoding="utf-8")
    (raw / "full-rootfs-scan-result.json").write_text(json.dumps({"count": 10}), encoding="utf-8")
    (raw / "full-rootfs-sudo-scan-result.json").write_text(json.dumps({"count": 12, "note": "metadata only", "stderr_tail": ["find: one denied"]}), encoding="utf-8")
    (raw / "sudo-delta-summary.json").write_text(json.dumps({"added_by_sudo": 2, "top_added_prefixes": [["/var/lib", 2]], "top_added_names": [["run", 2]]}), encoding="utf-8")
    write_csv(raw / "desktop_apps.csv", [
        {"name": "GitKraken", "generic": "", "categories": "Development;", "exec": "gitkraken", "desktop_file": "/usr/share/applications/gitkraken.desktop"},
        {"name": "Spotify", "generic": "", "categories": "AudioVideo;", "exec": "spotify", "desktop_file": "/usr/share/applications/spotify.desktop"},
    ], ["name", "generic", "categories", "exec", "desktop_file"])
    write_csv(raw / "running_processes.csv", [
        {"pid": "1", "ppid": "0", "user": "root", "stat": "S", "comm": "systemd", "args": "systemd"},
        {"pid": "2", "ppid": "1", "user": "alex", "stat": "S", "comm": "bash", "args": "bash"},
        {"pid": "3", "ppid": "1", "user": "alex", "stat": "S", "comm": "bash", "args": "bash"},
    ], ["pid", "ppid", "user", "stat", "comm", "args"])
    write_csv(raw / "executables.csv", [
        {"name": "git", "path": "/usr/bin/git", "resolved": "/usr/bin/git", "source": "PATH", "size": "1", "mtime": "1", "sha256_1m": "x"},
    ], ["name", "path", "resolved", "source", "size", "mtime", "sha256_1m"])
    write_csv(raw / "executables_added_by_sudo.csv", [
        {"name": "run", "path": "/var/lib/example/run", "size": "1", "mtime": "1"},
        {"name": "run", "path": "/var/lib/example2/run", "size": "1", "mtime": "1"},
    ], ["name", "path", "size", "mtime"])
    (raw / "flatpak_apps.tsv").write_text("# rc=0\ncom.spotify.Client\tSpotify\t1.0\tsystem\n", encoding="utf-8")
    (raw / "snap_list.txt").write_text("# rc=0\nName Version Rev Tracking Publisher Notes\nhelm 4.2.2 531 latest/stable canonical** classic\n", encoding="utf-8")
    (raw / "docker_ps.tsv").write_text("# rc=0\nheim-util-beszel\thenrygd/beszel:latest\tUp 10 hours\t127.0.0.1:8090->8090/tcp\n", encoding="utf-8")

    snapshot = build_snapshot(raw, generated_at="2026-09-12T13:00:00Z")

    assert snapshot["schema"] == "program-inventory.v1"
    assert snapshot["generated_at"] == "2026-09-12T13:00:00Z"
    assert snapshot["observation_scope"] == {
        "kind": "point_in_time_runtime_observation",
        "observed_at": "2026-07-09T18:15:00Z",
        "observation_id": "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
        "binding_eligible": True,
        "does_not_establish": [
            "current_state_after_observed_at",
            "service_necessity",
            "system_architecture",
            "preferred_access_path",
        ],
    }
    assert snapshot["counts"]["running_process_rows"] == 3
    assert snapshot["counts"]["rootfs_executables_sudo"] == 12
    assert snapshot["counts"]["executables_added_by_sudo"] == 2
    assert snapshot["desktop_groups"]["Entwicklung / Operator"] == ["GitKraken"]
    assert snapshot["operator_tools"] == {"git": ["/usr/bin/git"]}
    assert snapshot["docker_containers"][0]["name"] == "heim-util-beszel"
    assert snapshot["collection_provenance"]["host"] == "heim-pc"
    assert snapshot["collection_provenance"]["collector_sha256"] == "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
    assert snapshot["collection_provenance"]["raw_manifest_sha256"] == "cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc"


def test_render_and_write_outputs(tmp_path):
    raw = tmp_path / "raw"
    raw.mkdir()
    (raw / "run-result.json").write_text(json.dumps({"process_rows": 0, "executables": 0, "desktop_apps": 0, "observed_at": "2026-07-09T18:15:00Z"}), encoding="utf-8")
    snapshot = build_snapshot(raw, generated_at="2026-09-12T13:00:00Z")
    summary = render_markdown(snapshot)

    assert "id: program-inventory-summary" in summary
    assert "canonicality: observation" in summary
    assert "temporal_scope: point_in_time" in summary
    assert 'observed_at: "2026-07-09T18:15:00Z"' in summary
    assert "Generated at: `2026-09-12T13:00:00Z`" in summary
    assert "Observed at: `2026-07-09T18:15:00Z`" in summary
    assert "does not establish current state after that timestamp" in summary
    assert "Raw artifact policy" in summary
    assert "Large raw inventories stay outside Git" in summary

    summary_out = tmp_path / "summary.md"
    json_out = tmp_path / "inventory.json"
    write_outputs(snapshot, summary_out, json_out)
    assert summary_out.exists()
    assert json.loads(json_out.read_text())["schema"] == "program-inventory.v1"


def test_build_snapshot_uses_legacy_summary_collection_timestamp(tmp_path):
    raw = tmp_path / "legacy"
    raw.mkdir()
    (raw / "run-result.json").write_text(json.dumps({"process_rows": 0}), encoding="utf-8")
    (raw / "SUMMARY.md").write_text("# Raw inventory\n\nGenerated: 2026-07-09T20:15:00+0200\n", encoding="utf-8")

    snapshot = build_snapshot(raw, generated_at="2026-09-12T13:00:00Z")

    assert snapshot["generated_at"] == "2026-09-12T13:00:00Z"
    assert snapshot["observation_scope"]["observed_at"] == "2026-07-09T18:15:00Z"


def test_build_snapshot_rejects_raw_inventory_without_collection_timestamp(tmp_path):
    raw = tmp_path / "untimestamped"
    raw.mkdir()
    (raw / "run-result.json").write_text(json.dumps({"process_rows": 0}), encoding="utf-8")

    with pytest.raises(ValueError, match="missing a trustworthy collection timestamp"):
        build_snapshot(raw, generated_at="2026-09-12T13:00:00Z")


def test_real_renderer_subprocess_emits_runtime_timestamp_and_complete_hashes(tmp_path):
    # An actual separate Python process, not a prelaunch timestamp fixture.
    # It still does not authenticate task stdout against a same-UID writer.
    raw = tmp_path / "raw"
    raw.mkdir()
    obs_id = "a" * 64
    (raw / "run-result.json").write_text(json.dumps({
        "host": "heim-pc",
        "observed_at": "2026-10-07T15:00:05Z",
        "observation_id": obs_id,
        "binding_eligible": True,
        "collector_sha256": "b" * 64,
        "raw_manifest_sha256": "c" * 64,
        "raw_artifact_count": 1,
    }), encoding="utf-8")
    summary = tmp_path / "summary.md"
    program = tmp_path / "program.json"
    argv = [
        sys.executable,
        str(repo_root / "scripts/generate_program_inventory.py"),
        "--raw-dir", str(raw),
        "--summary-out", str(summary),
        "--json-out", str(program),
    ]
    before = datetime.now(timezone.utc).replace(microsecond=0)
    proc = subprocess.run(
        argv, cwd=repo_root, stdout=subprocess.PIPE,
        stderr=subprocess.PIPE, check=True, timeout=30,
    )
    after = datetime.now(timezone.utc)
    proof = json.loads(proc.stdout)
    generated = datetime.fromisoformat(
        proof["generated_at"].replace("Z", "+00:00")
    )
    assert before <= generated <= after
    assert proc.stdout == (
        json.dumps(proof, ensure_ascii=False, sort_keys=True, separators=(",", ":"))
        + "\n"
    ).encode("utf-8")
    assert proof["kind"] == "heim_pc.program_renderer_output"
    assert proof["schema_version"] == 1
    assert proof["generated_at_source"] == "renderer_runtime_clock"
    assert proof["observation_id"] == obs_id
    assert json.loads(program.read_bytes())["generated_at"] == proof["generated_at"]
    for prefix, path in (("summary", summary), ("json", program)):
        full = path.read_bytes()
        assert proof[f"{prefix}_sha256"] == hashlib.sha256(full).hexdigest()
        assert proof[f"{prefix}_bytes"] == len(full)
    assert "--generated-at" not in argv


def test_explicit_override_is_marked_nonadmissible_for_live_tasks(tmp_path):
    raw = tmp_path / "raw"
    raw.mkdir()
    (raw / "run-result.json").write_text(
        json.dumps({"observed_at": "2026-10-07T15:00:05Z"}),
        encoding="utf-8",
    )
    summary, program = tmp_path / "summary.md", tmp_path / "program.json"
    proc = subprocess.run(
        [
            sys.executable,
            str(repo_root / "scripts/generate_program_inventory.py"),
            "--raw-dir", str(raw),
            "--summary-out", str(summary),
            "--json-out", str(program),
            "--generated-at", "2099-01-01T00:00:00Z",
        ],
        cwd=repo_root, stdout=subprocess.PIPE,
        stderr=subprocess.PIPE, check=True, timeout=30,
    )
    proof = json.loads(proc.stdout)
    assert proof["generated_at"] == "2099-01-01T00:00:00Z"
    assert proof["generated_at_source"] == "explicit_override_not_admissible"
    assert json.loads(program.read_bytes())["generated_at"] == proof["generated_at"]


def test_renderer_help_does_not_generate_provenance_or_outputs(tmp_path):
    summary, program = tmp_path / "summary.md", tmp_path / "program.json"
    proc = subprocess.run(
        [
            sys.executable,
            str(repo_root / "scripts/generate_program_inventory.py"),
            "--help",
            "--summary-out", str(summary),
            "--json-out", str(program),
        ],
        cwd=repo_root, stdout=subprocess.PIPE,
        stderr=subprocess.PIPE, check=True, timeout=30,
    )
    assert b"usage:" in proc.stdout
    assert b"heim_pc.program_renderer_output" not in proc.stdout
    assert not summary.exists() and not program.exists()
