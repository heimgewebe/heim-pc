import csv
import json
import sys
from pathlib import Path

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
    (raw / "run-result.json").write_text(json.dumps({"process_rows": 3, "executables": 7, "desktop_apps": 2}), encoding="utf-8")
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

    snapshot = build_snapshot(raw, generated_at="2026-07-09T18:15:00Z")

    assert snapshot["schema"] == "program-inventory.v1"
    assert snapshot["counts"]["running_process_rows"] == 3
    assert snapshot["counts"]["rootfs_executables_sudo"] == 12
    assert snapshot["counts"]["executables_added_by_sudo"] == 2
    assert snapshot["desktop_groups"]["Entwicklung / Operator"] == ["GitKraken"]
    assert snapshot["operator_tools"] == {"git": ["/usr/bin/git"]}
    assert snapshot["docker_containers"][0]["name"] == "heim-util-beszel"


def test_render_and_write_outputs(tmp_path):
    raw = tmp_path / "raw"
    raw.mkdir()
    (raw / "run-result.json").write_text(json.dumps({"process_rows": 0, "executables": 0, "desktop_apps": 0}), encoding="utf-8")
    snapshot = build_snapshot(raw, generated_at="2026-07-09T18:15:00Z")
    summary = render_markdown(snapshot)

    assert "id: program-inventory-summary" in summary
    assert "Raw artifact policy" in summary
    assert "Large raw inventories stay outside Git" in summary

    summary_out = tmp_path / "summary.md"
    json_out = tmp_path / "inventory.json"
    write_outputs(snapshot, summary_out, json_out)
    assert summary_out.exists()
    assert json.loads(json_out.read_text())["schema"] == "program-inventory.v1"
