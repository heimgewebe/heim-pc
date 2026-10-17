import hashlib
import sys
from pathlib import Path

repo_root = Path(__file__).resolve().parents[1]
scripts_path = repo_root / "scripts"
if str(scripts_path) not in sys.path:
    sys.path.insert(0, str(scripts_path))

import collect_program_inventory as collector
from collect_program_inventory import observation_binding, raw_manifest_sha256


def test_explicit_observation_id_is_binding_eligible():
    observation_id, binding_eligible = observation_binding("a" * 64)
    assert observation_id == "a" * 64
    assert binding_eligible is True


def test_default_observation_id_is_not_binding_eligible():
    observation_id, binding_eligible = observation_binding(None)
    assert len(observation_id) == 64
    assert set(observation_id) <= set("0123456789abcdef")
    assert binding_eligible is False


def test_raw_manifest_is_deterministic_and_excludes_receipt_files(tmp_path):
    (tmp_path / "b.txt").write_bytes(b"bravo")
    (tmp_path / "a.txt").write_bytes(b"alpha")
    (tmp_path / "run-result.json").write_text("ignored", encoding="utf-8")
    (tmp_path / "SUMMARY.md").write_text("ignored", encoding="utf-8")

    digest, count = raw_manifest_sha256(tmp_path)

    entries = []
    for name, payload in [("a.txt", b"alpha"), ("b.txt", b"bravo")]:
        entries.append((name, hashlib.sha256(payload).hexdigest()))
    expected_payload = "".join(
        f"{name}\0{item_digest}\n" for name, item_digest in entries
    ).encode()
    assert digest == hashlib.sha256(expected_payload).hexdigest()
    assert count == 2


def test_explicit_output_dir_is_fresh_and_below_inventory_root(tmp_path, monkeypatch):
    monkeypatch.setattr(collector, "OUT_ROOT", tmp_path)
    target = (tmp_path / "bound-run").resolve()
    out, bound = collector.explicit_output_dir(target, stamp="ignored")
    assert out == target
    assert bound is True


def test_explicit_output_dir_rejects_reuse(tmp_path, monkeypatch):
    monkeypatch.setattr(collector, "OUT_ROOT", tmp_path)
    target = tmp_path / "existing"
    target.mkdir()
    try:
        collector.explicit_output_dir(target.resolve(), stamp="ignored")
    except ValueError as exc:
        assert "already exists" in str(exc)
    else:
        raise AssertionError("expected existing raw run to be rejected")


def test_explicit_output_dir_rejects_path_outside_inventory_root(tmp_path, monkeypatch):
    root = tmp_path / "root"
    root.mkdir()
    monkeypatch.setattr(collector, "OUT_ROOT", root)
    outside = (tmp_path / "outside").resolve()
    try:
        collector.explicit_output_dir(outside, stamp="ignored")
    except ValueError as exc:
        assert "below the program-inventory root" in str(exc)
    else:
        raise AssertionError("expected outside raw run to be rejected")
