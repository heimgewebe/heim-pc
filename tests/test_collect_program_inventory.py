import hashlib
import sys
from pathlib import Path

repo_root = Path(__file__).resolve().parents[1]
scripts_path = repo_root / "scripts"
if str(scripts_path) not in sys.path:
    sys.path.insert(0, str(scripts_path))

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
