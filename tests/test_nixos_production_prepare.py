import importlib.util
import json
import os
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
SCRIPTS = ROOT / "scripts"
sys.path.insert(0, str(SCRIPTS))
try:
    spec = importlib.util.spec_from_file_location("nixos_production_prepare", SCRIPTS / "nixos_production_prepare.py")
    prep = importlib.util.module_from_spec(spec)
    assert spec.loader is not None
    spec.loader.exec_module(prep)
finally:
    sys.path.pop(0)

REVISION = "a" * 40
SYSTEM_PATH = "/nix/store/" + "0" * 32 + "-nixos-system-heim-pc-26.05-test"
NIX_VOLUME = "heim-pc-nixos-production-" + REVISION[:12]
SOURCE_VOLUME = "heim-pc-nixos-source-" + REVISION[:12]


class Result:
    def __init__(self, stdout=b"", returncode=0, stderr=b""):
        self.stdout = stdout
        self.returncode = returncode
        self.stderr = stderr


def test_volume_names_are_revision_bound():
    assert prep.volume_names(REVISION) == (NIX_VOLUME, SOURCE_VOLUME)
    with pytest.raises(prep.PrepareError, match="invalid exact revision"):
        prep.volume_names("main")


def test_make_artifact_uses_pinned_image_and_exact_profile():
    artifact = prep.make_artifact(
        revision=REVISION,
        system_path=SYSTEM_PATH,
        nix_volume=NIX_VOLUME,
        bundle_sha256="b" * 64,
    )
    assert artifact == {
        "schema_version": 1,
        "kind": "heim_pc.nixos_production_install_artifact",
        "source_revision": REVISION,
        "system_path": SYSTEM_PATH,
        "nix_volume": NIX_VOLUME,
        "nix_image": prep.installer.PINNED_NIX_IMAGE,
        "profile": "heim-pc-storage-target",
        "source_bundle_sha256": "b" * 64,
    }


def test_nix_argv_binds_exact_source_and_dedicated_nix_volume():
    argv = prep.nix_argv(
        source_volume=SOURCE_VOLUME,
        nix_volume=NIX_VOLUME,
        args=["flake", "check", "/source/repo"],
        network_none=True,
    )
    assert argv == [
        "docker", "run", "--rm", "--network", "none",
        "-v", f"{SOURCE_VOLUME}:/source:ro",
        "-v", f"{NIX_VOLUME}:/nix",
        "--entrypoint", prep.NIX_BIN,
        prep.installer.PINNED_NIX_IMAGE,
        "--extra-experimental-features", "nix-command flakes",
        "flake", "check", "/source/repo",
    ]


def test_exact_source_revision_requires_clean_head(monkeypatch, tmp_path):
    responses = iter([Result((REVISION + "\n").encode()), Result(b"")])
    monkeypatch.setattr(prep, "run", lambda argv, check=True: next(responses))
    assert prep.exact_source_revision(tmp_path) == REVISION

    responses = iter([Result((REVISION + "\n").encode()), Result(b" M README.md\n")])
    monkeypatch.setattr(prep, "run", lambda argv, check=True: next(responses))
    with pytest.raises(prep.PrepareError, match="clean Git source"):
        prep.exact_source_revision(tmp_path)


def test_existing_volume_is_rejected(monkeypatch):
    monkeypatch.setattr(prep, "run", lambda argv, check=True: Result(b"[]", returncode=0))
    with pytest.raises(prep.PrepareError, match="refusing existing production build volume"):
        prep.ensure_volume_absent(NIX_VOLUME)


def test_write_artifact_is_create_only_and_private(tmp_path):
    artifact = prep.make_artifact(
        revision=REVISION,
        system_path=SYSTEM_PATH,
        nix_volume=NIX_VOLUME,
        bundle_sha256="b" * 64,
    )
    target = tmp_path / "artifact.json"
    prep.write_artifact(target, artifact)
    assert json.loads(target.read_text()) == artifact
    assert target.stat().st_mode & 0o777 == 0o600
    with pytest.raises(prep.PrepareError, match="refusing to overwrite"):
        prep.write_artifact(target, artifact)


def test_build_exact_closure_runs_check_then_build(monkeypatch):
    calls = []
    def fake_run(argv, check=True):
        calls.append(argv)
        if "build" in argv:
            return Result((SYSTEM_PATH + "\n").encode())
        return Result()
    monkeypatch.setattr(prep, "run", fake_run)
    result = prep.build_exact_closure(source_volume=SOURCE_VOLUME, nix_volume=NIX_VOLUME)
    assert result == SYSTEM_PATH
    assert len(calls) == 2
    assert "flake" in calls[0] and "check" in calls[0]
    assert "build" in calls[1]
    assert "#nixosConfigurations.heim-pc-storage-target.config.system.build.toplevel" in " ".join(calls[1])


def test_verify_closure_checks_only_exact_closure_in_offline_container(monkeypatch):
    calls = []
    monkeypatch.setattr(prep, "run", lambda argv, check=True: calls.append(argv) or Result())
    prep.verify_closure(nix_volume=NIX_VOLUME, system_path=SYSTEM_PATH)
    assert len(calls) == 4
    for argv in calls:
        assert argv[:5] == ["docker", "run", "--rm", "--network", "none"]
        assert f"{NIX_VOLUME}:/nix:ro" in argv
        assert prep.installer.PINNED_NIX_IMAGE in argv
        assert argv[argv.index("--entrypoint") + 1].startswith(SYSTEM_PATH + "/sw/bin/")


def test_prepare_source_contains_no_block_mutation_surface():
    source = (SCRIPTS / "nixos_production_prepare.py").read_text()
    for forbidden in ("sgdisk", "cryptsetup", "mkfs.fat", "mkfs.ext4", "/dev/nvme"):
        assert forbidden not in source


def test_prepare_failure_removes_created_volumes_and_does_not_publish_artifact(monkeypatch, tmp_path):
    output = tmp_path / "artifact.json"
    removed = []
    created = []
    monkeypatch.setattr(prep, "exact_source_revision", lambda repo: REVISION)
    monkeypatch.setattr(prep, "image_gate", lambda: None)
    monkeypatch.setattr(prep, "ensure_volume_absent", lambda name: None)
    monkeypatch.setattr(prep, "create_volume", lambda name: created.append(name))
    monkeypatch.setattr(prep, "remove_volume", lambda name: removed.append(name))
    def fake_run(argv, check=True):
        if len(argv) >= 6 and argv[0] == "git" and "bundle" in argv and "create" in argv:
            Path(argv[-2]).write_bytes(b"fake-bundle")
        return Result()
    monkeypatch.setattr(prep, "run", fake_run)
    monkeypatch.setattr(prep, "clone_bundle_to_volume", lambda **kwargs: None)
    monkeypatch.setattr(prep, "build_exact_closure", lambda **kwargs: (_ for _ in ()).throw(prep.PrepareError("boom")))
    with pytest.raises(prep.PrepareError, match="boom"):
        prep.prepare(repo=tmp_path, output=output)
    assert created == [NIX_VOLUME, SOURCE_VOLUME]
    assert removed == [SOURCE_VOLUME, NIX_VOLUME]
    assert not output.exists()
