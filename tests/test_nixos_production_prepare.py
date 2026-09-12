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
CLOSURE_SHA = "c" * 64
CLOSURE_COUNT = 42


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
        closure_manifest_sha256=CLOSURE_SHA,
        closure_path_count=CLOSURE_COUNT,
    )
    assert artifact == {
        "schema_version": 1,
        "kind": "heim_pc.nixos_production_install_artifact",
        "source_revision": REVISION,
        "system_path": SYSTEM_PATH,
        "nix_volume": NIX_VOLUME,
        "nix_image": prep.installer.PINNED_NIX_IMAGE,
        "profile": "heim-pc-storage-target",
        "source_authority": "proof-only",
        "source_bundle_sha256": "b" * 64,
        "closure_manifest_sha256": CLOSURE_SHA,
        "closure_path_count": CLOSURE_COUNT,
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


def test_managed_nix_volume_is_bound_to_managed_backing_directory(monkeypatch, tmp_path):
    calls = []
    backing = tmp_path / "store"
    backing.mkdir()
    monkeypatch.setattr(prep, "run", lambda argv, check=True: calls.append(argv) or Result((NIX_VOLUME + "\n").encode()))
    prep.create_volume(NIX_VOLUME, backing_dir=backing)
    argv = calls[0]
    assert argv[:3] == ["docker", "volume", "create"]
    assert ["--driver", "local"] == argv[3:5]
    assert f"device={backing}" in argv
    assert argv[-1] == NIX_VOLUME


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
        closure_manifest_sha256=CLOSURE_SHA,
        closure_path_count=CLOSURE_COUNT,
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


def test_capture_closure_manifest_uses_canonical_path_info(monkeypatch):
    path_info = {SYSTEM_PATH: {"narHash": "sha256-AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=", "narSize": 123, "references": []}}
    calls = []
    monkeypatch.setattr(prep, "run", lambda argv, check=True: calls.append(argv) or Result(json.dumps(path_info).encode()))
    result = prep.capture_closure_manifest(nix_volume=NIX_VOLUME, system_path=SYSTEM_PATH)
    assert result == prep.installer.closure_manifest_metadata(path_info)
    assert "path-info" in calls[0] and "--recursive" in calls[0]
    assert "--network" in calls[0] and "none" in calls[0]
    assert f"{NIX_VOLUME}:/subject/nix:ro" in calls[0]
    assert calls[0][calls[0].index("--store") + 1] == prep.installer.READONLY_NIX_STORE


def test_verify_closure_checks_store_and_exact_closure_in_offline_container(monkeypatch):
    calls = []
    monkeypatch.setattr(prep, "run", lambda argv, check=True: calls.append(argv) or Result())
    prep.verify_closure(nix_volume=NIX_VOLUME, system_path=SYSTEM_PATH)
    assert len(calls) == 6
    assert any(f"{SYSTEM_PATH}/sw/bin/nix" in argv for argv in calls[1:])
    verify = calls[0]
    assert "store" in verify and "verify" in verify and "--no-trust" in verify and "--recursive" in verify
    assert verify[verify.index("--entrypoint") + 1] == prep.NIX_BIN
    assert f"{NIX_VOLUME}:/subject/nix:ro" in verify
    assert verify[verify.index("--store") + 1] == prep.installer.READONLY_NIX_STORE
    for argv in calls[1:]:
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
    monkeypatch.setattr(prep, "create_volume", lambda name, **kwargs: created.append((name, kwargs.get("backing_dir"))))
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
    assert created == [(NIX_VOLUME, None), (SOURCE_VOLUME, None)]
    assert removed == [SOURCE_VOLUME, NIX_VOLUME]
    assert not output.exists()


def test_run_uses_fixed_trusted_environment(monkeypatch):
    captured = {}

    def fake_run(*args, **kwargs):
        captured.update(kwargs)
        return Result()

    monkeypatch.setattr(prep.subprocess, "run", fake_run)
    prep.run(["git", "--version"])
    assert captured["env"]["PATH"] == prep.installer.TRUSTED_PATH
    assert captured["env"]["HOME"] == "/"
    assert set(captured["env"]) == {"PATH", "LC_ALL", "LANG", "HOME", "SYSTEMD_COLORS"}


def test_prepare_main_never_surfaces_exception_text(monkeypatch, tmp_path, capsys):
    monkeypatch.setattr(
        prep, "prepare",
        lambda **kwargs: (_ for _ in ()).throw(prep.PrepareError("super-secret-material")),
    )
    monkeypatch.setenv(prep.MANAGED_WORKER_ENV, "1")
    monkeypatch.setattr(prep, "_managed_worker_context_valid", lambda **_kwargs: True)
    assert prep.main([
        "--managed-worker", "--repo", str(tmp_path),
        "--output", str(tmp_path / "artifact.json"),
    ]) == 2
    captured = capsys.readouterr()
    assert captured.err == "nixos production artifact preparation blocked by a safety check\n"
    assert "super-secret-material" not in captured.err


def test_merged_main_authority_fetches_and_binds_exact_origin_main(monkeypatch, tmp_path):
    calls = []

    def fake_run(argv, check=True):
        calls.append(argv)
        if "rev-parse" in argv:
            return Result((REVISION + "\n").encode())
        return Result()

    monkeypatch.setattr(prep, "run", fake_run)
    prep.verify_promoted_main(tmp_path, REVISION)
    assert calls[0] == [
        "git", "-C", str(tmp_path), "fetch", "--quiet", "--no-tags", "origin",
        "+refs/heads/main:refs/remotes/origin/main",
    ]
    assert calls[1][-1] == "refs/remotes/origin/main"


def test_merged_main_authority_rejects_non_main_head(monkeypatch, tmp_path):
    monkeypatch.setattr(
        prep,
        "run",
        lambda argv, check=True: Result((("b" * 40) + "\n").encode()) if "rev-parse" in argv else Result(),
    )
    with pytest.raises(prep.PrepareError, match="freshly fetched origin/main"):
        prep.verify_promoted_main(tmp_path, REVISION)


def test_managed_prepare_routes_plan_then_run_without_recursive_reexec(monkeypatch, tmp_path):
    calls = []

    class ManagedResult:
        returncode = 0

    def fake_subprocess(argv, **kwargs):
        calls.append((argv, kwargs))
        return ManagedResult()

    monkeypatch.setattr(prep.subprocess, "run", fake_subprocess)
    rc = prep.run_managed_prepare(
        repo=tmp_path, output=tmp_path / "artifact.json", source_authority="proof-only"
    )
    assert rc == 0
    assert len(calls) == 2
    assert "plan" in calls[0][0]
    assert "run" in calls[1][0]
    for argv, kwargs in calls:
        assert str(prep.MANAGED_BUILD) in argv
        assert "--managed-worker" in argv
        assert argv[argv.index("--tool") + 1] == "nix"
        assert kwargs["env"][prep.MANAGED_WORKER_ENV] == "1"


def test_managed_worker_env_alone_cannot_bypass_parent_context(monkeypatch, tmp_path):
    monkeypatch.setenv(prep.MANAGED_WORKER_ENV, "1")
    output = tmp_path / "artifact.json"
    assert prep._managed_worker_context_valid(
        repo=tmp_path, output=output, source_authority="proof-only"
    ) is False


def test_managed_worker_parent_must_match_exact_nix_run_argv(tmp_path):
    output = tmp_path / "artifact.json"
    expected = prep.managed_prepare_argv(
        operation="run", repo=tmp_path, output=output, source_authority="proof-only"
    )
    assert prep._managed_worker_parent_argv_valid(
        expected, repo=tmp_path, output=output, source_authority="proof-only"
    ) is True
    tampered = list(expected)
    tampered[tampered.index("--tool") + 1] = "python"
    assert prep._managed_worker_parent_argv_valid(
        tampered, repo=tmp_path, output=output, source_authority="proof-only"
    ) is False


def test_unmanaged_worker_invocation_is_blocked(monkeypatch, tmp_path, capsys):
    monkeypatch.delenv(prep.MANAGED_WORKER_ENV, raising=False)
    assert prep.main([
        "--managed-worker", "--repo", str(tmp_path),
        "--output", str(tmp_path / "artifact.json"),
    ]) == 2
    assert "blocked by a safety check" in capsys.readouterr().err


def test_artifact_publication_leaves_no_final_file_on_short_write(monkeypatch, tmp_path):
    artifact = prep.make_artifact(
        revision=REVISION,
        system_path=SYSTEM_PATH,
        nix_volume=NIX_VOLUME,
        bundle_sha256="b" * 64,
        closure_manifest_sha256=CLOSURE_SHA,
        closure_path_count=CLOSURE_COUNT,
    )
    target = tmp_path / "artifact.json"
    real_write = prep.os.write
    count = {"value": 0}

    def failing_write(fd, data):
        count["value"] += 1
        if count["value"] > 1:
            raise OSError("synthetic write failure")
        return min(1, len(data)) if data else real_write(fd, data)

    monkeypatch.setattr(prep.os, "write", failing_write)
    with pytest.raises(OSError, match="synthetic write failure"):
        prep.write_artifact(target, artifact)
    assert not target.exists()
    assert not list(tmp_path.glob(".artifact.json.*.tmp"))


def test_managed_nix_container_label_is_injected_only_into_docker_run(monkeypatch):
    calls = []
    label = "heim-pc.managed-nix=" + "a" * 64 + "-" + "b" * 12
    monkeypatch.setenv(prep.MANAGED_NIX_CONTAINER_LABEL_ENV, label)

    class Result:
        returncode = 0
        stdout = b""
        stderr = b""

    monkeypatch.setattr(prep.subprocess, "run", lambda argv, **kwargs: calls.append(argv) or Result())
    prep.run(["docker", "run", "--rm", "image", "true"] )
    prep.run(["git", "status"] )
    assert calls[0][:4] == ["docker", "run", "--label", label]
    assert "--label" not in calls[1]


def test_managed_nix_container_label_rejects_untrusted_value(monkeypatch):
    monkeypatch.setenv(prep.MANAGED_NIX_CONTAINER_LABEL_ENV, "not-a-managed-label")
    with pytest.raises(prep.PrepareError, match="container label"):
        prep.run(["docker", "run", "--rm", "image", "true"] )
