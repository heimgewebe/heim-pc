#!/usr/bin/env python3
"""Build an exact, revision-bound NixOS production install artifact in Docker.

This prepares the immutable source closure only. It never reads or mutates block
storage. The resulting JSON points at a dedicated Docker /nix volume consumed by
nixos_production_install.py for the later offline Seagate installation.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
import subprocess
import sys
import tempfile
from pathlib import Path

import nixos_production_install as installer

ROOT = Path(__file__).resolve().parents[1]
FLAKE = ROOT
NIX_BIN = "/nix/var/nix/profiles/default/bin/nix"
GIT_BIN = "/root/.nix-profile/bin/git"
MANAGED_BUILD = ROOT / "scripts" / "managed_build.py"
MANAGED_WORKER_ENV = "HEIM_PC_NIXOS_PRODUCTION_PREPARE_MANAGED"
MANAGED_PROFILE = "nixos-production-prepare"


class PrepareError(RuntimeError):
    pass


def run(argv: list[str], *, check: bool = True) -> subprocess.CompletedProcess[bytes]:
    command_env = {
        "PATH": installer.TRUSTED_PATH,
        "LC_ALL": "C",
        "LANG": "C",
        "HOME": "/",
        "SYSTEMD_COLORS": "0",
    }
    result = subprocess.run(
        argv, stdout=subprocess.PIPE, stderr=subprocess.PIPE, check=False, env=command_env
    )
    if check and result.returncode != 0:
        stderr = result.stderr.decode("utf-8", "replace")[-8000:]
        raise PrepareError(f"command failed ({argv[0]}): {stderr}")
    return result


def exact_source_revision(repo: Path) -> str:
    head = run(["git", "-C", str(repo), "rev-parse", "HEAD"]).stdout.decode().strip()
    if installer.SOURCE_REVISION_RE.fullmatch(head) is None:
        raise PrepareError("source HEAD is not exact 40-hex")
    if run(["git", "-C", str(repo), "status", "--porcelain"]).stdout:
        raise PrepareError("production artifact requires a clean Git source")
    return head


def verify_promoted_main(repo: Path, revision: str) -> None:
    if installer.SOURCE_REVISION_RE.fullmatch(revision) is None:
        raise PrepareError("promoted source revision must be exact 40-hex")
    run([
        "git", "-C", str(repo), "fetch", "--quiet", "--no-tags", "origin",
        "+refs/heads/main:refs/remotes/origin/main",
    ])
    observed = run([
        "git", "-C", str(repo), "rev-parse", "refs/remotes/origin/main"
    ]).stdout.decode().strip()
    if installer.SOURCE_REVISION_RE.fullmatch(observed) is None or observed != revision:
        raise PrepareError("production artifact source is not the freshly fetched origin/main")


def volume_names(revision: str) -> tuple[str, str]:
    if installer.SOURCE_REVISION_RE.fullmatch(revision) is None:
        raise PrepareError("invalid exact revision")
    short = revision[:12]
    return f"heim-pc-nixos-production-{short}", f"heim-pc-nixos-source-{short}"


def make_artifact(
    *, revision: str, system_path: str, nix_volume: str, bundle_sha256: str,
    closure_manifest_sha256: str, closure_path_count: int,
    source_authority: str = "proof-only",
) -> dict[str, object]:
    value = {
        "schema_version": 1,
        "kind": "heim_pc.nixos_production_install_artifact",
        "source_revision": revision,
        "system_path": system_path,
        "nix_volume": nix_volume,
        "nix_image": installer.PINNED_NIX_IMAGE,
        "profile": "heim-pc-storage-target",
        "source_authority": source_authority,
        "source_bundle_sha256": bundle_sha256,
        "closure_manifest_sha256": closure_manifest_sha256,
        "closure_path_count": closure_path_count,
    }
    return installer.validate_install_artifact(value)


def image_gate() -> None:
    actual = run(["docker", "image", "inspect", "--format", "{{.Id}}", installer.PINNED_NIX_IMAGE]).stdout.decode().strip()
    if actual != installer.PINNED_NIX_IMAGE:
        raise PrepareError("pinned Nix image identity mismatch")


def ensure_volume_absent(name: str) -> None:
    if run(["docker", "volume", "inspect", name], check=False).returncode == 0:
        raise PrepareError(f"refusing existing production build volume: {name}")


def create_volume(name: str) -> None:
    created = run(["docker", "volume", "create", name]).stdout.decode().strip()
    if created != name:
        raise PrepareError(f"Docker created unexpected volume identity for {name}")


def remove_volume(name: str) -> None:
    run(["docker", "volume", "rm", "-f", name], check=False)


def clone_bundle_to_volume(*, bundle: Path, source_volume: str, revision: str) -> None:
    bind = f"{bundle.parent}:/input:ro"
    source = f"{source_volume}:/source"
    run([
        "docker", "run", "--rm", "--network", "none",
        "-v", bind, "-v", source,
        "--entrypoint", GIT_BIN, installer.PINNED_NIX_IMAGE,
        "clone", "/input/source.bundle", "/source/repo",
    ])
    run([
        "docker", "run", "--rm", "--network", "none",
        "-v", source,
        "--entrypoint", GIT_BIN, installer.PINNED_NIX_IMAGE,
        "-C", "/source/repo", "checkout", "--detach", revision,
    ])
    actual = run([
        "docker", "run", "--rm", "--network", "none",
        "-v", f"{source_volume}:/source:ro",
        "--entrypoint", GIT_BIN, installer.PINNED_NIX_IMAGE,
        "-C", "/source/repo", "rev-parse", "HEAD",
    ]).stdout.decode().strip()
    if actual != revision:
        raise PrepareError("container source revision mismatch")
    dirty = run([
        "docker", "run", "--rm", "--network", "none",
        "-v", f"{source_volume}:/source:ro",
        "--entrypoint", GIT_BIN, installer.PINNED_NIX_IMAGE,
        "-C", "/source/repo", "status", "--porcelain",
    ]).stdout
    if dirty:
        raise PrepareError("container source clone is unexpectedly dirty")


def nix_argv(*, source_volume: str, nix_volume: str, args: list[str], network_none: bool = False) -> list[str]:
    argv = ["docker", "run", "--rm"]
    if network_none:
        argv += ["--network", "none"]
    argv += [
        "-v", f"{source_volume}:/source:ro",
        "-v", f"{nix_volume}:/nix",
        "--entrypoint", NIX_BIN,
        installer.PINNED_NIX_IMAGE,
    ]
    return argv + ["--extra-experimental-features", "nix-command flakes"] + args


def build_exact_closure(*, source_volume: str, nix_volume: str) -> str:
    flake = "/source/repo"
    run(nix_argv(
        source_volume=source_volume,
        nix_volume=nix_volume,
        args=["flake", "check", "--no-build", "--no-update-lock-file", flake],
    ))
    result = run(nix_argv(
        source_volume=source_volume,
        nix_volume=nix_volume,
        args=[
            "build",
            f"{flake}#nixosConfigurations.heim-pc-storage-target.config.system.build.toplevel",
            "--no-link",
            "--print-out-paths",
            "--no-update-lock-file",
        ],
    ))
    paths = [line.strip() for line in result.stdout.decode().splitlines() if line.strip().startswith("/nix/store/")]
    if len(paths) != 1:
        raise PrepareError(f"expected exactly one NixOS system path, got {paths!r}")
    system_path = paths[0]
    if installer.SYSTEM_PATH_RE.fullmatch(system_path) is None:
        raise PrepareError(f"unexpected Heim-PC system closure path: {system_path}")
    return system_path


def readonly_nix_argv(*, nix_volume: str, args: list[str]) -> list[str]:
    return [
        "docker", "run", "--rm", "--network", "none",
        "-v", f"{nix_volume}:/subject/nix:ro",
        "--entrypoint", NIX_BIN,
        installer.PINNED_NIX_IMAGE,
        "--extra-experimental-features", installer.READONLY_NIX_FEATURES,
        "--store", installer.READONLY_NIX_STORE,
        *args,
    ]


def capture_closure_manifest(*, nix_volume: str, system_path: str) -> dict[str, object]:
    result = run(readonly_nix_argv(
        nix_volume=nix_volume,
        args=["path-info", "--json", "--recursive", system_path],
    ))
    try:
        payload = json.loads(result.stdout.decode("utf-8"))
    except json.JSONDecodeError as exc:
        raise PrepareError("invalid JSON from Nix closure path-info") from exc
    return installer.closure_manifest_metadata(payload)


def verify_closure(*, nix_volume: str, system_path: str) -> None:
    run(readonly_nix_argv(
        nix_volume=nix_volume,
        args=["store", "verify", "--no-trust", "--recursive", system_path],
    ))
    checks = [
        ("-x", f"{system_path}/sw/bin/nixos-install"),
        ("-x", f"{system_path}/sw/bin/mkfs.btrfs"),
        ("-x", f"{system_path}/sw/bin/btrfs"),
        ("-e", f"{system_path}/etc/systemd/system/heim-pc-firstboot-credentials.service"),
    ]
    for mode, target in checks:
        run([
            "docker", "run", "--rm", "--network", "none",
            "-v", f"{nix_volume}:/nix:ro",
            "--entrypoint", f"{system_path}/sw/bin/test",
            installer.PINNED_NIX_IMAGE, mode, target,
        ])


def _fsync_directory(path: Path) -> None:
    flags = os.O_RDONLY
    if hasattr(os, "O_DIRECTORY"):
        flags |= os.O_DIRECTORY
    fd = os.open(path, flags)
    try:
        os.fsync(fd)
    finally:
        os.close(fd)


def write_artifact(path: Path, artifact: dict[str, object]) -> None:
    if path.exists() or path.is_symlink():
        raise PrepareError(f"refusing to overwrite install artifact: {path}")
    path.parent.mkdir(parents=True, exist_ok=True)
    payload = (json.dumps(artifact, indent=2, sort_keys=True) + "\n").encode("utf-8")
    fd, temporary_name = tempfile.mkstemp(
        dir=path.parent, prefix=f".{path.name}.", suffix=".tmp"
    )
    temporary = Path(temporary_name)
    try:
        os.fchmod(fd, 0o600)
        view = memoryview(payload)
        while view:
            written = os.write(fd, view)
            if written <= 0:
                raise PrepareError("short write while creating install artifact")
            view = view[written:]
        os.fsync(fd)
        os.close(fd)
        fd = -1
        try:
            os.link(temporary, path, follow_symlinks=False)
        except FileExistsError as exc:
            raise PrepareError(f"refusing to overwrite install artifact: {path}") from exc
        _fsync_directory(path.parent)
    finally:
        if fd >= 0:
            os.close(fd)
        temporary.unlink(missing_ok=True)


def prepare(
    *, repo: Path, output: Path, source_authority: str = "proof-only"
) -> dict[str, object]:
    revision = exact_source_revision(repo)
    if source_authority not in installer.INSTALL_ARTIFACT_AUTHORITIES:
        raise PrepareError("invalid install artifact source authority")
    if source_authority == "merged-main":
        verify_promoted_main(repo, revision)
    image_gate()
    nix_volume, source_volume = volume_names(revision)
    ensure_volume_absent(nix_volume)
    ensure_volume_absent(source_volume)
    if output.exists() or output.is_symlink():
        raise PrepareError(f"refusing existing output: {output}")

    nix_created = False
    source_created = False
    success = False
    with tempfile.TemporaryDirectory(prefix="heim-pc-nixos-production-") as tmp:
        bundle = Path(tmp) / "source.bundle"
        run(["git", "-C", str(repo), "bundle", "create", str(bundle), "HEAD"])
        bundle_sha = hashlib.sha256(bundle.read_bytes()).hexdigest()
        try:
            create_volume(nix_volume)
            nix_created = True
            create_volume(source_volume)
            source_created = True
            clone_bundle_to_volume(bundle=bundle, source_volume=source_volume, revision=revision)
            system_path = build_exact_closure(source_volume=source_volume, nix_volume=nix_volume)
            verify_closure(nix_volume=nix_volume, system_path=system_path)
            closure = capture_closure_manifest(nix_volume=nix_volume, system_path=system_path)
            artifact = make_artifact(
                revision=revision,
                system_path=system_path,
                nix_volume=nix_volume,
                bundle_sha256=bundle_sha,
                closure_manifest_sha256=str(closure["closure_manifest_sha256"]),
                closure_path_count=int(closure["closure_path_count"]),
                source_authority=source_authority,
            )
            write_artifact(output, artifact)
            success = True
            return artifact
        finally:
            if source_created:
                remove_volume(source_volume)
            if nix_created and not success:
                remove_volume(nix_volume)


def managed_prepare_argv(
    *, operation: str, repo: Path, output: Path, source_authority: str
) -> list[str]:
    if operation not in {"plan", "run"}:
        raise PrepareError("invalid managed-build operation")
    return [
        sys.executable,
        str(MANAGED_BUILD),
        operation,
        "--repo", str(repo),
        "--tool", "python",
        "--profile", MANAGED_PROFILE,
        "--",
        "python3",
        str(Path(__file__).resolve()),
        "--managed-worker",
        "--repo", str(repo),
        "--output", str(output),
        "--source-authority", source_authority,
    ]


def _managed_worker_context_valid() -> bool:
    if os.environ.get(MANAGED_WORKER_ENV) != "1":
        return False
    try:
        parent_argv = [
            item.decode("utf-8", "strict")
            for item in Path(f"/proc/{os.getppid()}/cmdline").read_bytes().split(b"\0")
            if item
        ]
    except (OSError, UnicodeDecodeError):
        return False
    return str(MANAGED_BUILD) in parent_argv and "run" in parent_argv


def run_managed_prepare(
    *, repo: Path, output: Path, source_authority: str
) -> int:
    environment = os.environ.copy()
    environment[MANAGED_WORKER_ENV] = "1"
    planned = subprocess.run(
        managed_prepare_argv(
            operation="plan", repo=repo, output=output, source_authority=source_authority
        ),
        check=False,
        env=environment,
    )
    if planned.returncode != 0:
        return int(planned.returncode)
    return int(
        subprocess.run(
            managed_prepare_argv(
                operation="run", repo=repo, output=output, source_authority=source_authority
            ),
            check=False,
            env=environment,
        ).returncode
    )


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--repo", type=Path, default=ROOT)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument(
        "--source-authority",
        choices=sorted(installer.INSTALL_ARTIFACT_AUTHORITIES),
        default="proof-only",
    )
    parser.add_argument("--managed-worker", action="store_true", help=argparse.SUPPRESS)
    args = parser.parse_args(argv)
    repo = args.repo.resolve()
    output = args.output.resolve()
    if not args.managed_worker:
        try:
            return run_managed_prepare(
                repo=repo, output=output, source_authority=args.source_authority
            )
        except OSError:
            print(
                "nixos production artifact preparation blocked by a safety check",
                file=sys.stderr,
            )
            return 2
    if not _managed_worker_context_valid():
        print(
            "nixos production artifact preparation blocked by a safety check",
            file=sys.stderr,
        )
        return 2
    try:
        artifact = prepare(
            repo=repo, output=output, source_authority=args.source_authority
        )
        print(json.dumps(artifact, indent=2, sort_keys=True))
        return 0
    except (PrepareError, installer.ProductionInstallError, OSError):
        print("nixos production artifact preparation blocked by a safety check", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
