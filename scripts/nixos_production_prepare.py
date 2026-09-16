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
import re
import sqlite3
import stat
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
MANAGED_NIX_CONTAINER_LABEL_ENV = "HEIM_PC_MANAGED_NIX_CONTAINER_LABEL"
MANAGED_NIX_CONTAINER_LABEL_RE = re.compile(r"^heim-pc\.managed-nix=[0-9a-f]{64}-[0-9a-f]{12}$")


class PrepareError(RuntimeError):
    pass


def run(argv: list[str], *, check: bool = True) -> subprocess.CompletedProcess[bytes]:
    argv = list(argv)
    managed_label = os.environ.get(MANAGED_NIX_CONTAINER_LABEL_ENV)
    if managed_label is not None:
        if MANAGED_NIX_CONTAINER_LABEL_RE.fullmatch(managed_label) is None:
            raise PrepareError("managed Nix container label is invalid")
        if argv[:2] == ["docker", "run"]:
            argv[2:2] = ["--label", managed_label]
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
    inspected = run(["docker", "volume", "inspect", name], check=False)
    if inspected.returncode == 0:
        raise PrepareError(f"refusing existing production build volume: {name}")
    # A failed inspect alone is ambiguous (missing object vs daemon/transport
    # failure). Require a successful daemon-wide listing and exact-name absence
    # before treating the volume as absent.
    listed = run(["docker", "volume", "ls", "--quiet"])
    names = {line.strip() for line in listed.stdout.decode("utf-8", "strict").splitlines()}
    if name in names:
        raise PrepareError(f"refusing existing production build volume: {name}")


def create_volume(name: str, *, backing_dir: Path | None = None) -> None:
    argv = ["docker", "volume", "create"]
    if backing_dir is not None:
        if (
            not backing_dir.is_absolute()
            or backing_dir.is_symlink()
            or not backing_dir.is_dir()
            or os.path.normpath(str(backing_dir)) != str(backing_dir)
        ):
            raise PrepareError("managed Nix backing directory is unsafe")
        argv += [
            "--driver", "local", "--opt", "type=none", "--opt", "o=bind",
            "--opt", f"device={backing_dir}",
        ]
    created = run([*argv, name]).stdout.decode().strip()
    if created != name:
        raise PrepareError(f"Docker created unexpected volume identity for {name}")


def remove_volume(name: str) -> None:
    removed = run(["docker", "volume", "rm", "-f", name], check=False)
    if removed.returncode != 0:
        stderr = removed.stderr.decode("utf-8", "replace")[-8000:]
        raise PrepareError(f"failed to remove production build volume {name}: {stderr}")
    ensure_volume_absent(name)


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


def _managed_nix_db_snapshot(
    *, managed_nix_store_root: Path, destination: Path, system_path: str
) -> Path:
    """Materialize current SQLite state without checkpointing the managed store.

    Nix read-only-local-store deliberately opens db.sqlite as immutable, which
    ignores WAL-only registrations. The managed build lock already excludes a
    second writer, so take one SQLite backup through a read-only WAL-aware
    connection and expose only that private snapshot to the immutable verifier.
    """
    root_text = str(managed_nix_store_root)
    if (
        not managed_nix_store_root.is_absolute()
        or managed_nix_store_root.is_symlink()
        or not managed_nix_store_root.is_dir()
        or os.path.normpath(root_text) != root_text
    ):
        raise PrepareError("managed Nix store root is unsafe for verification snapshot")
    if installer.SYSTEM_PATH_RE.fullmatch(system_path) is None:
        raise PrepareError("managed Nix verification snapshot system path is invalid")
    if (
        not destination.is_absolute()
        or destination.exists()
        or destination.is_symlink()
        or os.path.normpath(str(destination)) != str(destination)
    ):
        raise PrepareError("managed Nix verification snapshot destination is unsafe")

    source = managed_nix_store_root / "var" / "nix" / "db" / "db.sqlite"
    try:
        before = source.lstat()
    except OSError as exc:
        raise PrepareError("managed Nix database is unavailable for verification snapshot") from exc
    if (
        not stat.S_ISREG(before.st_mode)
        or stat.S_ISLNK(before.st_mode)
        or before.st_nlink != 1
        or before.st_size <= 0
    ):
        raise PrepareError("managed Nix database identity is unsafe for verification snapshot")

    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_CLOEXEC
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    descriptor = os.open(destination, flags, 0o600)
    os.close(descriptor)
    try:
        source_db = None
        snapshot_db = None
        try:
            source_db = sqlite3.connect(source.as_uri() + "?mode=ro", uri=True)
            snapshot_db = sqlite3.connect(str(destination))
            source_db.backup(snapshot_db)
        finally:
            if snapshot_db is not None:
                snapshot_db.close()
            if source_db is not None:
                source_db.close()

        after = source.lstat()
        before_identity = (
            before.st_dev, before.st_ino, before.st_mode, before.st_uid, before.st_gid,
            before.st_nlink, before.st_size, before.st_mtime_ns,
        )
        after_identity = (
            after.st_dev, after.st_ino, after.st_mode, after.st_uid, after.st_gid,
            after.st_nlink, after.st_size, after.st_mtime_ns,
        )
        if after_identity != before_identity:
            raise PrepareError("managed Nix database identity changed during verification snapshot")

        os.chmod(destination, 0o400)
        read_flags = os.O_RDONLY | os.O_CLOEXEC
        if hasattr(os, "O_NOFOLLOW"):
            read_flags |= os.O_NOFOLLOW
        descriptor = os.open(destination, read_flags)
        try:
            snapshot_stat = os.fstat(descriptor)
            if (
                not stat.S_ISREG(snapshot_stat.st_mode)
                or snapshot_stat.st_uid != os.getuid()
                or snapshot_stat.st_nlink != 1
                or stat.S_IMODE(snapshot_stat.st_mode) != 0o400
            ):
                raise PrepareError("managed Nix verification snapshot identity is unsafe")
            os.fsync(descriptor)
        finally:
            os.close(descriptor)
        _fsync_directory(destination.parent)

        immutable = sqlite3.connect(destination.as_uri() + "?immutable=1", uri=True)
        try:
            row = immutable.execute(
                "select 1 from ValidPaths where path = ? limit 1", (system_path,)
            ).fetchone()
        finally:
            immutable.close()
        if row is None:
            raise PrepareError("managed Nix verification snapshot lacks the built system path")
    except PrepareError:
        destination.unlink(missing_ok=True)
        raise
    except (OSError, sqlite3.Error) as exc:
        destination.unlink(missing_ok=True)
        raise PrepareError("managed Nix verification snapshot failed") from exc
    return destination


def readonly_nix_argv(
    *, nix_volume: str, args: list[str], db_snapshot: Path | None = None
) -> list[str]:
    argv = [
        "docker", "run", "--rm", "--network", "none",
        "-v", f"{nix_volume}:/subject/nix:ro",
    ]
    if db_snapshot is not None:
        try:
            snapshot_stat = db_snapshot.lstat()
        except OSError as exc:
            raise PrepareError("managed Nix verification snapshot is unavailable") from exc
        if (
            not db_snapshot.is_absolute()
            or os.path.normpath(str(db_snapshot)) != str(db_snapshot)
            or not stat.S_ISREG(snapshot_stat.st_mode)
            or stat.S_ISLNK(snapshot_stat.st_mode)
            or snapshot_stat.st_uid != os.getuid()
            or snapshot_stat.st_nlink != 1
            or stat.S_IMODE(snapshot_stat.st_mode) != 0o400
        ):
            raise PrepareError("managed Nix verification snapshot is unsafe")
        argv += [
            "-v", f"{db_snapshot}:/subject/nix/var/nix/db/db.sqlite:ro",
        ]
    argv += [
        "--entrypoint", NIX_BIN,
        installer.PINNED_NIX_IMAGE,
        "--extra-experimental-features", installer.READONLY_NIX_FEATURES,
        "--store", installer.READONLY_NIX_STORE,
        *args,
    ]
    return argv


def capture_closure_manifest(
    *, nix_volume: str, system_path: str, db_snapshot: Path | None = None
) -> dict[str, object]:
    result = run(readonly_nix_argv(
        nix_volume=nix_volume, db_snapshot=db_snapshot,
        args=["path-info", "--json", "--recursive", system_path],
    ))
    try:
        payload = json.loads(result.stdout.decode("utf-8"))
    except json.JSONDecodeError as exc:
        raise PrepareError("invalid JSON from Nix closure path-info") from exc
    return installer.closure_manifest_metadata(payload)


def verify_closure(
    *, nix_volume: str, system_path: str, db_snapshot: Path | None = None
) -> None:
    run(readonly_nix_argv(
        nix_volume=nix_volume, db_snapshot=db_snapshot,
        args=["store", "verify", "--no-trust", "--recursive", system_path],
    ))
    checks = [
        ("-x", f"{system_path}/sw/bin/nix"),
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
    *, repo: Path, output: Path, source_authority: str = "proof-only",
    managed_nix_store_root: Path | None = None,
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
            create_volume(nix_volume, backing_dir=managed_nix_store_root)
            nix_created = True
            create_volume(source_volume)
            source_created = True
            clone_bundle_to_volume(bundle=bundle, source_volume=source_volume, revision=revision)
            system_path = build_exact_closure(source_volume=source_volume, nix_volume=nix_volume)
            db_snapshot = None
            if managed_nix_store_root is not None:
                db_snapshot = _managed_nix_db_snapshot(
                    managed_nix_store_root=managed_nix_store_root,
                    destination=Path(tmp) / "nix-verification-db.sqlite",
                    system_path=system_path,
                )
            verify_closure(
                nix_volume=nix_volume, system_path=system_path, db_snapshot=db_snapshot,
            )
            closure = capture_closure_manifest(
                nix_volume=nix_volume, system_path=system_path, db_snapshot=db_snapshot,
            )
            artifact = make_artifact(
                revision=revision,
                system_path=system_path,
                nix_volume=nix_volume,
                bundle_sha256=bundle_sha,
                closure_manifest_sha256=str(closure["closure_manifest_sha256"]),
                closure_path_count=int(closure["closure_path_count"]),
                source_authority=source_authority,
            )
            # The transient source clone is outside the retained Nix-volume
            # budget. Its successful, observed removal is part of completion,
            # not best-effort hygiene after artifact publication.
            remove_volume(source_volume)
            source_created = False
            write_artifact(output, artifact)
            success = True
            return artifact
        finally:
            if source_created:
                try:
                    remove_volume(source_volume)
                finally:
                    if nix_created and not success:
                        remove_volume(nix_volume)
            elif nix_created and not success:
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
        "--tool", "nix",
        "--profile", MANAGED_PROFILE,
        "--",
        sys.executable,
        str(Path(__file__).resolve()),
        "--managed-worker",
        "--repo", str(repo),
        "--output", str(output),
        "--source-authority", source_authority,
    ]


def _managed_worker_parent_argv_valid(
    parent_argv: list[str], *, repo: Path, output: Path, source_authority: str
) -> bool:
    return parent_argv == managed_prepare_argv(
        operation="run", repo=repo, output=output, source_authority=source_authority
    )


def _managed_worker_context_valid(
    *, repo: Path, output: Path, source_authority: str
) -> bool:
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
    return _managed_worker_parent_argv_valid(
        parent_argv, repo=repo, output=output, source_authority=source_authority
    )


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
    if not _managed_worker_context_valid(
        repo=repo, output=output, source_authority=args.source_authority
    ):
        print(
            "nixos production artifact preparation blocked by a safety check",
            file=sys.stderr,
        )
        return 2
    try:
        managed_store_raw = os.environ.get("HEIM_PC_MANAGED_NIX_STORE_ROOT")
        if not managed_store_raw:
            raise PrepareError("managed Nix worker lacks its managed store root")
        artifact = prepare(
            repo=repo, output=output, source_authority=args.source_authority,
            managed_nix_store_root=Path(managed_store_raw),
        )
        print(json.dumps(artifact, indent=2, sort_keys=True))
        return 0
    except (PrepareError, installer.ProductionInstallError, OSError):
        print("nixos production artifact preparation blocked by a safety check", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
