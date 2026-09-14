#!/usr/bin/env python3
"""Install the subscription-only Grok Build launcher into ~/.local/bin."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import stat
import sys
import tempfile
from pathlib import Path

WRAPPER = b'''#!/usr/bin/env bash
set -euo pipefail

# Fail closed onto the grok.com OAuth/Device-Auth subscription surface. Remove
# both current and compatibility API-key variables and make Grok itself reject
# the Grok.com API-key authentication fallback.
unset XAI_API_KEY
unset GROK_CODE_XAI_API_KEY
export GROK_DISABLE_API_KEY_AUTH=1

target="${HOME}/.npm-global/bin/grok"
if [[ ! -x "$target" ]]; then
  printf 'grok: official npm entrypoint is missing or not executable: %s\\n' "$target" >&2
  exit 127
fi
if [[ "$(readlink -f "$target")" == "$(readlink -f "$0")" ]]; then
  printf 'grok: refusing recursive launcher target: %s\\n' "$target" >&2
  exit 126
fi

# Execute the package-owned entrypoint as-is. It may be a script, symlink, or
# native ELF binary; the wrapper must never force it through Node.
exec "$target" "$@"
'''


class InstallConflict(RuntimeError):
    pass


def _sha256(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def _read_regular(path: Path) -> bytes | None:
    if path.is_symlink():
        raise InstallConflict(f"refusing symlink target: {path}")
    if not path.exists():
        return None
    if not path.is_file():
        raise InstallConflict(f"refusing non-file target: {path}")
    return path.read_bytes()


def _chmod_unchanged_regular(path: Path, expected: bytes, mode: int) -> None:
    flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0)
    no_follow = getattr(os, "O_NOFOLLOW", None)
    if no_follow is None:
        raise InstallConflict("platform lacks O_NOFOLLOW; refusing launcher revalidation")
    try:
        descriptor = os.open(path, flags | no_follow)
    except OSError as exc:
        raise InstallConflict(f"cannot safely reopen unchanged target {path}: {exc}") from exc
    try:
        metadata = os.fstat(descriptor)
        if not stat.S_ISREG(metadata.st_mode):
            raise InstallConflict(f"unchanged target is not a regular file: {path}")
        chunks: list[bytes] = []
        while True:
            chunk = os.read(descriptor, 65536)
            if not chunk:
                break
            chunks.append(chunk)
        if b"".join(chunks) != expected:
            raise InstallConflict(f"target changed after preflight: {path}")
        os.fchmod(descriptor, mode)
    finally:
        os.close(descriptor)


def _atomic_write(path: Path, value: bytes, *, expected_before: bytes | None) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    if _read_regular(path) != expected_before:
        raise InstallConflict(f"target changed after preflight: {path}")
    descriptor, temporary_name = tempfile.mkstemp(prefix=f".{path.name}.grok-", dir=path.parent)
    temporary = Path(temporary_name)
    try:
        with os.fdopen(descriptor, "wb") as handle:
            handle.write(value)
            handle.flush()
            os.fsync(handle.fileno())
        os.chmod(temporary, 0o755)
        temporary.replace(path)
        directory_fd = os.open(path.parent, os.O_RDONLY | os.O_DIRECTORY)
        try:
            os.fsync(directory_fd)
        finally:
            os.close(directory_fd)
    finally:
        temporary.unlink(missing_ok=True)


def install(*, home: Path, apply: bool, replace_existing: bool = False) -> dict[str, object]:
    home = home.expanduser().resolve()
    if not home.is_dir():
        raise ValueError(f"home directory does not exist: {home}")

    target = home / ".local/bin/grok"
    official = home / ".npm-global/bin/grok"
    before = _read_regular(target)
    official_ready = official.exists() and official.is_file() and os.access(official, os.X_OK)
    action = "unchanged" if before == WRAPPER else "install"
    requires_replacement = before is not None and before != WRAPPER

    receipt: dict[str, object] = {
        "schemaVersion": 1,
        "kind": "heim_pc_grok_subscription_wrapper_install",
        "apply": apply,
        "home": str(home),
        "target": str(target),
        "officialEntrypoint": str(official),
        "officialEntrypointReady": official_ready,
        "action": action,
        "requiresReplacement": requires_replacement,
        "beforeSha256": _sha256(before) if before is not None else None,
        "afterSha256": _sha256(WRAPPER),
        "paygApiKeyInherited": False,
        "apiKeyAuthDisabled": True,
        "forcesNodeInterpreter": False,
        "doesNotEstablish": [
            "grok_authentication",
            "grok_subscription_quota",
            "provider_billing_state",
            "future_package_entrypoint_availability",
        ],
    }
    if not apply:
        return receipt
    if not official_ready:
        raise InstallConflict(f"official Grok entrypoint is missing or not executable: {official}")
    if requires_replacement and not replace_existing:
        raise InstallConflict(
            "existing Grok launcher differs; review the plan and rerun with --replace-existing"
        )
    if action == "install":
        _atomic_write(target, WRAPPER, expected_before=before)
    else:
        _chmod_unchanged_regular(target, WRAPPER, 0o755)
    return receipt


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--home", type=Path, default=Path.home())
    parser.add_argument("--apply", action="store_true")
    parser.add_argument("--replace-existing", action="store_true")
    args = parser.parse_args()
    try:
        result = install(
            home=args.home,
            apply=args.apply,
            replace_existing=args.replace_existing,
        )
    except (OSError, RuntimeError, ValueError) as exc:
        print(
            json.dumps(
                {"kind": "heim_pc_grok_subscription_wrapper_install_error", "error": str(exc)},
                sort_keys=True,
            ),
            file=sys.stderr,
        )
        return 1
    print(json.dumps(result, ensure_ascii=False, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
