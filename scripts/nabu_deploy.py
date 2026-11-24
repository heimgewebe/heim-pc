"""Deploy only Nabu's six Home Assistant custom-component files.

Check an immutable Git revision before applying it. Review any differences first:
    python3 scripts/nabu_deploy.py --check --revision <merged-commit>
    python3 scripts/nabu_deploy.py --apply --revision <merged-commit> --expect-drift <fingerprint>

No private HA options, Chrome extension, credentials, or other services are modified.
A failed activation restores the changed package files from a private backup.
"""
from __future__ import annotations

import argparse
import ast
import fcntl
import hashlib
import json
import os
from pathlib import Path
import re
import stat
import subprocess
import tempfile
import time
from urllib.request import urlopen

FILES = ("__init__.py", "manifest.json", "llm.py", "grabowski_client.py",
         "chatgpt_client.py", "radio.py")
REPO = Path(__file__).resolve().parents[1]
TARGET = Path.home() / ".local/share/heimgewebe/home-assistant/custom_components/nabu_web"
BACKUPS = Path.home() / ".local/state/nabu-deploy"
UNIT = "heimgewebe-homeassistant.service"
CONTAINER = "heimgewebe-homeassistant"
HEALTH = "http://127.0.0.1:8123/"


def digest(data):
    return None if data is None else hashlib.sha256(data).hexdigest()


def json_bytes(value):
    return (json.dumps(value, sort_keys=True, ensure_ascii=False) + "\n").encode()


def read_file(path):
    if path.is_symlink():
        raise RuntimeError(f"refusing symlink: {path}")
    if not path.exists():
        return None
    if not stat.S_ISREG(path.stat().st_mode):
        raise RuntimeError(f"not a regular file: {path}")
    return path.read_bytes()


def snapshot(target):
    if target.is_symlink() or not target.is_dir():
        raise RuntimeError(f"Nabu component directory not found: {target}")
    return {name: read_file(target / name) for name in FILES}


def validate_release(files):
    for name in FILES:
        if not isinstance(files.get(name), bytes) or not files[name]:
            raise ValueError(f"missing or empty release file: {name}")
        if name.endswith(".py"):
            ast.parse(files[name].decode("utf-8"), filename=name)
    manifest = json.loads(files["manifest.json"])
    if not isinstance(manifest, dict) or manifest.get("domain") != "nabu_web":
        raise ValueError("manifest domain is not nabu_web")


def load_release(repo, revision):
    commit = subprocess.check_output(
        ["git", "-C", str(repo), "rev-parse", "--verify", revision + "^{commit}"],
        text=True, timeout=15).strip()
    files = {name: subprocess.check_output(
        ["git", "-C", str(repo), "show", f"{commit}:nixos/system/nabu/{name}"],
        timeout=15) for name in FILES}
    validate_release(files)
    return commit, files


def plan(target, commit, release, current):
    entries = {name: {"source": digest(release[name]), "installed": digest(current[name])}
               for name in FILES}
    data = {"revision": commit, "target": str(target),
            "files": entries, "changed": [name for name in FILES
                                          if current[name] != release[name]]}
    data["drift_fingerprint"] = digest(json_bytes(data))
    return data


def atomic_write(path, data):
    fd, tmp = tempfile.mkstemp(prefix=".nabu-deploy-", dir=path.parent)
    try:
        os.fchmod(fd, 0o600)
        with os.fdopen(fd, "wb") as stream:
            stream.write(data)
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(tmp, path)
    finally:
        if os.path.exists(tmp):
            os.unlink(tmp)


def run(*argv):
    subprocess.run(argv, check=True, timeout=60)


def active():
    run("systemctl", "--user", "is-active", "--quiet", UNIT)


def smoke():
    # Import using the real HA Python and installed package, without calling tools.
    run("podman", "exec", CONTAINER, "python", "-B", "-X",
        "pycache_prefix=/tmp/nabu-deploy-import", "-c",
        "import sys; sys.path.insert(0, '/config'); "
        "import custom_components.nabu_web.llm as n; "
        "result=n.async_get_tools(None,None,n.LLM_API_ASSIST); "
        "names={t.name for t in result.tools}; "
        "assert {'nabu_web__search','nabu_web__read_page','nabu_web__browser',"
        "'nabu_web__play_music','nabu_web__grabowski','nabu_web__grabowski_request',"
        "'nabu_web__chatgpt','nabu_web__weather'} <= names")


def restart():
    run("systemctl", "--user", "restart", UNIT)


def health():
    deadline = time.monotonic() + 60
    while time.monotonic() < deadline:
        try:
            with urlopen(HEALTH, timeout=3) as response:
                if response.status == 200:
                    active()
                    return
        except (OSError, subprocess.SubprocessError):
            pass
        time.sleep(1)
    raise RuntimeError("Home Assistant did not become healthy after restart")


def deploy(target, backups, commit, release, expected, *,
           check_active=active, import_smoke=smoke, restart_service=restart,
           verify_health=health):
    validate_release(release)
    before = snapshot(target)
    planned = plan(target, commit, release, before)
    if planned["drift_fingerprint"] != expected:
        raise RuntimeError("drift changed; run --check again before applying")
    changed = planned["changed"]
    if not changed:
        return {"status": "already_current", **planned}
    check_active()
    backups.mkdir(mode=0o700, parents=True, exist_ok=True)
    backup = Path(tempfile.mkdtemp(prefix=commit[:12] + "-", dir=backups))
    for name in changed:
        if before[name] is not None:
            atomic_write(backup / name, before[name])
    atomic_write(backup / "plan.json", json_bytes(planned))
    written = []
    restarted = False
    try:
        for name in changed:
            if read_file(target / name) != before[name]:
                raise RuntimeError(f"installed file changed during deploy: {name}")
            atomic_write(target / name, release[name])
            written.append(name)
        import_smoke()
        restarted = True
        restart_service()
        verify_health()
        if snapshot(target) != release:
            raise RuntimeError("installed package differs after activation")
        return {"status": "applied", "backup": str(backup),
                "revision": commit, "changed": changed,
                "installed_sha256": {name: digest(release[name]) for name in FILES}}
    except (Exception, KeyboardInterrupt) as cause:
        try:
            for name in reversed(written):
                if read_file(target / name) != release[name]:
                    raise RuntimeError(f"concurrent change during rollback: {name}")
                if before[name] is None:
                    (target / name).unlink()
                else:
                    atomic_write(target / name, before[name])
            if restarted:
                restart_service()
                verify_health()
            if snapshot(target) != before:
                raise RuntimeError("rollback readback differs from original package")
        except Exception as failure:
            raise RuntimeError(f"deployment and rollback failed; backup {backup}: {failure}") from cause
        raise RuntimeError(f"deployment failed; original package restored; backup {backup}") from cause


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    mode = parser.add_mutually_exclusive_group(required=True)
    mode.add_argument("--check", action="store_true")
    mode.add_argument("--apply", action="store_true")
    parser.add_argument("--revision", default="HEAD", help="Git release revision; exact commit for --apply")
    parser.add_argument("--expect-drift", help="fingerprint printed by --check for that release")
    args = parser.parse_args(argv)
    if args.apply and (not re.fullmatch("[0-9a-f]{40}", args.revision)
                       or not re.fullmatch("[0-9a-f]{64}", args.expect_drift or "")):
        parser.error("--apply requires an exact Git commit and --expect-drift from --check")
    try:
        commit, release = load_release(REPO, args.revision)
        if args.check:
            result = plan(TARGET, commit, release, snapshot(TARGET))
            result["status"] = "drift" if result["changed"] else "current"
            print(json.dumps(result, indent=2))
            return 1 if result["changed"] else 0
        BACKUPS.mkdir(mode=0o700, parents=True, exist_ok=True)
        with (BACKUPS / ".lock").open("a") as lock:
            fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
            result = deploy(TARGET, BACKUPS, commit, release, args.expect_drift)
        print(json.dumps(result, indent=2))
        return 0
    except (OSError, ValueError, RuntimeError, SyntaxError, subprocess.SubprocessError) as exc:
        print(json.dumps({"status": "failed", "error": str(exc)}))
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
