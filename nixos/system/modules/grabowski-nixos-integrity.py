"""Fail-closed deployment identity for the *Nix-built* canonical Grabowski runtime.

The upstream portable deployment manifest describes a mutable Python 3.10 venv.
It is deliberately not accepted on NixOS. This attestation is generated in the
same locked, revision-pinned Nix derivation as the Python 3.12 operator. Its
checks are restricted to immutable root-owned Nix store inputs and exact tool,
module, runtime-asset and interpreter identities. No user-provided path,
environment flag or Pop!_OS deployment manifest can grant runtime readiness.
"""
from __future__ import annotations

import hashlib
import importlib.util
import json
import os
from pathlib import Path
import platform
import re
import stat
import sys
from typing import Any

PINNED_RELEASE = "c6a74e8ce760-srcset80bd825be2dc-lock264e747ad05a-contract650f923c4cfb"
PINNED_REVISION = "c6a74e8ce76096f5a7f8380f3618ac7d30df6509"
PINNED_LOCK_SHA256 = "264e747ad05a536e9ca7639c6cba5a45636b93df0fe3153b4ae040ec14d456e3"
ROOT_RE = re.compile(r"/nix/store/[0-9a-z]{32}-grabowski-operator-c6a74e8c\Z")
REQUIRED_MODULE = "lib/python3.12/site-packages/grabowski_mcp.py"
MANIFEST_RELATIVE = "share/grabowski/nixos-integrity-manifest.json"
CONTRACT_RELATIVE = "share/grabowski/config/runtime-entrypoint.json"
RELEASE_RELATIVE = "share/grabowski/nixos-release.json"
LOCK_RELATIVE = "share/grabowski/requirements/runtime.lock.txt"
SITE_RELATIVE = "lib/python3.12/site-packages"
MAX_READ = 16 * 1024 * 1024


def store_root(module_path: Path) -> Path:
    """Resolve *this* installed module; never accept a caller-selected release."""
    path = module_path.resolve(strict=True)
    root = path.parents[3]
    if not ROOT_RE.fullmatch(str(root)) or path != root / REQUIRED_MODULE:
        raise ValueError("NixOS Grabowski module is outside the pinned Nix store output")
    info = root.lstat()
    if not stat.S_ISDIR(info.st_mode) or info.st_uid != 0 or (info.st_mode & 0o022):
        raise ValueError("Nix store package root is not immutable and root-owned")
    return root


def _read(root: Path, relative: str, *, maximum: int = MAX_READ) -> bytes:
    if relative.startswith("/") or ".." in Path(relative).parts:
        raise ValueError("invalid release-relative path")
    path = root / relative
    meta = path.lstat()
    if (not stat.S_ISREG(meta.st_mode) or meta.st_uid != 0 or
            meta.st_nlink < 1 or meta.st_size > maximum or
            (stat.S_IMODE(meta.st_mode) & 0o022)):
        raise ValueError("unsafe release artifact: " + relative)
    descriptor = os.open(path, os.O_RDONLY | os.O_CLOEXEC | getattr(os, "O_NOFOLLOW", 0))
    try:
        actual = os.fstat(descriptor)
        if (actual.st_dev != meta.st_dev or actual.st_ino != meta.st_ino or
                actual.st_mode != meta.st_mode or actual.st_uid != meta.st_uid or
                actual.st_nlink != meta.st_nlink):
            raise ValueError("artifact identity changed during open")
        data = os.read(descriptor, maximum + 1)
        if len(data) > maximum or os.read(descriptor, 1):
            raise ValueError("release artifact exceeds size bound")
        return data
    finally:
        os.close(descriptor)


def _sha(payload: bytes) -> str:
    return hashlib.sha256(payload).hexdigest()


def _contract_entries(contract: dict[str, Any]) -> tuple[dict[str, str], dict[str, str]]:
    if (contract.get("mode") != "module" or
            contract.get("module") != "grabowski_operator" or
            contract.get("source") != "src/grabowski_runtime.py"):
        raise ValueError("unrecognized canonical entrypoint")
    tools = contract.get("expected_tools")
    if not isinstance(tools, list) or len(tools) != 203 or len(set(tools)) != 203:
        raise ValueError("203-tool contract absent")
    supporting = contract.get("supporting_sources")
    if not isinstance(supporting, list) or len(supporting) != 130:
        raise ValueError("canonical source mapping incomplete")
    modules = {}
    for entry in [{"module": contract["module"], "source": contract["source"]}, *supporting]:
        name = entry.get("module")
        src = entry.get("source")
        if (not isinstance(name, str) or not name.isidentifier() or
                not isinstance(src, str) or not src.startswith("src/") or
                ".." in Path(src).parts or not src.endswith(".py") or name in modules):
            raise ValueError("invalid canonical module mapping")
        modules[name] = SITE_RELATIVE + "/" + name + ".py"
    assets = {}
    for entry in contract.get("runtime_assets", []):
        dst = entry.get("destination")
        if not isinstance(dst, str) or not dst or dst.startswith("/") or ".." in Path(dst).parts:
            raise ValueError("invalid runtime asset path")
        if dst in assets:
            raise ValueError("duplicate runtime asset")
        assets[dst] = "share/grabowski/" + dst
    return modules, assets


def build_manifest(root: Path, *, agent_sha256: str, python_executable: str) -> dict[str, Any]:
    """Run only inside the pinned derivation after all upstream files are installed."""
    contract_bytes = (root / CONTRACT_RELATIVE).read_bytes()
    contract = json.loads(contract_bytes)
    modules, assets = _contract_entries(contract)
    release = json.loads((root / RELEASE_RELATIVE).read_text())
    if (release.get("release_id") != PINNED_RELEASE or
            release.get("source_revision") != PINNED_REVISION or
            release.get("runtime_lock_sha256") != PINNED_LOCK_SHA256):
        raise ValueError("native Nix release differs from pinned build")
    if _sha((root / LOCK_RELATIVE).read_bytes()) != PINNED_LOCK_SHA256:
        raise ValueError("pinned source lock drift")
    if not re.fullmatch(r"[0-9a-f]{64}", agent_sha256):
        raise ValueError("invalid agent instructions digest")
    return {
        "schema_version": 1,
        "kind": "grabowski-nixos-immutable-runtime-integrity",
        "release_id": PINNED_RELEASE,
        "repo_head": PINNED_REVISION,
        "runtime_lock_sha256": PINNED_LOCK_SHA256,
        "entrypoint_contract": contract,
        "entrypoint_contract_sha256": _sha(contract_bytes),
        "agent_instructions_sha256": agent_sha256,
        "module_sha256s": {name: _sha((root / relative).read_bytes()) for name, relative in modules.items()},
        "runtime_asset_sha256s": {name: _sha((root / relative).read_bytes()) for name, relative in assets.items()},
        "python_executable": str(Path(python_executable).resolve(strict=True)),
        "python_version": platform.python_version(),
        "python_implementation": platform.python_implementation(),
    }


def deployment_metadata(module_path: Path, *, expected_agent_sha256: str) -> dict[str, Any]:
    """Return readiness only for a complete, unchanged, native pinned Nix output."""
    result = {
        "completion_status": "incomplete",
        "manifest_exists": False,
        "manifest_parse_valid": False,
        "manifest_schema_valid": False,
        "entrypoint_contract_sha256": None,
        "entrypoint_contract_identity_valid": False,
        "repo_head_valid": False,
        "agent_instructions_identity_valid": False,
        "runtime_binding_valid": False,
        "environment_compatibility_valid": False,
        "artifact_integrity_valid": False,
        "provenance_valid": False,
    }
    try:
        root = store_root(module_path)
        manifest_path = root / MANIFEST_RELATIVE
        result["manifest_path"] = str(manifest_path)
        payload = _read(root, MANIFEST_RELATIVE, maximum=1024 * 1024)
        result["manifest_exists"] = True
        doc = json.loads(payload)
        result["manifest_parse_valid"] = True
        if (doc.get("schema_version") != 1 or
                doc.get("kind") != "grabowski-nixos-immutable-runtime-integrity" or
                doc.get("release_id") != PINNED_RELEASE or
                doc.get("repo_head") != PINNED_REVISION or
                doc.get("runtime_lock_sha256") != PINNED_LOCK_SHA256):
            raise ValueError("native release identity mismatch")
        result["manifest_schema_valid"] = True
        result["repo_head_valid"] = True
        result["release_id"] = PINNED_RELEASE
        result["repo_head"] = PINNED_REVISION
        contract_data = _read(root, CONTRACT_RELATIVE, maximum=64 * 1024)
        contract = json.loads(contract_data)
        if (doc.get("entrypoint_contract_sha256") != _sha(contract_data) or
                doc.get("entrypoint_contract") != contract):
            raise ValueError("entrypoint contract does not match installed pinned source")
        result["entrypoint_contract_sha256"] = _sha(contract_data)
        result["entrypoint_contract_identity_valid"] = True
        modules, assets = _contract_entries(contract)
        if (set(doc.get("module_sha256s", {})) != set(modules) or
                set(doc.get("runtime_asset_sha256s", {})) != set(assets)):
            raise ValueError("incomplete module or runtime-asset digest list")
        if _sha(_read(root, LOCK_RELATIVE, maximum=1_000_000)) != PINNED_LOCK_SHA256:
            raise ValueError("pinned runtime lock does not match Nix artifact")
        release = json.loads(_read(root, RELEASE_RELATIVE, maximum=4096))
        if (release.get("release_id") != PINNED_RELEASE or
                release.get("source_revision") != PINNED_REVISION or
                release.get("runtime_lock_sha256") != PINNED_LOCK_SHA256 or
                release.get("entrypoint") != "bin/grabowski-operator"):
            raise ValueError("native release metadata differs from pinned build")
        for name, relative in modules.items():
            if _sha(_read(root, relative)) != doc["module_sha256s"][name]:
                raise ValueError("installed canonical module hash drift: " + name)
            origin = importlib.util.find_spec(name)
            if origin is None or origin.origin is None or Path(origin.origin).resolve() != root / relative:
                raise ValueError("Python imported a noncanonical module: " + name)
        for name, relative in assets.items():
            if _sha(_read(root, relative)) != doc["runtime_asset_sha256s"][name]:
                raise ValueError("runtime asset hash drift: " + name)
        result["artifact_integrity_valid"] = True
        result["agent_instructions_identity_valid"] = (
            doc.get("agent_instructions_sha256") == expected_agent_sha256
        )
        # Nix makeWrapper uses exec -a with the immutable operator wrapper
        # as argv[0] so the original broker can authenticate MainPID/cmdline.
        # CPython derives sys.executable from argv[0], NOT /proc/self/exe.
        # Bind both identities: the real kernel-executed pinned interpreter
        # and either its direct argv[0] (offline tests) or the exact wrapper
        # argv[0] (the production systemd MainPID). Never trust argv[0] alone.
        python_bin = str(Path("/proc/self/exe").resolve(strict=True))
        argv0_bin = str(Path(sys.executable).resolve(strict=True))
        wrapper_bin = str((root / "bin/grabowski-operator").resolve(strict=True))
        result["runtime_binding_valid"] = (
            doc.get("python_executable") == python_bin
            and argv0_bin in (python_bin, wrapper_bin)
            and Path(module_path).resolve() == root / REQUIRED_MODULE
        )
        result["environment_compatibility_valid"] = (
            doc.get("python_version") == platform.python_version()
            and doc.get("python_implementation") == platform.python_implementation()
        )
        result["provenance_valid"] = all([
            result["artifact_integrity_valid"],
            result["runtime_binding_valid"],
            result["environment_compatibility_valid"],
            result["agent_instructions_identity_valid"],
        ])
        result["completion_status"] = "complete" if result["provenance_valid"] else "incomplete"
    except (OSError, ValueError, TypeError, KeyError, json.JSONDecodeError, ImportError):
        # Never turn invalid or incomplete evidence into a platform-ready result.
        pass
    return result

def patch_pinned_module(path: Path) -> None:
    """Adapt only two exact, expected manifest-discovery sites in pinned source.

    The 203-tool implementation, broker policy, tool signatures and signed
    connector transport are not altered. Unknown upstream revisions fail build.
    """
    text = path.read_text()
    old_discovery = (
        "def _deployment_manifest_path() -> Path:\n"
        "    executable = Path(sys.executable)\n"
        "    if executable.parent.name == \"bin\" and executable.parent.parent.name == \".venv\":\n"
        "        return executable.parent.parent.parent / \"deployment-manifest.json\"\n"
        "    return Path(__file__).resolve().parent / \"deployment-manifest.json\"\n"
    )
    new_discovery = (
        "def _deployment_manifest_path() -> Path:\n"
        "    import grabowski_nixos_integrity\n"
        "    path = Path(__file__).resolve()\n"
        "    try:\n"
        "        native_root = grabowski_nixos_integrity.store_root(path)\n"
        "    except (OSError, ValueError):\n"
        "        native_root = None\n"
        "    if native_root is not None:\n"
        "        return native_root / grabowski_nixos_integrity.MANIFEST_RELATIVE\n"
        "    executable = Path(sys.executable)\n"
        "    if executable.parent.name == \"bin\" and executable.parent.parent.name == \".venv\":\n"
        "        return executable.parent.parent.parent / \"deployment-manifest.json\"\n"
        "    return Path(__file__).resolve().parent / \"deployment-manifest.json\"\n"
    )
    old_metadata = (
        "    try:\n"
        "        return _deployment_metadata_impl()\n"
        "    except Exception as exc:  # pragma: no cover - final status containment\n"
    )
    new_metadata = (
        "    try:\n"
        "        if DEPLOYMENT_MANIFEST.name == \"nixos-integrity-manifest.json\":\n"
        "            from grabowski_nixos_integrity import deployment_metadata\n"
        "            return deployment_metadata(\n"
        "                Path(__file__), expected_agent_sha256=AGENT_INSTRUCTIONS_SHA256\n"
        "            )\n"
        "        return _deployment_metadata_impl()\n"
        "    except Exception as exc:  # pragma: no cover - final status containment\n"
    )
    if text.count(old_discovery) != 1 or text.count(old_metadata) != 1:
        raise ValueError("pinned canonical manifest interface unexpectedly changed")
    patched = text.replace(old_discovery, new_discovery).replace(old_metadata, new_metadata)
    if patched == text:
        raise ValueError("canonical NixOS manifest adaptation made no change")
    path.chmod(0o644)
    path.write_text(patched)
    path.chmod(0o444)