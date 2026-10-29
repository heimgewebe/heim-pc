{ pkgs }:
let
  # Identical Git source as the already built canonical Rootbroker package.
  # Every dependency must also match the hashed upstream runtime.lock.txt.
  sourceRevision = "586a6fc8461935d4383a83e9ae1a2ab6f36beec6";
  releaseId = "586a6fc84619-srcset9cf8e6c8781c-lock264e747ad05a-contract650f923c4cfb";
  lockSha256 = "264e747ad05a536e9ca7639c6cba5a45636b93df0fe3153b4ae040ec14d456e3";
  sourceArchive = pkgs.fetchurl {
    url = "https://codeload.github.com/heimgewebe/grabowski/tar.gz/${sourceRevision}";
    hash = "sha256-+wI18lL8gcyeBQXAIi0iWdylykBikuK8aGpF46G1fiQ=";
  };
  python = pkgs.python312;
  pip = pkgs.python312Packages.pip;
  # Fixed-output wheel acquisition: pip validates the *individual* SHA256
  # hashes in the full upstream lock. A second NAR hash binds the wheelhouse.
  # Fail closed if the wheelhouse hash is not known; no mutable pip downloads
  # occur during the subsequent ordinary, sandboxed operator build.
  wheelhouse = pkgs.stdenvNoCC.mkDerivation {
    pname = "grabowski-locked-runtime-wheels";
    version = "586a6fc8";
    dontUnpack = true;
    outputHashAlgo = "sha256";
    outputHashMode = "recursive";
    # Hash from actual, individually hash-verified pinned dependency wheelhouse build.
    outputHash = "sha256-y/6EMxK7jFHXSJzI4xWre15WY4VOyeP+C33SQPjNESg=";
    nativeBuildInputs = [ pkgs.gnutar pkgs.gzip pip pkgs.coreutils ];
    buildCommand = ''
      set -euo pipefail
      export HOME="$TMPDIR" PIP_DISABLE_PIP_VERSION_CHECK=1
      export SSL_CERT_FILE="${pkgs.cacert}/etc/ssl/certs/ca-bundle.crt"
      mkdir -p extracted "$out"
      tar -xzf ${sourceArchive} --strip-components=1 -C extracted
      printf '%s  %s\n' ${lockSha256} extracted/requirements/runtime.lock.txt | sha256sum -c -
      ${pip}/bin/pip download --no-input --require-hashes --only-binary=:all: \
        --dest "$out" -r extracted/requirements/runtime.lock.txt
      test "$(find "$out" -type f -name '*.whl' | wc -l)" -gt 0
      test -z "$(find "$out" -type f ! -name '*.whl' -print -quit)"
    '';
  };
in
pkgs.stdenvNoCC.mkDerivation {
  pname = "grabowski-operator";
  version = "586a6fc8";
  dontUnpack = true;
  nativeBuildInputs = [
    pkgs.gnutar pkgs.gzip pkgs.makeWrapper pip pkgs.coreutils
    pkgs.autoPatchelfHook
  ];
  buildInputs = [ pkgs.stdenv.cc.cc.lib pkgs.zlib pkgs.openssl ];
  passthru = {
    inherit sourceRevision releaseId lockSha256 wheelhouse;
  };
  buildCommand = ''
    set -euo pipefail
    export HOME="$TMPDIR" PIP_DISABLE_PIP_VERSION_CHECK=1
    mkdir -p extracted "$out/bin" "$out/lib/python3.12/site-packages" "$out/share/grabowski"
    # Python -I intentionally ignores PYTHONPATH. Install a store-owned
    # virtual environment so subprocess tools can import their pinned modules
    # even under isolated execution, without a writable home directory.
    ln -s ${python}/bin/python3.12 "$out/bin/python3"
    printf 'home = ${python}/bin\ninclude-system-site-packages = false\n' > "$out/pyvenv.cfg"
    tar -xzf ${sourceArchive} --strip-components=1 -C extracted
    printf '%s  %s\n' ${lockSha256} extracted/requirements/runtime.lock.txt | sha256sum -c -

    # Offline, exact-wheel install. Never accept Nixpkgs' differently pinned
    # MCP, PostHog, OpenTelemetry or other Python dependencies implicitly.
    ${pip}/bin/pip install --no-index --no-deps --no-compile --no-input \
      --require-hashes --only-binary=:all: --find-links ${wheelhouse} \
      --target "$out/lib/python3.12/site-packages" \
      -r extracted/requirements/runtime.lock.txt

    # Immutable Nix-Store wrappers retain root-owned executable validation
    # without depending on Pop!_OS /usr/bin/git or /usr/bin/gh.
    makeWrapper ${pkgs.git}/bin/git "$out/bin/git"
    makeWrapper ${pkgs.gh}/bin/gh "$out/bin/gh" \
      --prefix PATH : "${pkgs.git}/bin:${pkgs.coreutils}/bin"
    export GRABOWSKI_NIXOS_GIT_BIN="$out/bin/git"
    export GRABOWSKI_NIXOS_GH_BIN="$out/bin/gh"

    # Reproduce the ORIGINAL canonical 203-tool deployment entrypoint.
    # The source file name differs from the Python module name: the public
    # runtime-entrypoint.json intentionally maps src/grabowski_runtime.py to
    # grabowski_operator and src/grabowski_operator.py to
    # grabowski_operator_core. Blindly copying src/*.py builds only the old
    # 53-tool core and silently omits the real runtime extensions.
    cp -r extracted/config extracted/requirements "$out/share/grabowski/"
    install -m 0644 extracted/pyproject.toml "$out/share/grabowski/pyproject.toml"
    ${python}/bin/python3.12 -B - "$PWD/extracted" \
      "$out/lib/python3.12/site-packages" "$out/share/grabowski" <<'PY'
import json
import os
from pathlib import Path
import shutil
import sys

root = Path(sys.argv[1]).resolve(strict=True)
site = Path(sys.argv[2])
share = Path(sys.argv[3])
contract = json.loads((root / "config/runtime-entrypoint.json").read_text())
if not (
    contract.get("mode") == "module"
    and contract.get("module") == "grabowski_operator"
    and contract.get("source") == "src/grabowski_runtime.py"
):
    raise SystemExit("unexpected upstream canonical runtime entrypoint")
expected = contract.get("expected_tools")
if not (isinstance(expected, list) and len(expected) == 203
        and len(set(expected)) == len(expected)):
    raise SystemExit("canonical runtime tool contract changed")
supporting = contract.get("supporting_sources")
if not isinstance(supporting, list) or len(supporting) != 130:
    raise SystemExit("canonical runtime module mapping changed")
entries = [{"module": contract["module"], "source": contract["source"]}, *supporting]
seen = set()
for entry in entries:
    name = entry.get("module")
    original = entry.get("source")
    if not (
        isinstance(name, str) and name.isidentifier()
        and isinstance(original, str) and original.startswith("src/")
        and original.endswith(".py") and ".." not in Path(original).parts
        and name not in seen
    ):
        raise SystemExit("unsafe or duplicate canonical runtime module mapping")
    seen.add(name)
    src = (root / original).resolve(strict=True)
    if not src.is_relative_to(root / "src") or not src.is_file():
        raise SystemExit("runtime module source escaped pinned source tree")
    dst = site / (name + ".py")
    shutil.copyfile(src, dst)
    # Adapt ONLY the known immutable executable selectors in the pinned
    # upstream revision. Mismatched occurrences fail the Nix build closed.
    expected_paths = {
        "src/grabowski_operator.py": (1, 1),
        "src/grabowski_self_deploy.py": (2, 0),
    }
    if original in expected_paths:
        content = dst.read_text()
        expected_git, expected_gh = expected_paths[original]
        if (content.count("/usr/bin/git") != expected_git
                or content.count("/usr/bin/gh") != expected_gh):
            raise SystemExit("unexpected pinned Grabowski CLI path topology")
        content = content.replace("/usr/bin/git", os.environ["GRABOWSKI_NIXOS_GIT_BIN"])
        content = content.replace("/usr/bin/gh", os.environ["GRABOWSKI_NIXOS_GH_BIN"])
        dst.write_text(content)
    # The copied full upstream runtime is still the canonical 203-tool
    # entrypoint. Repair only Nix-specific argv0 and catalog discovery.
    if original == "src/grabowski_runtime.py":
        content = dst.read_text()
        marker = "from __future__ import annotations\n\n"
        if not content.startswith(marker) or content.count(marker) != 1:
            raise SystemExit("canonical Grabowski runtime prologue changed")
        real_python = str(Path("${python}/bin/python3.12").resolve(strict=True))
        wrapper = str(site.parents[2] / "bin/grabowski-operator")
        venv_python = str(site.parents[2] / "bin/python3")
        bootstrap = (
            "import os as _grabowski_nix_os\n"
            "import sys as _grabowski_nix_sys\n"
            f"if (_grabowski_nix_sys.executable == {wrapper!r}\n"
            f"        and _grabowski_nix_os.path.realpath('/proc/self/exe') == {real_python!r}):\n"
            f"    _grabowski_nix_sys.executable = {venv_python!r}\n\n"
        )
        dst.write_text(content.replace(marker, marker + bootstrap, 1))
    if original == "src/grabowski_coding_agent_router.py":
        content = dst.read_text()
        old = (
            "def _deployment_catalog_path() -> Path:\n"
            "    module_path = Path(__file__).resolve()\n"
            "    environment_prefix = Path(sys.prefix).resolve()\n"
            "    if (\n"
            "        sys.prefix != sys.base_prefix\n"
            "        and module_path.is_relative_to(environment_prefix)\n"
            "    ):\n"
            "        return environment_prefix.parent / \"config\" / \"coding-agent-catalog.json\"\n"
            "    return module_path.parent.parent / \"config\" / \"coding-agent-catalog.json\"\n"
        )
        new = (
            "def _deployment_catalog_path() -> Path:\n"
            "    # Nix-built canonical catalog inside the immutable package output.\n"
            "    return Path(__file__).resolve().parents[3] / \"share/grabowski/config/coding-agent-catalog.json\"\n"
        )
        if content.count(old) != 1:
            raise SystemExit("pinned coding-agent catalog path topology changed")
        dst.write_text(content.replace(old, new, 1))
    # Preserve Debian /usr/bin/python3 for SSH fleet hosts; NixOS-local
    # user systemd jobs need this package's immutable runtime interpreter.
    # Every substitution is bound to the exact pinned upstream topology.
    if original == "src/grabowski_tasks.py":
        content = dst.read_text()
        local_python = (
            '(sys.executable if fleet.fleet_host(str(record["host"]))["transport"] == "local"\n'
            '         else TASK_OUTPUT_CAPTURE_PYTHON)'
        )
        anchors = (
            (
                '        TASK_OUTPUT_CAPTURE_PYTHON,\n'
                '        str(_task_output_capture_script_path()),',
                '        ' + local_python + ',\n'
                '        str(_task_output_capture_script_path()),',
            ),
            (
                '        TASK_OUTPUT_CAPTURE_PYTHON,\n'
                '        "-c",\n'
                '        TASK_OUTPUT_CLEANUP_CODE,',
                '        ' + local_python + ',\n'
                '        "-c",\n'
                '        TASK_OUTPUT_CLEANUP_CODE,',
            ),
        )
        for old, new in anchors:
            if content.count(old) != 1:
                raise SystemExit("unexpected pinned task capture Python topology")
            content = content.replace(old, new, 1)
        dst.write_text(content)
    if original == "src/grabowski_fleet.py":
        content = dst.read_text()
        imports = "import stat\nfrom typing import Any, Sequence"
        if content.count(imports) != 1:
            raise SystemExit("unexpected pinned fleet import topology")
        content = content.replace(imports, "import stat\nimport sys\nfrom typing import Any, Sequence", 1)
        old = (
            '    if command[0] != TASK_OUTPUT_READ_PYTHON or command[1] != "-c":\n'
            '        raise ValueError("Invalid task-output cleanup executable")'
        )
        new = (
            '    expected_python = (sys.executable if host["transport"] == "local"\n'
            '                       else TASK_OUTPUT_READ_PYTHON)\n'
            '    if command[0] != expected_python or command[1] != "-c":\n'
            '        raise ValueError("Invalid task-output cleanup executable")'
        )
        if content.count(old) != 1:
            raise SystemExit("unexpected pinned fleet cleanup Python guard")
        dst.write_text(content.replace(old, new, 1))
    dst.chmod(0o444)
for item in contract.get("runtime_assets", []):
    original = item.get("source")
    dest = item.get("destination")
    if not (
        isinstance(original, str) and isinstance(dest, str)
        and ".." not in Path(original).parts
        and ".." not in Path(dest).parts
        and not Path(dest).is_absolute()
    ):
        raise SystemExit("invalid canonical runtime asset")
    src = (root / original).resolve(strict=True)
    if not src.is_file() or not src.is_relative_to(root):
        raise SystemExit("runtime asset escaped pinned source tree")
    target = share / dest
    target.parent.mkdir(parents=True, exist_ok=True)
    shutil.copyfile(src, target)
    target.chmod(0o444)
PY

    # The existing source-pinned ingress CAS publisher is reused by the native
    # operator post-start rebind; it is not a second tunnel daemon.
    install -m 0444 extracted/tools/grabowski_transport_ingress.py \
      "$out/lib/python3.12/site-packages/grabowski_transport_ingress.py"

    # Nix-native integrity: adapt only the two expected manifest discovery
    # sites in the pinned upstream module. Everything else stays canonical.
    install -m 0444 ${./grabowski-nixos-integrity.py} \
      "$out/lib/python3.12/site-packages/grabowski_nixos_integrity.py"
    PYTHONPATH="$out/lib/python3.12/site-packages" ${python}/bin/python3.12 -B - "$out" <<'PY'
from pathlib import Path
import sys
from grabowski_nixos_integrity import patch_pinned_module
path = Path(sys.argv[1]) / "lib/python3.12/site-packages/grabowski_mcp.py"
patch_pinned_module(path)
PY
    makeWrapper "$out/bin/python3" "$out/bin/grabowski-operator" \
      --argv0 "$out/bin/grabowski-operator" \
      --set PYTHONDONTWRITEBYTECODE 1 \
      --prefix PYTHONPATH : "$out/lib/python3.12/site-packages" \
      --prefix PATH : "${pkgs.coreutils}/bin:${pkgs.git}/bin:${pkgs.systemd}/bin" \
      --add-flags "-m grabowski_operator --transport streamable-http --host 127.0.0.1 --port 18181"

    cat > "$out/share/grabowski/nixos-release.json" <<'EOF'
{
  "schema_version": 1,
  "release_id": "${releaseId}",
  "source_revision": "${sourceRevision}",
  "runtime_lock_sha256": "${lockSha256}",
  "entrypoint": "bin/grabowski-operator",
  "transport": "streamable-http",
  "host": "127.0.0.1",
  "port": 18181
}
EOF
    # Store-owned native attestation replaces the Pop!-specific Python 3.10
    # deployment path contract. Its tool/module/asset hashes are checked
    # again at each runtime status call; user-owned copies are never trusted.
    PYTHONPATH="$out/lib/python3.12/site-packages" ${python}/bin/python3.12 -B - "$out" <<'PY'
import json
from pathlib import Path
import sys
from grabowski_nixos_integrity import build_manifest, MANIFEST_RELATIVE
import grabowski_mcp
root = Path(sys.argv[1])
data = build_manifest(
    root,
    agent_sha256=grabowski_mcp.AGENT_INSTRUCTIONS_SHA256,
    python_executable=sys.executable,
)
path = root / MANIFEST_RELATIVE
path.write_text(json.dumps(data, sort_keys=True, separators=(",", ":")) + "\n")
path.chmod(0o444)
PY
    ${python}/bin/python3.12 -B -m compileall -q "$out/lib/python3.12/site-packages"
    PYTHONPATH="$out/lib/python3.12/site-packages" ${python}/bin/python3.12 -B -c '
import importlib.metadata
for package, expected in {
    "mcp": "1.30.0",
    "posthog": "7.62.0",
    "opentelemetry-api": "1.45.0",
    "opentelemetry-sdk": "1.45.0",
    "opentelemetry-exporter-otlp-proto-http": "1.45.0",
    "filelock": "3.32.2",
    "jsonschema": "4.26.0",
    "PyYAML": "6.0.3",
}.items():
    actual = importlib.metadata.version(package)
    if actual != expected:
        raise SystemExit(f"{package}: expected {expected}, got {actual}")
'
    # Build-time live proof: Nix Python -I must discover the real pinned
    # job-finalization module and the pinned coding agent catalog.
    "$out/bin/python3" -I -B - "$out" <<'PY'
from pathlib import Path
import importlib.util
import sys

root = Path(sys.argv[1])
if Path(sys.prefix) != root or sys.prefix == sys.base_prefix:
    raise SystemExit("Nix Python isolated site-packages prefix is not the package root")
if importlib.util.find_spec("grabowski_job_finalizer") is None:
    raise SystemExit("Nix isolated job finalizer is not importable")
import grabowski_coding_agent_router as router
health = router.coding_agent_catalog_health()
if health.get("ready") is not True:
    raise SystemExit("Nix immutable coding-agent catalog is not ready: " + repr(health))
if Path(health["path"]).resolve(strict=True) != root / "share/grabowski/config/coding-agent-catalog.json":
    raise SystemExit("Nix coding-agent catalog is not the pinned store asset")
print("nix isolated jobfinalizer and immutable catalog verified")
PY
    test -x "$out/bin/grabowski-operator"
    test -x "$out/bin/git"
    test -x "$out/bin/gh"
  '';
}