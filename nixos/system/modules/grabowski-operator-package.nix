{ pkgs }:
let
  # Identical Git source as the already built canonical Rootbroker package.
  # Every dependency must also match the hashed upstream runtime.lock.txt.
  sourceRevision = "dd6dc690285b6a8a0cdbb3c18d84a1681e604923";
  releaseId = "dd6dc690285b-srcset5c51dbd24485-lock264e747ad05a-contract2681d2593edc";
  lockSha256 = "264e747ad05a536e9ca7639c6cba5a45636b93df0fe3153b4ae040ec14d456e3";
  sourceArchive = pkgs.fetchurl {
    url = "https://codeload.github.com/heimgewebe/grabowski/tar.gz/${sourceRevision}";
    hash = "sha256-rEsGU4mWRbti570DialOPusjZvFK1gfk7UUiI9pbrf4=";
  };
  python = pkgs.python312;
  pip = pkgs.python312Packages.pip;
  # Fixed-output wheel acquisition: pip validates the *individual* SHA256
  # hashes in the full upstream lock. A second NAR hash binds the wheelhouse.
  # Fail closed if the wheelhouse hash is not known; no mutable pip downloads
  # occur during the subsequent ordinary, sandboxed operator build.
  wheelhouse = pkgs.stdenvNoCC.mkDerivation {
    pname = "grabowski-locked-runtime-wheels";
    version = "dd6dc690";
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
  version = "dd6dc690";
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
    tar -xzf ${sourceArchive} --strip-components=1 -C extracted
    printf '%s  %s\n' ${lockSha256} extracted/requirements/runtime.lock.txt | sha256sum -c -

    # Offline, exact-wheel install. Never accept Nixpkgs' differently pinned
    # MCP, PostHog, OpenTelemetry or other Python dependencies implicitly.
    ${pip}/bin/pip install --no-index --no-deps --no-compile --no-input \
      --require-hashes --only-binary=:all: --find-links ${wheelhouse} \
      --target "$out/lib/python3.12/site-packages" \
      -r extracted/requirements/runtime.lock.txt

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
if not isinstance(supporting, list) or len(supporting) != 127:
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

    makeWrapper ${python}/bin/python3.12 "$out/bin/grabowski-operator" \
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
    test -x "$out/bin/grabowski-operator"
  '';
}