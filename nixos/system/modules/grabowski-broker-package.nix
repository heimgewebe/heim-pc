{ lib, pkgs, ... }@args:
let
  # Exact Git revision of the last verified Pop!_OS operator release.
  # This publicly verifiable source archive contains no live host credentials.
  sourceRevision = "6a6360a92be11d24d85e9b002bb34ac2b07672d5";
  releaseId = "6a6360a92be1-srcset8a29601ce885-lock264e747ad05a-contract8414018c4b85";
  lockSha256 = "264e747ad05a536e9ca7639c6cba5a45636b93df0fe3153b4ae040ec14d456e3";
  sourceArchive = pkgs.fetchurl {
    url = "https://codeload.github.com/heimgewebe/grabowski/tar.gz/${sourceRevision}";
    hash = "sha256-qxPpTXFUQ7m7ZCX3eGiy26rDoMyVpmjnzgSgmgKcmdk=";
  };

  # Build the EXISTING root-owned production broker, not a second API.
  brokerPackage = pkgs.runCommand "grabowski-rootbroker-source-6a6360a9" {
    nativeBuildInputs = [ pkgs.makeWrapper pkgs.gnutar pkgs.gzip ];
    passthru = {
      inherit sourceRevision releaseId lockSha256;
      nixosUnitAuthoritySha256 = builtins.hashFile "sha256" ./grabowski-nixos-unit-authority.py;
    };
  } ''
    set -euo pipefail
    mkdir -p "$out/bin" "$out/libexec" "$out/lib/grabowski" extracted
    tar -xzf ${sourceArchive} --strip-components=1 -C extracted

    for module in \
      grabowski_blockades \
      grabowski_blockade_store \
      grabowski_blockade_authority \
      grabowski_command_identity \
      grabowski_privileged_broker \
      grabowski_secret_pty
    do
      install -m 0644 "extracted/src/$module.py" "$out/lib/grabowski/$module.py"
    done
    install -m 0644 extracted/tools/grabowski_privileged_broker.py \
      "$out/libexec/grabowski-privileged-broker.py"
    # The original operator's broker-ready contract also needs the ORIGINAL
    # request CLI. It is a user-mode socket client, never another root daemon.
    install -m 0644 extracted/tools/grabowski_privileged_request.py \
      "$out/libexec/grabowski-privileged-request.py"

    # Immutable Nix source replaces the mutable Pop!/usr/local import path.
    # Pin systemd executables, never use PATH lookup for privileged actions.
    substituteInPlace "$out/libexec/grabowski-privileged-broker.py" \
      --replace-fail 'LIB_DIR = Path("/usr/local/lib/grabowski")' \
        "LIB_DIR = Path(\"$out/lib/grabowski\")" \
      --replace-fail 'SYSTEMCTL = "/usr/bin/systemctl"' \
        'SYSTEMCTL = "${pkgs.systemd}/bin/systemctl"'

    substituteInPlace "$out/lib/grabowski/grabowski_privileged_broker.py" \
      --replace-fail '"/usr/bin/systemctl"' \
        '"${pkgs.systemd}/bin/systemctl"' \
      --replace-fail '"/usr/bin/journalctl"' \
        '"${pkgs.systemd}/bin/journalctl"' \
      --replace-fail '"/usr/bin/systemd-run"' \
        '"${pkgs.systemd}/bin/systemd-run"'

    # NixOS renders the canonical root-owned service fragment through /etc
    # symlinks to immutable Store units, and executes the pinned Python wrapper.
    # Keep original SO_PEERCRED, systemd MainPID, cgroup and cmdline proofs.
    # Fail loudly if upstream text changes: this must never silently drift.
    install -m 0644 ${./grabowski-nixos-unit-authority.py} \
      "$out/lib/grabowski/grabowski_nixos_unit_authority.py"
    ${pkgs.python3}/bin/python3 -B - "$out/libexec/grabowski-privileged-broker.py" <<'PY'
from pathlib import Path
import sys
p = Path(sys.argv[1])
code = p.read_text(encoding="utf-8")

def replace_once(old: str, new: str) -> None:
    global code
    if code.count(old) != 1:
        raise SystemExit(f"rootbroker NixOS patch preimage mismatch: {old!r}")
    code = code.replace(old, new)

replace_once("sys.path.insert(0, str(LIB_DIR))", """sys.path.insert(0, str(LIB_DIR))
import grabowski_nixos_unit_authority as nixos_auth""")
replace_once(
    "or fragment != OPERATOR_UNIT_PATH",
    "or not nixos_auth.fragment_allowed(fragment, etc_fragment=OPERATOR_UNIT_PATH)",
)
fragment_start = """    try:
        fragment_meta = fragment.lstat()
"""
fragment_end = """    return {
"""
if code.count(fragment_start) != 1:
    raise SystemExit("broker fragment safety preimage changed")
start = code.index(fragment_start)
end = code.index(fragment_end, start)
code = code[:start] + """    if not nixos_auth.fragment_trusted(fragment, etc_fragment=OPERATOR_UNIT_PATH):
        raise PermissionError("blockade lifecycle operator system unit fragment is unsafe")
""" + code[end:]
expected_start = "def _operator_expected_argv(home: str) -> tuple[str, ...]:"
expected_end = "def _process_cmdline(pid: int, *, proc_root: Path) -> tuple[str, ...]:"
if code.count(expected_start) != 1 or code.count(expected_end) != 1:
    raise SystemExit("broker expected process-argv preimage changed")
start = code.index(expected_start)
end = code.index(expected_end, start)
code = code[:start] + """def _operator_expected_argv(home: str) -> tuple[str, ...]:
    if not isinstance(home, str) or not home.startswith("/") or chr(0) in home:
        raise PermissionError("blockade lifecycle operator home is invalid")
    return nixos_auth.expected_operator_argv()


""" + code[end:]
for required in (
    "systemd_main_pid != pid",
    "_validate_system_cgroup_authority(",
    "_process_cmdline(pid, proc_root=proc_root) != effective_expected_argv",
    "_socket_peer_credentials(descriptor)",
):
    if required not in code:
        raise SystemExit(f"Rootbroker canonical peer trust check missing: {required}")
p.write_text(code, encoding="utf-8")
PY
    # Unsupported Debian dpkg/Snap/root-package actions intentionally remain
    # unavailable on NixOS. No alternate privileged package path is invented.
    makeWrapper "${pkgs.python3}/bin/python3" \
      "$out/bin/grabowski-privileged-broker" \
      --add-flags "$out/libexec/grabowski-privileged-broker.py" \
      --set PYTHONDONTWRITEBYTECODE 1

    makeWrapper "${pkgs.python3}/bin/python3" \
      "$out/bin/grabowski-privileged-request" \
      --add-flags "$out/libexec/grabowski-privileged-request.py" \
      --set PYTHONDONTWRITEBYTECODE 1
    "$out/bin/grabowski-privileged-request" --help >/dev/null

    # No socket, root policy, or system state is accessed during this import.
    ${pkgs.python3}/bin/python3 -B -c '
import runpy
runpy.run_path(
    "'$out'/libexec/grabowski-privileged-broker.py",
    run_name="nixos_package_import_smoke",
)
'
    chmod 0444 "$out/libexec/grabowski-privileged-broker.py" \
      "$out/libexec/grabowski-privileged-request.py" "$out/lib/grabowski/"*.py
  '';
in
if args ? packageOnly && args.packageOnly then brokerPackage else {
  # No activation until the equally pinned FULL operator and private
  # allowlist pass acceptance. Default remains enable=false.
  heimPc.grabowskiProduction.brokerPackage = lib.mkDefault brokerPackage;
}