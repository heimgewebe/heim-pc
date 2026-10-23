{ lib, pkgs, ... }:
let
  # Exact Git revision of the last verified Pop!_OS operator release.
  # This publicly verifiable source archive contains no live host credentials.
  sourceRevision = "dd6dc690285b6a8a0cdbb3c18d84a1681e604923";
  sourceArchive = pkgs.fetchurl {
    url = "https://codeload.github.com/heimgewebe/grabowski/tar.gz/${sourceRevision}";
    hash = "sha256-rEsGU4mWRbti570DialOPusjZvFK1gfk7UUiI9pbrf4=";
  };

  # Build the EXISTING root-owned production broker, not a second API.
  brokerPackage = pkgs.runCommand "grabowski-rootbroker-source-dd6dc690" {
    nativeBuildInputs = [ pkgs.makeWrapper pkgs.gnutar pkgs.gzip ];
    passthru = { inherit sourceRevision; };
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

    # Unsupported Debian dpkg/Snap/root-package actions intentionally remain
    # unavailable on NixOS. No alternate privileged package path is invented.
    makeWrapper "${pkgs.python3}/bin/python3" \
      "$out/bin/grabowski-privileged-broker" \
      --add-flags "$out/libexec/grabowski-privileged-broker.py" \
      --set PYTHONDONTWRITEBYTECODE 1

    # No socket, root policy, or system state is accessed during this import.
    ${pkgs.python3}/bin/python3 -B -c '
import runpy
runpy.run_path(
    "'$out'/libexec/grabowski-privileged-broker.py",
    run_name="nixos_package_import_smoke",
)
'
    chmod 0444 "$out/libexec/grabowski-privileged-broker.py" "$out/lib/grabowski/"*.py
  '';
in
{
  # No activation until the equally pinned FULL operator and private
  # allowlist pass acceptance. Default remains enable=false.
  heimPc.grabowskiProduction.brokerPackage = lib.mkDefault brokerPackage;
}
