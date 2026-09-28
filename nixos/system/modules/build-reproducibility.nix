{ config, lib, pkgs, ... }:
let
  # Nixpkgs c5c4a43 builds hwdb.bin with --root=$(pwd). systemd-hwdb
  # records source filenames in the database, so the transient Nix build root
  # becomes part of the output bytes. Keep the exact package set and compiler,
  # but pass a stable relative root so independently fresh builds converge.
  deterministicHwdbBin =
    pkgs.runCommand "hwdb.bin"
      {
        preferLocalBuild = true;
        allowSubstitutes = false;
        packages = lib.unique (
          map toString ([ config.systemd.package ] ++ config.services.udev.packages)
        );
      }
      ''
        mkdir -p etc/udev/hwdb.d
        for i in $packages; do
          echo "Adding hwdb files for package $i"
          for j in $i/{etc,lib}/udev/hwdb.d/*; do
            cp "$j" "etc/udev/hwdb.d/$(basename "$j")"
          done
        done

        echo "Generating hwdb database with a stable relative root..."
        res="$(${pkgs.buildPackages.systemd}/bin/systemd-hwdb --root=. update 2>&1)"
        echo "$res"
        [ -z "$(echo "$res" | egrep '^Error')" ]
        mv etc/udev/hwdb.bin "$out"
      '';

  baseNvidiaPackage = config.boot.kernelPackages.nvidiaPackages.stable;
  deterministicNvidiaPackage = baseNvidiaPackage.overrideAttrs (oldAttrs: {
    passthru = oldAttrs.passthru // {
      # The proprietary module derivation invokes the unwrapped compiler
      # directly. Its DWARF therefore retained the transient Nix build root,
      # which also changed the GNU build-id. Map only that build-root prefix;
      # runtime module contents and all non-debug inputs remain unchanged.
      mod = oldAttrs.passthru.mod.overrideAttrs (oldModAttrs: {
        preBuild = (oldModAttrs.preBuild or "") + ''
          export KCFLAGS="''${KCFLAGS-} -fdebug-prefix-map=$NIX_BUILD_TOP=/build/nvidia-kernel-modules -ffile-prefix-map=$NIX_BUILD_TOP=/build/nvidia-kernel-modules"
        '';
      });
    };
  });
in
{
  environment.etc."udev/hwdb.bin".source = lib.mkForce deterministicHwdbBin;

  hardware.nvidia.package = lib.mkIf config.heimPc.hardware.nvidia.enable (
    lib.mkForce deterministicNvidiaPackage
  );
}
