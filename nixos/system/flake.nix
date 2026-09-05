{
  description = "Isolated heim-pc-as-code prototype for NixOS 26.05";

  inputs = {
    nixpkgs.url = "github:NixOS/nixpkgs/nixos-26.05";
    microvm = {
      url = "github:microvm-nix/microvm.nix";
      inputs.nixpkgs.follows = "nixpkgs";
    };
  };

  outputs = { self, nixpkgs, microvm }:
    let
      system = "x86_64-linux";
      pkgs = import nixpkgs { inherit system; config.allowUnfree = true; };
      sourceRevision =
        if self ? rev then self.rev
        else if self ? dirtyRev then self.dirtyRev
        else "prototype-unbound";

      # Cheap fail-closed admission gate. Keep this separate from the expensive
      # host/VM closure so an unbound or dirty source is rejected before any
      # production-shaped system dependency needs to build.
      provenanceGuard = pkgs.runCommand "heim-pc-provenance-guard" {
        nativeBuildInputs = [ pkgs.gnugrep ];
      } ''
        printf '%s\n' ${nixpkgs.lib.escapeShellArg sourceRevision} | grep -Eq '^[0-9a-f]{40}$' || {
          echo "strict provenance requires a clean 40-hex Git-backed flake revision" >&2
          exit 1
        }
        mkdir -p "$out"
        printf '%s\n' ${nixpkgs.lib.escapeShellArg sourceRevision} > "$out/source-revision"
      '';

      # NixOS' system.build.vm boots virtualisation.vmVariant, which has its own
      # toplevel and /etc closure. Preserve both identities instead of pretending
      # that the declarative proof configuration and its transformed VM runtime
      # are the same Store object.
      proofConfig = self.nixosConfigurations.heim-pc-vm.config;
      proofVmConfig = proofConfig.virtualisation.vmVariant;

      # Proof/promotion-shaped bundle: one admitted Git revision plus the exact
      # declared proof configuration, the exact VM runtime variant and the runner
      # that boots it. Bare-metal promotion will later bind the real heim-pc host
      # closure separately; this bundle is deliberately scoped to the VM proof.
      provenanceBundle = pkgs.runCommand "heim-pc-provenance-bundle" { } ''
        test -s ${provenanceGuard}/source-revision
        mkdir -p "$out"
        ln -s ${proofConfig.system.build.toplevel} "$out/declared-system"
        ln -s ${proofConfig.system.build.etc} "$out/declared-etc"
        ln -s ${proofConfig.system.build.vm} "$out/vm-runner"
        ln -s ${proofVmConfig.system.build.toplevel} "$out/runtime-system"
        ln -s ${proofVmConfig.system.build.etc} "$out/runtime-etc"
        cp ${provenanceGuard}/source-revision "$out/source-revision"
      '';
    in {
      nixosConfigurations.heim-pc = nixpkgs.lib.nixosSystem {
        inherit system;
        specialArgs = {
          inherit self;
          heimPcProfile = {
            nvidia = true;
            nvidiaOpen = false;
            desktop = true;
            physicalGates = false;
          };
        };
        modules = [ ./hosts/heim-pc ];
      };

      # Build-only physical Gate-A/B/D profiles. Both retain the deliberately
      # impossible root label and cannot be installed as-is. The only difference
      # between the two is NVIDIA's proprietary vs open kernel-module path, so a
      # future second-disk test can falsify that choice causally on the RTX 4070 Ti SUPER.
      nixosConfigurations.heim-pc-physical-gate-proprietary = nixpkgs.lib.nixosSystem {
        inherit system;
        specialArgs = {
          inherit self;
          heimPcProfile = {
            nvidia = true;
            nvidiaOpen = false;
            desktop = true;
            physicalGates = true;
          };
        };
        modules = [ ./hosts/heim-pc ];
      };

      nixosConfigurations.heim-pc-physical-gate-open = nixpkgs.lib.nixosSystem {
        inherit system;
        specialArgs = {
          inherit self;
          heimPcProfile = {
            nvidia = true;
            nvidiaOpen = true;
            desktop = true;
            physicalGates = true;
          };
        };
        modules = [ ./hosts/heim-pc ];
      };

      # Non-installing physical Gate-A/B live media. These import only the
      # generic ISO image mechanism, not NixOS' installation-device or graphical
      # installer profiles. Root is tmpfs, the Nix Store is squashfs+overlay, and
      # the live user has no wheel/sudo/UDisks/SSH path to the production disk.
      nixosConfigurations.heim-pc-live-gate-proprietary = nixpkgs.lib.nixosSystem {
        inherit system;
        specialArgs = {
          inherit self;
          heimPcLiveProfile = {
            nvidiaOpen = false;
            edition = "proprietary";
          };
        };
        modules = [
          (nixpkgs + "/nixos/modules/installer/cd-dvd/iso-image.nix")
          ./modules/desktop.nix
          ./modules/nvidia.nix
          ./modules/audio.nix
          ./modules/containers.nix
          ./modules/physical-gates.nix
          ./modules/live-media.nix
        ];
      };

      nixosConfigurations.heim-pc-live-gate-open = nixpkgs.lib.nixosSystem {
        inherit system;
        specialArgs = {
          inherit self;
          heimPcLiveProfile = {
            nvidiaOpen = true;
            edition = "open";
          };
        };
        modules = [
          (nixpkgs + "/nixos/modules/installer/cd-dvd/iso-image.nix")
          ./modules/desktop.nix
          ./modules/nvidia.nix
          ./modules/audio.nix
          ./modules/containers.nix
          ./modules/physical-gates.nix
          ./modules/live-media.nix
        ];
      };

      nixosConfigurations.heim-pc-vm = nixpkgs.lib.nixosSystem {
        inherit system;
        specialArgs = {
          inherit self;
          heimPcProfile = {
            nvidia = false;
            nvidiaOpen = false;
            desktop = false;
            physicalGates = false;
          };
        };
        modules = [ ./hosts/heim-pc ];
      };

      # Negative pre-deployment proof is exported as a module, not as a normal
      # nixosConfiguration. Regular `nix flake check` must remain healthy; CI
      # instantiates this module explicitly and requires evaluation to fail.
      nixosModules.intentionalBreak = { ... }: {
        assertions = [{
          assertion = false;
          message = "intentional pre-deployment failure for rollback-path evidence";
        }];
      };

      # Concrete future-architecture proof: untrusted coding agents are
      # separate NixOS closures behind a KVM boundary. The zone module owns
      # the fail-closed capability contract; the Flake owns its identity.
      nixosConfigurations.agent-zone = nixpkgs.lib.nixosSystem {
        inherit system;
        modules = [
          microvm.nixosModules.microvm
          ./zones/agent.nix
        ];
      };

      # Test-only variant: same fail-closed zone plus a real host capability
      # handshake over AF_VSOCK. It still has no IP interface or host share.
      nixosConfigurations.agent-zone-vsock-proof = nixpkgs.lib.nixosSystem {
        inherit system;
        modules = [
          microvm.nixosModules.microvm
          ./zones/agent.nix
          ./tests/vsock-broker.nix
        ];
      };

      # Host-side proof that the same Flake can own lifecycle wiring for the
      # agent VM. This configuration is build-only and uses a tmpfs root; it
      # is never switched onto the physical heim-pc.
      nixosConfigurations.trust-zone-host = nixpkgs.lib.nixosSystem {
        inherit system;
        modules = [
          microvm.nixosModules.host
          ({ ... }: {
            networking.hostName = "heim-pc-trust-zone-host-proof";
            fileSystems."/" = {
              device = "none";
              fsType = "tmpfs";
            };
            boot.loader.grub.enable = false;
            microvm.vms."agent-zone" = {
              flake = self;
              autostart = true;
            };
            system.stateVersion = "26.05";
          })
        ];
      };

      packages.${system} = {
        heim-pc-system = self.nixosConfigurations.heim-pc.config.system.build.toplevel;
        physical-gate-proprietary-system = self.nixosConfigurations.heim-pc-physical-gate-proprietary.config.system.build.toplevel;
        physical-gate-open-system = self.nixosConfigurations.heim-pc-physical-gate-open.config.system.build.toplevel;
        physical-gate-live-proprietary-iso = self.nixosConfigurations.heim-pc-live-gate-proprietary.config.system.build.isoImage;
        physical-gate-live-open-iso = self.nixosConfigurations.heim-pc-live-gate-open.config.system.build.isoImage;
        vm = self.nixosConfigurations.heim-pc-vm.config.system.build.vm;
        provenance-guard = provenanceGuard;
        provenance-bundle = provenanceBundle;
        agent-microvm = self.nixosConfigurations.agent-zone.config.microvm.declaredRunner;
        agent-vsock-proof-microvm = self.nixosConfigurations.agent-zone-vsock-proof.config.microvm.declaredRunner;
        trust-zone-host-system = self.nixosConfigurations.trust-zone-host.config.system.build.toplevel;
      };

      checks.${system} = {
        integration = import ./tests/integration.nix { inherit pkgs; };
        trust-zones = import ./tests/trust-zones.nix { inherit pkgs; };
      };

      devShells.${system}.default = pkgs.mkShell {
        packages = with pkgs; [ git gh nodejs python3 rustc cargo jq ripgrep ];
      };
    };
}
