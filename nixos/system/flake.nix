{
  description = "Isolated heim-pc-as-code prototype for NixOS 26.05";

  inputs = {
    nixpkgs.url = "github:NixOS/nixpkgs/nixos-26.05";
    microvm = {
      url = "github:microvm-nix/microvm.nix";
      inputs.nixpkgs.follows = "nixpkgs";
    };
    nixer.url = "github:heimgewebe/nixer/c0b75cfd580c221f8a5095fbf802c4f6386a017e";
  };

  outputs = { self, nixpkgs, microvm, nixer }:
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
      # One storage/boot base for the candidate and both physical proof variants.
      hostModules = [ nixer.nixosModules.default ./modules/nixer.nix ./hosts/heim-pc ];
      physicalHostModules = hostModules ++ [ ./modules/storage-layout.nix ];

      # Issue #202: Limine module OPTION compatibility, evaluated over the
      # existing storage topology. This is NOT a bootable signed NixOS target.
      # The current systemd-boot-specific hook supplies private rd.luks
      # arguments only after bootloader installation; disabling it
      # drops them. Actual target boot-chain signing/injection remains
      # unimplemented and cannot be inferred from this evaluation.
      # Keep private to let: no selectable host/package, no key/EFI actions.
      limineStorageTargetProof = nixpkgs.lib.nixosSystem {
        inherit system;
        specialArgs = {
          inherit self;
          heimPcProfile = {
            physical = true;
            nvidia = true;
            nvidiaOpen = false;
            desktop = true;
            physicalGates = false;
          };
        };
        modules = physicalHostModules ++ [
          ({ lib, ... }: {
            boot.loader.systemd-boot.enable = lib.mkForce false;
            boot.loader.limine = {
              enable = true;
              secureBoot.enable = true;
              secureBoot.autoGenerateKeys = false;
              secureBoot.autoEnrollKeys.enable = false;
              enableEditor = false;
              validateChecksums = true;
              panicOnChecksumMismatch = true;
              enrollConfig = true;
              efiInstallAsRemovable = true;
              biosSupport = false;
            };
            boot.loader.efi.canTouchEfiVariables = lib.mkForce false;
          })
        ];
      };

      # Issue #202: evaluation-only companion for synthetic LUKS arguments.
      # The baseline Limine options proof above intentionally contains NO
      # rd.luks parameters. This second private configuration demonstrates that
      # the NixOS module graph accepts an explicit systemd-initrd LUKS command
      # line under Limine's Secure Boot options; no real PARTUUID is embedded.
      # It does NOT sign/enroll the generated Limine config, build a bootable
      # encrypted root, authenticate keys, or permit physical installation.
      limineSyntheticLuksArgsProof = nixpkgs.lib.nixosSystem {
        inherit system;
        specialArgs = {
          inherit self;
          heimPcProfile = {
            physical = true;
            nvidia = true;
            nvidiaOpen = false;
            desktop = true;
            physicalGates = false;
          };
        };
        modules = physicalHostModules ++ [
          ({ lib, ... }: {
            boot.loader.systemd-boot.enable = lib.mkForce false;
            boot.loader.limine = {
              enable = true;
              secureBoot.enable = true;
              secureBoot.autoGenerateKeys = false;
              secureBoot.autoEnrollKeys.enable = false;
              enableEditor = false;
              validateChecksums = true;
              panicOnChecksumMismatch = true;
              enrollConfig = true;
              efiInstallAsRemovable = true;
              biosSupport = false;
            };
            boot.loader.efi.canTouchEfiVariables = lib.mkForce false;
            boot.kernelParams = [
              "rd.luks.name=11111111-2222-4333-8444-555555555555=heimpc-nixos-crypt"
              "rd.luks.options=11111111-2222-4333-8444-555555555555=tpm2-device=auto,headless=yes"
            ];
          })
        ];
      };

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
            physical = true;
            nvidia = true;
            nvidiaOpen = false;
            desktop = true;
            physicalGates = false;
          };
        };
        modules = hostModules;
      };

      # Build-only closure for T011/T003. Unlike the deliberately impossible
      # prototype host, its boot filesystems are derived from the exact storage
      # rehearsal contract so the built closure can be booted on that topology.
      nixosConfigurations.heim-pc-storage-target = nixpkgs.lib.nixosSystem {
        inherit system;
        specialArgs = {
          inherit self;
          heimPcProfile = {
            physical = true;
            nvidia = true;
            nvidiaOpen = false;
            desktop = true;
            physicalGates = false;
          };
        };
        modules = physicalHostModules;
      };

      # Build-only physical Gate-A/B/D variants of the same storage candidate.
      # Gates add proof tooling; the paired variants differ only in the NVIDIA
      # kernel-module choice. Neither authorizes physical installation or boot.
      nixosConfigurations.heim-pc-physical-gate-proprietary = nixpkgs.lib.nixosSystem {
        inherit system;
        specialArgs = {
          inherit self;
          heimPcProfile = {
            physical = true;
            nvidia = true;
            nvidiaOpen = false;
            desktop = true;
            physicalGates = true;
          };
        };
        modules = physicalHostModules;
      };

      nixosConfigurations.heim-pc-physical-gate-open = nixpkgs.lib.nixosSystem {
        inherit system;
        specialArgs = {
          inherit self;
          heimPcProfile = {
            physical = true;
            nvidia = true;
            nvidiaOpen = true;
            desktop = true;
            physicalGates = true;
          };
        };
        modules = physicalHostModules;
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
          ./modules/physical-gates.nix
          ./modules/live-media.nix
        ];
      };

      # Dedicated non-installing offline inventory live media. The shared live
      # module keeps Gate A/B defaults unchanged and narrows this variant to the
      # root-owned one-shot inventory service with networking and desktop off.
      nixosConfigurations.heim-pc-live-inventory = nixpkgs.lib.nixosSystem {
        inherit system;
        specialArgs = {
          inherit self;
          heimPcSourceRevision = sourceRevision;
          heimPcLiveProfile = {
            nvidiaOpen = false;
            edition = "inventory";
            inventoryMode = true;
          };
        };
        modules = [
          (nixpkgs + "/nixos/modules/installer/cd-dvd/iso-image.nix")
          ./modules/desktop.nix
          ./modules/nvidia.nix
          ./modules/physical-gates.nix
          ./modules/live-media.nix
        ];
      };

      # Disposable, USB-free console-first NixOS on the internal Seagate only.
      # This does not change any production install/apply admission policy.
      nixosConfigurations.heim-pc-stage0 = nixpkgs.lib.nixosSystem {
        inherit system;
        modules = [ ./modules/stage0-no-usb.nix ];
      };

      # Separate remote-ready first-boot variant. The established isolated
      # console-only Stage0 and its no-SSH assertions are deliberately intact.
      # Public keys are staged into alex's persistent home on the Seagate,
      # never embedded into the Nix store. Tailscale needs separate enrollment.
      nixosConfigurations.heim-pc-stage0-remote = nixpkgs.lib.nixosSystem {
        inherit system;
        modules = [
          ./modules/stage0-no-usb.nix
          ({ lib, ... }: {
            services.openssh.enable = lib.mkForce true;
            services.openssh.openFirewall = true;
            services.openssh.settings = {
              PasswordAuthentication = false;
              KbdInteractiveAuthentication = false;
              PermitRootLogin = "no";
              AllowUsers = [ "alex" ];
            };
            services.tailscale.enable = true;
            services.getty.autologinUser = "alex";
            security.sudo.wheelNeedsPassword = lib.mkForce false;
          })
        ];
      };

      # Incremental, deliberately non-activating migration candidate based on
      # the physically verified unencrypted Seagate Stage0 mounts. This does
      # not supersede the separate encrypted production storage contract.
      nixosConfigurations.heim-pc-seagate-primary-candidate = nixpkgs.lib.nixosSystem {
        inherit system;
        modules = [
          ./modules/seagate-primary-candidate.nix
          ({ ... }: {
            # Candidate runtime identity must bind to the exact clean source.
            # Source-only evaluations from a dirty checkout are not releases.
            system.configurationRevision = sourceRevision;
            environment.etc."heim-pc/source-revision".text = sourceRevision;
            assertions = [{
              assertion = builtins.match "^[0-9a-f]{40}$" sourceRevision != null;
              message = "Seagate primary activation requires an exact clean Git revision";
            }];
          })
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
        modules = hostModules;
      };

      # Source-only workstation successor to the headless Seagate primary
      # baseline. Reuses the physically tested, unencrypted Stage0 mounts and
      # never changes BootOrder, protected WD_BLACK or production enablement.
      # NVIDIA/Plasma hardware remains subject to a separate PHYSICAL proof.
      nixosConfigurations.heim-pc-seagate-workstation-candidate =
        self.nixosConfigurations.heim-pc-seagate-primary-candidate.extendModules {
          modules = [
            ./modules/desktop.nix
            ./modules/nvidia.nix
            ./modules/audio.nix
            ./modules/development.nix
            ./modules/containers.nix
            ({ lib, ... }: {
              # Stage0 deliberately has X disabled; override ONLY in this
              # explicitly named, non-activated workstation successor.
              services.xserver.enable = lib.mkForce true;
              nixpkgs.config.allowUnfreePredicate = pkg:
                lib.hasPrefix "nvidia-" (lib.getName pkg);
              heimPc.desktop.enable = true;
              heimPc.hardware.nvidia.enable = true;
            })
          ];
        };

      # Separate SOURCE-ONLY headless-agent integration. The existing Plasma
      # candidate stays free of Nixer or other session-scoped background units.
      # This successor uses the exact pinned upstream package but hosts its
      # loopback MCP endpoint as a system service under unprivileged alex.
      nixosConfigurations.heim-pc-seagate-nixer-headless-candidate =
        self.nixosConfigurations.heim-pc-seagate-workstation-candidate.extendModules {
          modules = [
            nixer.nixosModules.default
            ./modules/nixer-headless.nix
            ({ ... }: { heimPc.nixerHeadless.enable = true; })
          ];
        };

      # Explicit SOURCE-ONLY full-operator successor. The first three
      # profiles and their already tested physical Stage0 boot remain unchanged.
      # Real private Rootbroker policy is provisioned by root from /persist;
      # on this physical host it has NOT been provisioned or accepted yet.
      # Accordingly the policy, socket and operator must fail closed at boot
      # until separate host authority and runtime acceptance exist.
      nixosConfigurations.heim-pc-seagate-grabowski-headless-candidate =
        self.nixosConfigurations.heim-pc-seagate-nixer-headless-candidate.extendModules {
          modules = [
            ({ pkgs, ... }: {
              # The original operator's bounded task/job tools call systemd-run --user.
              # Enable this manager only for the full, explicit Grabowski successor.
              users.users.alex.linger = pkgs.lib.mkForce true;
              heimPc.grabowskiProduction = {
                enable = true;
                operatorPackage =
                  import ./modules/grabowski-operator-package.nix { inherit pkgs; };
                brokerPackage = import ./modules/grabowski-broker-package.nix {
                  inherit pkgs;
                  lib = pkgs.lib;
                  packageOnly = true;
                };
                releaseId =
                  "dd6dc690285b-srcset5c51dbd24485-lock264e747ad05a-contract2681d2593edc";
              };
            })
          ];
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
        grabowski-operator-pinned = import ./modules/grabowski-operator-package.nix { inherit pkgs; };
        # Optional real systemd + socket + MCP VM proof. Never a physical host.
        grabowski-headless-systemd-vm-proof =
          import ./tests/grabowski-headless-systemd.nix { inherit pkgs; };
        # Explicit KVM-only proof for the original Nixer MCP in system scope.
        # One VM must deny startup without its pinned image; a second VM
        # bypasses ONLY the test preflight to exercise the real MCP process.
        nixer-headless-systemd-vm-proof =
          import ./tests/nixer-headless-systemd.nix { inherit pkgs nixer; };
        heim-pc-system = self.nixosConfigurations.heim-pc.config.system.build.toplevel;
        heim-pc-stage0-system = self.nixosConfigurations.heim-pc-stage0.config.system.build.toplevel;
        heim-pc-storage-target-system = self.nixosConfigurations.heim-pc-storage-target.config.system.build.toplevel;
        physical-gate-proprietary-system = self.nixosConfigurations.heim-pc-physical-gate-proprietary.config.system.build.toplevel;
        physical-gate-open-system = self.nixosConfigurations.heim-pc-physical-gate-open.config.system.build.toplevel;
        physical-gate-live-proprietary-iso = self.nixosConfigurations.heim-pc-live-gate-proprietary.config.system.build.isoImage;
        physical-gate-live-open-iso = self.nixosConfigurations.heim-pc-live-gate-open.config.system.build.isoImage;
        physical-gate-live-inventory-iso = self.nixosConfigurations.heim-pc-live-inventory.config.system.build.isoImage;
        vm = self.nixosConfigurations.heim-pc-vm.config.system.build.vm;
        provenance-guard = provenanceGuard;
        provenance-bundle = provenanceBundle;
        # Optional real SDDM/Plasma Wayland credential proof. Keep this out of
        # checks: mandatory CI retains the smaller headless state-machine test,
        # while this target is run explicitly on a KVM-capable proof host.
        firstboot-gui-proof = import ./tests/firstboot-gui-proof.nix {
          inherit pkgs sourceRevision;
        };
        agent-microvm = self.nixosConfigurations.agent-zone.config.microvm.declaredRunner;
        agent-vsock-proof-microvm = self.nixosConfigurations.agent-zone-vsock-proof.config.microvm.declaredRunner;
        trust-zone-host-system = self.nixosConfigurations.trust-zone-host.config.system.build.toplevel;
      };

      checks.${system} = {
        # Built artifact admission, not a live privileged-action or boot test.
        # This check forces BOTH immutable binaries into the closure, verifies
        # the complete locked operator startup import and compares the release
        # manifest to the canonical broker/operator revision and runtime lock.
        grabowski-release-artifacts =
          let
            operator = import ./modules/grabowski-operator-package.nix { inherit pkgs; };
            broker = import ./modules/grabowski-broker-package.nix {
              inherit (nixpkgs) lib;
              inherit pkgs;
              packageOnly = true;
            };
            release = "dd6dc690285b-srcset5c51dbd24485-lock264e747ad05a-contract2681d2593edc";
            revision = "dd6dc690285b6a8a0cdbb3c18d84a1681e604923";
            lockSha256 = "264e747ad05a536e9ca7639c6cba5a45636b93df0fe3153b4ae040ec14d456e3";
          in
          assert operator.passthru.releaseId == release && broker.passthru.releaseId == release;
          assert operator.passthru.sourceRevision == revision && broker.passthru.sourceRevision == revision;
          assert operator.passthru.lockSha256 == lockSha256 && broker.passthru.lockSha256 == lockSha256;
          pkgs.runCommand "grabowski-exact-release-artifacts" {
            nativeBuildInputs = [ pkgs.coreutils pkgs.gnugrep pkgs.python312 ];
          } ''
            set -euo pipefail
            test -x ${operator}/bin/grabowski-operator
            test -x ${broker}/bin/grabowski-privileged-broker
            test -x ${broker}/bin/grabowski-privileged-request
            ${broker}/bin/grabowski-privileged-request --help > "$TMPDIR/broker-request-help"
            grep -Fq 'reference_file' "$TMPDIR/broker-request-help"
            test -s ${broker}/libexec/grabowski-privileged-broker.py
            printf '%s  %s\n' ${lockSha256} \
              ${operator}/share/grabowski/requirements/runtime.lock.txt | sha256sum -c -
            ${operator}/bin/grabowski-operator --help > "$TMPDIR/operator-help"
            grep -Fq 'streamable-http' "$TMPDIR/operator-help"
            # The original rootbroker checks exact /proc/<MainPID>/cmdline.
            # The Nix-generated wrapper MUST retain its own pinned path in
            # argv[0] when exec'ing Python; --help alone does not prove this.
            grep -Fq 'exec -a "${operator}/bin/grabowski-operator"' \
              "${operator}/bin/grabowski-operator"
            ${pkgs.python312}/bin/python3 -B - <<'PY'
import json
from pathlib import Path
root = Path("${operator}")
manifest = json.loads((root / "share/grabowski/nixos-release.json").read_text())
expected = {
  "schema_version": 1,
  "release_id": "${release}",
  "source_revision": "${revision}",
  "runtime_lock_sha256": "${lockSha256}",
  "entrypoint": "bin/grabowski-operator",
  "transport": "streamable-http",
  "host": "127.0.0.1",
  "port": 18181,
}
if manifest != expected:
    raise SystemExit("operator release manifest does not match the pinned broker and lock")
for name in ("grabowski_operator.py", "grabowski_mcp.py", "grabowski_runtime_contract.py"):
    if not (root / "lib/python3.12/site-packages" / name).is_file():
        raise SystemExit(f"missing full operator module {name}")
PY
            # Runtime assembly must match the full original 203-tool MCP
            # surface, not the older 53-tool core. Register tools only; no
            # MCP listener, privileged operation or production state is used.
            PYTHONPATH="${operator}/lib/python3.12/site-packages" \
              ${pkgs.python312}/bin/python3 -B - <<'PY'
import importlib
import json
from pathlib import Path
contract = json.loads(Path("${operator}/share/grabowski/config/runtime-entrypoint.json").read_text())
if (contract.get("mode"), contract.get("module"), contract.get("source")) != (
    "module", "grabowski_operator", "src/grabowski_runtime.py"
):
    raise SystemExit("pinned canonical runtime module/source contract changed")
expected = contract.get("expected_tools")
if not isinstance(expected, list) or len(expected) != 203 or len(set(expected)) != 203:
    raise SystemExit("canonical runtime tool list is incomplete")
actual = [
    tool.name
    for tool in importlib.import_module("grabowski_operator").mcp._tool_manager.list_tools()
]
if len(actual) != 203 or set(actual) != set(expected):
    raise SystemExit(
        "Nix Grabowski runtime tool surface differs from canonical 203-tool release: "
        + str({"missing": sorted(set(expected) - set(actual)),
               "unexpected": sorted(set(actual) - set(expected))})
    )
PY
            # Prove the real executable reaches the canonical 203-tool MCP
            # surface, not just the legacy 53-tool core. No host resources
            # are mounted and no tools are invoked; only initialize/list.
            PYTHONPATH="${operator}/lib/python3.12/site-packages" \
              ${pkgs.python312}/bin/python3 -B - <<'PY'
import asyncio
import json
import os
from pathlib import Path
import subprocess
import tempfile
import time
from mcp import ClientSession, StdioServerParameters
from mcp.client.stdio import stdio_client

root = Path("${operator}")
binary = str(root / "bin/grabowski-operator")
source_contract = json.loads(
    (root / "share/grabowski/config/runtime-entrypoint.json").read_text()
)
expected = set(source_contract["expected_tools"])
if len(expected) != 203:
    raise SystemExit("canonical expected tool catalog is not exactly 203")

with tempfile.TemporaryDirectory(prefix="nixos-grabowski-mcp-") as home:
    env = {
        "HOME": home,
        "XDG_STATE_HOME": home + "/state",
        "XDG_CONFIG_HOME": home + "/config",
        "PYTHONPATH": os.environ["PYTHONPATH"],
        "PYTHONDONTWRITEBYTECODE": "1",
        "PATH": os.environ.get("PATH", ""),
    }
    # Kernel-observed command-line bytes are checked, not just wrapper text.
    child = subprocess.Popen(
        [binary, "--transport", "stdio"], cwd=home, env=env,
        stdin=subprocess.PIPE, stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )
    try:
        prefix = [
            binary, "-m", "grabowski_operator", "--transport",
            "streamable-http", "--host", "127.0.0.1", "--port", "18181",
        ]
        seen = []
        for _ in range(60):
            if child.poll() is not None:
                raise SystemExit("operator exited before /proc identity readback")
            try:
                raw = Path("/proc") / str(child.pid) / "cmdline"
                seen = [part.decode("utf-8") for part in raw.read_bytes().rstrip(b"\0").split(b"\0")]
            except OSError:
                seen = []
            if seen[:len(prefix)] == prefix:
                break
            time.sleep(0.05)
        if seen[:len(prefix)] != prefix:
            raise SystemExit("operator MainPID command line does not match rootbroker contract")
    finally:
        child.terminate()
        child.wait(timeout=10)

    async def handshake():
        params = StdioServerParameters(
            command=binary, args=["--transport", "stdio"],
            env=env, cwd=home,
        )
        async with stdio_client(params) as (read, write):
            async with ClientSession(read, write) as session:
                await asyncio.wait_for(session.initialize(), timeout=35)
                catalog = await asyncio.wait_for(session.list_tools(), timeout=35)
                observed = {tool.name for tool in catalog.tools}
                if observed != expected:
                    raise RuntimeError(
                        "canonical MCP tool catalog mismatch: missing="
                        + str(sorted(expected - observed))
                        + " unexpected=" + str(sorted(observed - expected))
                    )
                print("verified canonical Grabowski MCP tools:", len(observed))

    asyncio.run(handshake())
PY
            # Real packaged broker (not the fixture) must fail closed for
            # forged peers, even before a root policy or socket is involved.
            ${pkgs.python3}/bin/python3 -B - <<'PY'
import runpy
scope = runpy.run_path(
    "${broker}/libexec/grabowski-privileged-broker.py",
    run_name="nixos_broker_negative_smoke",
)
peer_guard = scope["_validate_blockade_lifecycle_peer"]
unit = {
    "main_pid": 4002,
    "control_group": "/system.slice/grabowski-operator.service",
}
peer_guard.__globals__["_socket_peer_credentials"] = lambda descriptor: (4001, 1000, 1000)
peer_guard.__globals__["_operator_system_unit_identity"] = lambda uid, unit_name: dict(unit)
for request, fragment in (
    ({"allowed_peer_uid": 1001, "allowed_peer_unit": "grabowski-operator.service"}, "UID"),
    ({"allowed_peer_uid": 1000, "allowed_peer_unit": "grabowski-operator.service"}, "MainPID"),
):
    try:
        peer_guard(request, descriptor=0)
    except PermissionError as exc:
        if fragment not in str(exc):
            raise SystemExit(f"wrong negative broker error: {exc}")
    else:
        raise SystemExit("unauthorized peer was accepted")
try:
    scope["_operator_expected_argv"]("/home/alex")
except PermissionError:
    pass
else:
    raise SystemExit("NixOS broker accepted a missing root-owned argv binding")
PY
            mkdir -p "$out"
            cp ${operator}/share/grabowski/nixos-release.json "$out/release.json"
            printf '%s\n' ${broker} > "$out/broker-store-path"
            printf '%s\n' ${operator} > "$out/operator-store-path"
          '';

        # Evaluation-only: Stage0 must be an isolated, root-label-bound
        # console profile with the firmware/WD protections still enforced.
        stage0-no-usb-contract =
          let cfg = self.nixosConfigurations.heim-pc-stage0.config;
          in
          assert cfg.fileSystems."/".device == "/dev/disk/by-label/NIXOS_STAGE0_ROOT";
          assert cfg.fileSystems."/boot".device == "/dev/disk/by-label/NIXOS2_EFI";
          assert cfg.fileSystems."/boot".fsType == "vfat";
          assert cfg.boot.loader.systemd-boot.enable;
          assert !cfg.boot.loader.efi.canTouchEfiVariables;
          assert !cfg.boot.loader.systemd-boot.editor;
          assert !cfg.services.openssh.enable;
          assert !cfg.services.xserver.enable;
          assert cfg.users.mutableUsers;
          assert cfg.services.getty.autologinUser == null;
          assert cfg.boot.initrd.luks.devices == {};
          pkgs.runCommand "heim-pc-stage0-no-usb-contract" {} ''
            mkdir -p "$out"
          '';

        # Evaluation-only bridge from the physical Seagate Stage0 layout to
        # a secure headless core. It is NOT an operator/GUI/boot acceptance.
        seagate-primary-candidate-contract =
          let cfg = self.nixosConfigurations.heim-pc-seagate-primary-candidate.config;
          in
          assert cfg.networking.hostName == "heim-pc";
          assert cfg.system.configurationRevision == sourceRevision;
          assert builtins.match "^[0-9a-f]{40}$" cfg.system.configurationRevision != null;
          assert cfg.fileSystems."/".device == "/dev/disk/by-label/NIXOS_STAGE0_ROOT";
          assert builtins.all (option: builtins.elem option cfg.fileSystems."/nix".options) [ "subvol=@nix" "compress=zstd" ];
          assert builtins.all (option: builtins.elem option cfg.fileSystems."/home".options) [ "subvol=@home" "compress=zstd" ];
          assert builtins.all (option: builtins.elem option cfg.fileSystems."/persist".options) [ "subvol=@persist" "compress=zstd" ];
          assert cfg.fileSystems."/boot".device == "/dev/disk/by-label/NIXOS2_EFI";
          assert cfg.boot.loader.systemd-boot.enable;
          assert !cfg.boot.loader.efi.canTouchEfiVariables;
          assert cfg.services.openssh.enable && cfg.services.openssh.openFirewall;
          assert cfg.services.openssh.settings.PasswordAuthentication == false;
          assert cfg.services.openssh.settings.KbdInteractiveAuthentication == false;
          assert cfg.services.openssh.settings.PermitRootLogin == "no";
          assert cfg.services.openssh.settings.AllowUsers == [ "alex" ];
          assert cfg.services.tailscale.enable;
          assert cfg.services.getty.autologinUser == null;
          assert cfg.security.sudo.wheelNeedsPassword;
          assert !cfg.users.users.alex.linger;
          assert !cfg.services.xserver.enable;
          assert cfg.nix.settings.trusted-users == [ "root" ];
          assert !cfg.nix.gc.automatic;
          assert cfg.heimPc.day2Activation.enable;
          assert !(builtins.hasAttr "grabowski-demo" cfg.systemd.services);
          pkgs.runCommand "heim-pc-seagate-primary-candidate-contract" {} ''
            mkdir -p "$out"
          '';

        # Real source module composition for Plasma 6, NVIDIA and PipeWire
        # against the actual Seagate Stage0 root, not synthetic LUKS storage.
        # A successful evaluation does NOT prove physical GPU or peripherals.
        seagate-workstation-candidate-contract =
          let cfg = self.nixosConfigurations.heim-pc-seagate-workstation-candidate.config;
          in
          assert cfg.system.configurationRevision == sourceRevision;
          assert cfg.fileSystems."/".device == "/dev/disk/by-label/NIXOS_STAGE0_ROOT";
          assert cfg.fileSystems."/boot".device == "/dev/disk/by-label/NIXOS2_EFI";
          assert !cfg.boot.loader.efi.canTouchEfiVariables;
          assert cfg.services.openssh.enable && cfg.services.tailscale.enable;
          assert cfg.services.openssh.settings.PermitRootLogin == "no";
          assert cfg.services.getty.autologinUser == null;
          assert cfg.security.sudo.wheelNeedsPassword;
          assert !cfg.users.users.alex.linger;
          assert !cfg.heimPc.grabowskiProduction.enable;
          assert cfg.heimPc.desktop.enable && cfg.heimPc.hardware.nvidia.enable;
          assert cfg.services.xserver.enable;
          assert cfg.services.displayManager.sddm.enable;
          assert cfg.services.desktopManager.plasma6.enable;
          assert cfg.hardware.nvidia.modesetting.enable;
          # The physical Stage0 console fallback remains nomodeset, but Plasma
          # and NVIDIA DRM require the graphical successor to drop that flag.
          assert builtins.elem "nomodeset"
            self.nixosConfigurations.heim-pc-stage0.config.boot.kernelParams;
          assert !(builtins.elem "nomodeset" cfg.boot.kernelParams);
          assert cfg.services.pipewire.enable;
          assert cfg.virtualisation.podman.enable;
          pkgs.runCommand "heim-pc-seagate-workstation-candidate-contract" {} ''
            mkdir -p "$out"
          '';

        # The Nixer specialist is an unprivileged *system* service; the
        # upstream session-based service is not activated and alex.linger
        # stays disabled. No unreviewed OCI pull is performed by Nixer.
        seagate-nixer-headless-contract =
          let
            cfg = self.nixosConfigurations.heim-pc-seagate-nixer-headless-candidate.config;
            unit = cfg.systemd.services.nixer-headless;
            sc = unit.serviceConfig;
          in
          assert cfg.system.configurationRevision == sourceRevision;
          assert cfg.fileSystems."/".device == "/dev/disk/by-label/NIXOS_STAGE0_ROOT";
          assert cfg.fileSystems."/boot".device == "/dev/disk/by-label/NIXOS2_EFI";
          assert !cfg.boot.loader.efi.canTouchEfiVariables;
          assert !cfg.users.users.alex.linger;
          assert !cfg.services.nixer.enable;
          assert !(builtins.hasAttr "nixer" cfg.systemd.user.services);
          assert !cfg.heimPc.grabowskiProduction.enable;
          assert cfg.heimPc.nixerHeadless.enable;
          assert !(builtins.elem "nomodeset" cfg.boot.kernelParams);
          assert cfg.virtualisation.podman.enable;
          assert unit.wantedBy == [ "multi-user.target" ];
          assert sc.User == "alex" && sc.Group == "users";
          assert sc.RuntimeDirectory == "nixer-headless";
          assert sc.RuntimeDirectoryMode == "0700";
          assert sc.UMask == "0077";
          assert unit.environment.NIXER_CONTAINER_XDG_RUNTIME_DIR == "/run/nixer-headless";
          assert unit.environment.NIXER_REPO_ROOT == "/home/alex/repos";
          assert builtins.match ".*heim-pc-nixer-check-image" sc.ExecStartPre != null;
          assert builtins.match ".*nixer --transport streamable-http --host 127[.]0[.]0[.]1 --port 18187"
            sc.ExecStart != null;
          pkgs.runCommand "heim-pc-seagate-nixer-headless-contract" {} ''
            mkdir -p "$out"
          '';

        # Integrate the genuine pinned Grabowski release with the already
        # tested Nixer/Plasma successor without enabling the default host.
        # This proves declarative service and rootbroker *admission wiring*,
        # NOT real Seagate private policy or remote boot readiness.
        seagate-grabowski-headless-contract =
          let
            baseline = self.nixosConfigurations.heim-pc-seagate-nixer-headless-candidate.config;
            cfg = self.nixosConfigurations.heim-pc-seagate-grabowski-headless-candidate.config;
            op = cfg.systemd.services.grabowski-operator;
            broker = cfg.systemd.services."grabowski-privileged-broker@";
            socket = cfg.systemd.sockets.grabowski-privileged-broker;
            policy = cfg.systemd.services.grabowski-private-policy-install;
            originalOperator = import ./modules/grabowski-operator-package.nix { inherit pkgs; };
            originalBroker = import ./modules/grabowski-broker-package.nix {
              inherit pkgs;
              lib = pkgs.lib;
              packageOnly = true;
            };
          in
          assert !baseline.heimPc.grabowskiProduction.enable;
          assert cfg.heimPc.grabowskiProduction.enable;
          assert cfg.heimPc.grabowskiProduction.operatorPackage.outPath == originalOperator.outPath;
          assert cfg.heimPc.grabowskiProduction.brokerPackage.outPath == originalBroker.outPath;
          assert cfg.heimPc.grabowskiProduction.releaseId ==
            "dd6dc690285b-srcset5c51dbd24485-lock264e747ad05a-contract2681d2593edc";
          assert cfg.system.configurationRevision == sourceRevision;
          assert cfg.fileSystems."/".device == "/dev/disk/by-label/NIXOS_STAGE0_ROOT";
          assert cfg.fileSystems."/boot".device == "/dev/disk/by-label/NIXOS2_EFI";
          assert cfg.fileSystems."/persist".fsType == "btrfs";
          assert !cfg.boot.loader.efi.canTouchEfiVariables;
          assert !(builtins.elem "nomodeset" cfg.boot.kernelParams);
          assert cfg.services.openssh.enable && cfg.services.tailscale.enable;
          assert cfg.services.getty.autologinUser == null;
          assert cfg.security.sudo.wheelNeedsPassword;
          assert cfg.users.users.alex.linger;
          assert cfg.heimPc.nixerHeadless.enable && !cfg.services.nixer.enable;
          assert !(builtins.hasAttr "nixer" cfg.systemd.user.services);
          assert cfg.systemd.services.nixer-headless.serviceConfig.User == "alex";
          assert !(builtins.elem "grabowski" cfg.users.users.alex.extraGroups);
          assert op.serviceConfig.User == "alex";
          assert op.serviceConfig.Group == "users";
          assert cfg.systemd.services.nixer-headless.serviceConfig.Group == "users";
          assert builtins.elem "user@1000.service" op.requires;
          assert builtins.elem "XDG_RUNTIME_DIR=/run/user/1000" op.serviceConfig.Environment;
          assert builtins.elem "DBUS_SESSION_BUS_ADDRESS=unix:path=/run/user/1000/bus"
            op.serviceConfig.Environment;
          assert op.serviceConfig.SupplementaryGroups == [ "grabowski" ];
          assert builtins.elem "grabowski-private-policy-install.service" op.requires;
          assert builtins.elem "grabowski-privileged-broker.socket" op.requires;
          assert policy.serviceConfig.User == "root";
          assert policy.unitConfig.AssertPathIsMountPoint == "/persist";
          assert builtins.elem "grabowski-private-policy-install.service" socket.requires;
          assert socket.socketConfig.SocketMode == "0660";
          assert socket.socketConfig.SocketGroup == "grabowski";
          assert broker.serviceConfig.User == "root";
          assert builtins.match ".*CAP_SYS_ADMIN.*" broker.serviceConfig.CapabilityBoundingSet != null;
          assert !(builtins.hasAttr "grabowski-demo" cfg.systemd.services);
          pkgs.runCommand "heim-pc-seagate-grabowski-headless-contract" {} ''
            mkdir -p "$out"
          '';

        # NixOS evaluation proof of the exact pinned pair, NEVER a deployment
        # target. Positive unit properties require the immutable release.
        # Negative fixtures prove that missing, unrelated and mismatched
        # operator/broker artifacts fail before enabling either service.
        grabowski-production-unit-contract =
          let
            release = "dd6dc690285b-srcset5c51dbd24485-lock264e747ad05a-contract2681d2593edc";
            inactive = self.nixosConfigurations.heim-pc-seagate-primary-candidate.config;
            pinnedOperator = import ./modules/grabowski-operator-package.nix { inherit pkgs; };
            runProof = { op ? pinnedOperator, broker ? null, id ? release }:
              (nixpkgs.lib.nixosSystem {
                inherit system;
                modules = [
                  ./modules/seagate-primary-candidate.nix
                  ({ ... }: {
                    heimPc.grabowskiProduction = {
                      enable = true;
                      operatorPackage = op;
                      releaseId = id;
                    } // (if broker == null then { } else { brokerPackage = broker; });
                  })
                ];
              }).config;
            noPackages = runProof { op = null; id = "no-packages-must-fail"; };
            wrongOperator = runProof { op = pkgs.coreutils; };
            wrongBroker = runProof { broker = pkgs.coreutils; };
            wrongRelease = runProof { id = "different-release-must-fail"; };
            proof = runProof { };
            socketUnit = proof.systemd.sockets.grabowski-privileged-broker;
            sock = socketUnit.socketConfig;
            policyUnit = proof.systemd.services.grabowski-private-policy-install;
            policy = policyUnit.serviceConfig;
            broker = proof.systemd.services."grabowski-privileged-broker@".serviceConfig;
            operator = proof.systemd.services.grabowski-operator.serviceConfig;
            unitStore = toString proof.systemd.units."grabowski-operator.service".unit;
          in
          assert !inactive.heimPc.grabowskiProduction.enable;
          assert inactive.heimPc.grabowskiProduction.operatorPackage == null;
          assert inactive.heimPc.grabowskiProduction.brokerPackage.passthru.sourceRevision
            == "dd6dc690285b6a8a0cdbb3c18d84a1681e604923";
          assert !(builtins.tryEval noPackages.system.build.toplevel.drvPath).success;
          assert !(builtins.tryEval wrongOperator.system.build.toplevel.drvPath).success;
          assert !(builtins.tryEval wrongBroker.system.build.toplevel.drvPath).success;
          assert !(builtins.tryEval wrongRelease.system.build.toplevel.drvPath).success;
          assert !(builtins.hasAttr "grabowski-operator" inactive.systemd.services);
          assert !(builtins.hasAttr "grabowski-privileged-broker" inactive.systemd.sockets);
          assert proof.heimPc.grabowskiProduction.releaseId == release;
          assert proof.heimPc.grabowskiProduction.operatorPackage.outPath == pinnedOperator.outPath;
          assert sock.ListenStream == "/run/grabowski/privileged-broker.sock";
          assert sock.Accept && sock.SocketMode == "0660" && sock.SocketGroup == "grabowski";
          assert builtins.elem "grabowski-private-policy-install.service" socketUnit.requires;
          assert builtins.elem "grabowski-private-policy-install.service" socketUnit.after;
          assert socketUnit.wantedBy == [ "multi-user.target" ];
          assert socketUnit.unitConfig.DefaultDependencies == false;
          assert builtins.elem "basic.target" socketUnit.after;
          assert builtins.elem "shutdown.target" socketUnit.conflicts;
          assert builtins.elem "grabowski-private-policy-install.service"
            proof.systemd.services.grabowski-operator.requires;
          assert builtins.elem "grabowski-private-policy-install.service"
            proof.systemd.services.grabowski-operator.after;
          assert policy.User == "root" && policy.Group == "root";
          assert policy.Type == "oneshot" && policy.RemainAfterExit;
          assert policy.ConfigurationDirectory == "grabowski";
          assert policy.ConfigurationDirectoryMode == "0755";
          assert policy.ProtectHome && policy.ProtectSystem == "strict";
          assert policy.PrivateNetwork && policy.NoNewPrivileges;
          assert policy.UMask == "0077";
          assert builtins.match ".*grabowski-private-policy-install[.]py"
            policy.ExecStart != null;
          assert policyUnit.unitConfig.RequiresMountsFor == "/persist";
          assert policyUnit.unitConfig.AssertPathIsMountPoint == "/persist";
          assert builtins.match "/nix/store/[0-9a-z]{32}-unit-grabowski-operator[.]service" unitStore != null;
          assert broker.User == "root";
          assert broker.Environment == [
            "GRABOWSKI_NIXOS_OPERATOR_ENTRYPOINT=${pinnedOperator}/bin/grabowski-operator"
          ];
          assert broker.StandardInput == "socket" && broker.StandardOutput == "socket";
          assert broker.ProtectHome == "tmpfs" && broker.ProtectSystem == "strict";
          assert broker.StateDirectory == "grabowski/privileged-broker";
          assert broker.StateDirectoryMode == "0700";
          assert builtins.match ".*CAP_SYS_ADMIN.*" broker.CapabilityBoundingSet != null;
          assert builtins.match ".*@mount.*" broker.SystemCallFilter != null;
          assert broker.SystemCallErrorNumber == "EPERM";
          assert broker.RestrictNamespaces;
          assert operator.User == "alex" && operator.Group == "alex";
          assert builtins.elem
            "GRABOWSKI_PRIVILEGED_BROKER=${proof.heimPc.grabowskiProduction.brokerPackage}/bin/grabowski-privileged-broker"
            operator.Environment;
          assert builtins.elem
            "PATH=${proof.heimPc.grabowskiProduction.brokerPackage}/bin:${pkgs.coreutils}/bin:${pkgs.git}/bin:${pkgs.systemd}/bin"
            operator.Environment;
          assert operator.NoNewPrivileges && operator.ProtectSystem == "strict";
          assert builtins.elem "grabowski-privileged-broker.socket"
            proof.systemd.services.grabowski-operator.requires;
          assert !(builtins.elem "grabowski" proof.users.users.alex.extraGroups);
          assert builtins.elem "grabowski" operator.SupplementaryGroups;
          pkgs.runCommand "heim-pc-grabowski-production-unit-contract" {} ''
            mkdir -p "$out"
          '';

        # Check *module option compatibility only*. This explicitly does not
        # prove a bootable LUKS-root target: private rd.luks kernel parameters
        # still rely on the separate systemd-boot post-install entry hook.
        # The check is evaluation-only and never exposes an activatable host.
        limine-secureboot-module-options-eval =
          let
            cfg = limineStorageTargetProof.config;
            prod = self.nixosConfigurations.heim-pc-storage-target.config;
          in
          assert !(builtins.hasAttr "heim-pc-storage-limine-proof" self.nixosConfigurations);
          assert cfg.system.boot.loader.id == "limine";
          assert !cfg.boot.loader.systemd-boot.enable;
          assert cfg.boot.loader.limine.enable && cfg.boot.loader.limine.secureBoot.enable;
          assert cfg.boot.loader.limine.validateChecksums;
          assert cfg.boot.loader.limine.panicOnChecksumMismatch;
          assert cfg.boot.loader.limine.enrollConfig;
          assert !cfg.boot.loader.limine.enableEditor;
          assert cfg.boot.loader.limine.efiInstallAsRemovable;
          assert !cfg.boot.loader.efi.canTouchEfiVariables;
          assert !cfg.boot.loader.limine.secureBoot.autoGenerateKeys;
          assert !cfg.boot.loader.limine.secureBoot.autoEnrollKeys.enable;
          assert cfg.boot.loader.limine.efiSupport;
          # Explicit negative evidence for the unresolved physical LUKS boot
          # chain. New private parameters need independently reviewed signing
          # integration, not a silent upgrade of this option-only proof.
          assert prod.boot.loader.systemd-boot.enable;
          assert cfg.boot.initrd.luks.devices == {};
          assert !(builtins.any (param: nixpkgs.lib.hasPrefix "rd.luks." param) cfg.boot.kernelParams);
          assert builtins.isString cfg.system.build.toplevel.drvPath;
          pkgs.runCommand "heim-pc-limine-module-options-only" { } ''
            mkdir -p "$out"
          '';
        # Evaluates synthetic LUKS arguments in a non-selectable Limine
        # Secure Boot NixOS module graph. This does not establish that the
        # resulting limine.conf has actually been signed or boots under OVMF.
        limine-synthetic-luks-cmdline-eval =
          let
            cfg = limineSyntheticLuksArgsProof.config;
            syntheticPartuuid = "11111111-2222-4333-8444-555555555555";
            expectedArgs = [
              "rd.luks.name=${syntheticPartuuid}=heimpc-nixos-crypt"
              "rd.luks.options=${syntheticPartuuid}=tpm2-device=auto,headless=yes"
            ];
          in
          assert !(builtins.hasAttr "heim-pc-storage-limine-luks-proof" self.nixosConfigurations);
          assert !(builtins.hasAttr "limine-synthetic-luks-cmdline-proof" self.packages.${system});
          assert cfg.system.boot.loader.id == "limine";
          assert !cfg.boot.loader.systemd-boot.enable;
          assert cfg.boot.loader.limine.secureBoot.enable;
          assert cfg.boot.loader.limine.enrollConfig;
          assert cfg.boot.loader.limine.validateChecksums;
          assert cfg.boot.loader.limine.panicOnChecksumMismatch;
          assert !cfg.boot.loader.limine.enableEditor;
          assert !cfg.boot.loader.limine.secureBoot.autoGenerateKeys;
          assert !cfg.boot.loader.limine.secureBoot.autoEnrollKeys.enable;
          assert !cfg.boot.loader.efi.canTouchEfiVariables;
          assert cfg.boot.initrd.systemd.enable;
          assert cfg.boot.initrd.luks.devices == {};
          assert (builtins.filter (arg: nixpkgs.lib.hasPrefix "rd.luks." arg)
            cfg.boot.kernelParams) == expectedArgs;
          assert builtins.isString cfg.system.build.toplevel.drvPath;
          pkgs.runCommand "heim-pc-limine-synthetic-luks-options-only" { } ''
            mkdir -p "$out"
          '';
        # These assertions force real NixOS module evaluation, not text matching.
        profile-contract =
          let
            configs = self.nixosConfigurations;
            target = configs.heim-pc-storage-target.config;
            proprietary = configs.heim-pc-physical-gate-proprietary.config;
            open = configs.heim-pc-physical-gate-open.config;
            vm = configs.heim-pc-vm.config;
            credentialConflict = nixpkgs.lib.nixosSystem {
              inherit system;
              specialArgs = {
                inherit self;
                heimPcProfile = {
                  physical = true;
                  nvidia = true;
                  nvidiaOpen = false;
                  desktop = true;
                  physicalGates = false;
                };
              };
              modules = physicalHostModules ++ [
                ({ ... }: {
                  # Public sentinel only: prove that any declarative password
                  # source conflicts with the out-of-store bootstrap contract.
                  users.users.alex.initialHashedPassword = "!PUBLIC-TEST-ONLY";
                })
              ];
            };
            credentialConflictEval = builtins.tryEval
              credentialConflict.config.system.build.toplevel.drvPath;
            missingPersistConflict = nixpkgs.lib.nixosSystem {
              inherit system;
              specialArgs = {
                inherit self;
                heimPcProfile = {
                  physical = true;
                  nvidia = true;
                  nvidiaOpen = false;
                  desktop = true;
                  physicalGates = false;
                };
              };
              modules = hostModules ++ [
                ({ lib, ... }: {
                  fileSystems."/".device = lib.mkForce "/dev/disk/by-label/REAL-WITHOUT-PERSIST";
                })
              ];
            };
            missingPersistConflictEval = builtins.tryEval
              missingPersistConflict.config.system.build.toplevel.drvPath;
            targetCredentialsUnset = builtins.all (value: value == null) [
              target.users.users.alex.password
              target.users.users.alex.hashedPassword
              target.users.users.alex.hashedPasswordFile
              target.users.users.alex.initialPassword
              target.users.users.alex.initialHashedPassword
            ];
            live = map (name: configs.${name}.config) [
              "heim-pc-live-gate-proprietary" "heim-pc-live-gate-open"
            ];
            inventory = configs.heim-pc-live-inventory.config;
            contract = builtins.fromJSON (builtins.readFile ../production/contract-v1.json);
            topology = contract.topology;
            byRole = role: builtins.head (builtins.filter (p: p.role == role) topology.partitions);
            mapperName = topology.luks.mapper_name;
            mapper = "/dev/mapper/${mapperName}";
            storage = c: {
              mounts = builtins.mapAttrs (_: fs: {
                inherit (fs) device fsType options;
              }) c.fileSystems;
              luks = builtins.mapAttrs (_: device: device.device) c.boot.initrd.luks.devices;
              systemdBoot = c.boot.loader.systemd-boot.enable;
              touchEfi = c.boot.loader.efi.canTouchEfiVariables;
            };
            fsMatches = builtins.all (subvolume:
              target.fileSystems.${subvolume.mountpoint}.device == mapper
              && target.fileSystems.${subvolume.mountpoint}.fsType == "btrfs"
              && builtins.elem "subvol=${subvolume.name}" target.fileSystems.${subvolume.mountpoint}.options
            ) topology.btrfs.subvolumes;
            surfaceAbsent = builtins.all (role:
              let p = byRole role;
              in !(builtins.hasAttr p.mountpoint target.fileSystems)
            ) [ "efi-system-partition" "recovery-surface" ];
          in
          assert fsMatches && surfaceAbsent;
          assert target.boot.initrd.luks.devices == {};
          assert target.boot.initrd.luks.forceLuksSupportInInitrd;
          assert builtins.hasAttr "heim-pc-private-storage-mounts" target.systemd.services;
          assert target.systemd.services.heim-pc-private-storage-mounts.serviceConfig.Type == "oneshot";
          assert nixpkgs.lib.hasInfix "heim-pc-private-storage patch-loader-entries"
            target.boot.loader.systemd-boot.extraInstallCommands;
          assert target.boot.loader.systemd-boot.enable;
          # The physical target may not expose an editable kernel command line.
          # This defense-in-depth is not signed-bootchain authentication.
          assert !target.boot.loader.systemd-boot.editor;
          # The private-storage hook selects NixOS entries by this exact sort key.
          assert target.boot.loader.systemd-boot.sortKey == "nixos";
          assert !target.boot.loader.efi.canTouchEfiVariables;
          assert target.services.xserver.xkb.layout == "de";
          assert target.console.useXkbConfig;
          assert target.i18n.defaultLocale == "de_DE.UTF-8";
          assert target.time.timeZone == "Europe/Berlin";
          assert storage target == storage proprietary && storage target == storage open;
          assert !target.heimPc.physicalGates.enable;
          assert proprietary.heimPc.physicalGates.enable && open.heimPc.physicalGates.enable;
          assert target.heimPc.hostProtection.enable;
          assert proprietary.heimPc.hostProtection.enable && open.heimPc.hostProtection.enable;
          assert !vm.heimPc.hostProtection.enable;
          assert target.zramSwap.enable;
          assert target.zramSwap.algorithm == "zstd";
          assert target.zramSwap.memoryPercent == 25;
          assert target.zramSwap.priority == 1000;
          assert target.users.users.alex.linger == false;
          assert target.systemd.services.heim-pc-pytest-temp-gc.serviceConfig.Group
            == target.users.users.alex.group;
          assert builtins.hasAttr target.users.users.alex.group target.users.groups;
          assert target.systemd.oomd.enable;
          assert !target.systemd.oomd.enableRootSlice;
          assert !target.systemd.oomd.enableSystemSlice;
          assert !target.systemd.oomd.enableUserSlices;
          assert !target.heimPc.hostProtection.grabowskiGuard.enable;
          assert !builtins.hasAttr "heim-pc-grabowski-memory-guard" target.systemd.services;
          assert !target.heimPc.hostProtection.storagePressure.requestMaintenance;
          assert builtins.hasAttr "heim-pc-memory-pressure-snapshot" target.systemd.services;
          assert builtins.hasAttr "heim-pc-memory-pressure-snapshot" target.systemd.timers;
          assert builtins.hasAttr "heim-pc-pytest-temp-gc" target.systemd.timers;
          assert builtins.hasAttr "heim-pc-storage-pressure-watch" target.systemd.user.timers;
          assert builtins.hasAttr "heim-pc-home-hygiene" target.systemd.user.timers;
          assert nixpkgs.lib.hasInfix "--observe-only"
            target.systemd.user.services.heim-pc-storage-pressure-watch.serviceConfig.ExecStart;
          assert builtins.all (c:
            c.networking.networkmanager.enable
            && c.security.polkit.enable
            && c.services.displayManager.autoLogin.enable
            && c.heimPc.desktop.enable
            && c.heimPc.hardware.nvidia.enable
            && c.heimPc.physicalGates.enable
          ) live;
          assert !inventory.networking.networkmanager.enable;
          assert !inventory.networking.useDHCP;
          assert !inventory.security.polkit.enable;
          assert !inventory.security.rtkit.enable;
          assert !inventory.services.pipewire.enable;
          assert !inventory.services.displayManager.autoLogin.enable;
          assert !inventory.heimPc.desktop.enable;
          assert !inventory.heimPc.hardware.nvidia.enable;
          assert !inventory.heimPc.physicalGates.enable;
          assert inventory.users.users.root.hashedPassword == "!";
          assert !(builtins.elem "wheel" inventory.users.users.alex.extraGroups);
          assert !(builtins.elem "disk" inventory.users.users.alex.extraGroups);
          assert builtins.hasAttr "heim-pc-offline-critical-user-data-inventory"
            inventory.systemd.services;
          assert inventory.systemd.services.heim-pc-offline-critical-user-data-inventory.serviceConfig.Restart == "no";
          assert inventory.systemd.services.heim-pc-offline-critical-user-data-inventory.serviceConfig.PrivateNetwork;
          assert inventory.systemd.services.heim-pc-offline-critical-user-data-inventory.serviceConfig.PrivateMounts;
          assert inventory.systemd.services.heim-pc-offline-critical-user-data-inventory.serviceConfig.NoNewPrivileges;
          assert inventory.systemd.services.heim-pc-offline-critical-user-data-inventory.serviceConfig.User == "root";
          assert inventory.systemd.services.heim-pc-offline-critical-user-data-inventory.unitConfig.ConditionPathExists
            == "/dev/disk/by-label/HEIMPC_EVIDENCE";
          assert builtins.elem "systemd-udev-settle.service"
            inventory.systemd.services.heim-pc-offline-critical-user-data-inventory.wants;
          assert builtins.elem "heim-pc-offline-inventory"
            inventory.systemd.services.heim-pc-offline-critical-user-data-inventory.serviceConfig.RuntimeDirectory;
          assert builtins.elem "heim-pc-recovery-evidence"
            inventory.systemd.services.heim-pc-offline-critical-user-data-inventory.serviceConfig.RuntimeDirectory;
          assert !inventory.virtualisation.podman.enable
            && inventory.fileSystems."/".fsType == "tmpfs";
          assert targetCredentialsUnset;
          assert !credentialConflictEval.success;
          assert !missingPersistConflictEval.success;
          assert !builtins.hasAttr "heim-pc-firstboot-credentials" configs.heim-pc.config.systemd.services;
          assert builtins.hasAttr "heim-pc-firstboot-credentials" target.systemd.services;
          assert target.systemd.services.heim-pc-firstboot-credentials.serviceConfig.TimeoutStartSec == "30s";
          assert builtins.all (c: c.hardware.cpu.amd.updateMicrocode
            && c.networking.networkmanager.enable
            && builtins.elem "networkmanager" c.users.users.alex.extraGroups
          ) [ target proprietary open ];
          assert !vm.hardware.cpu.amd.updateMicrocode;
          assert !vm.heimPc.hardware.nvidia.enable && !vm.heimPc.physicalGates.enable;
          assert builtins.all (c:
            c.services.logind.settings.Login.IdleAction == "ignore"
            && c.environment.etc."xdg/powerdevilrc".text == ''
              [AC][SuspendAndShutdown]
              AutoSuspendAction[$i]=0
              [Battery][SuspendAndShutdown]
              AutoSuspendAction[$i]=0
              [LowBattery][SuspendAndShutdown]
              AutoSuspendAction[$i]=0
            ''
            && !(c.systemd.sleep.settings.Sleep ? AllowSuspend)
            && !(c.systemd.sleep.settings.Sleep ? AllowHibernation)
            && !(c.systemd.sleep.settings.Sleep ? AllowSuspendThenHibernate)
            && !(c.systemd.sleep.settings.Sleep ? AllowHybridSleep)
          ) ([ configs.heim-pc.config target proprietary open ] ++ live);
          assert configs.heim-pc.config.fileSystems."/".device
            == "/dev/disk/by-label/NIXOS_PROTOTYPE_DO_NOT_INSTALL";
          assert builtins.all (c: !c.virtualisation.podman.enable
            && c.fileSystems."/".fsType == "tmpfs"
          ) live;
          pkgs.runCommand "heim-pc-profile-contract" {
            report =
              let value = builtins.toJSON {
                evidenceClass = "evaluated-configuration-only";
                storageTarget = storage target;
                physicalGateProprietary = storage proprietary;
                physicalGateOpen = storage open;
                # Metadata, not a dependency on every VM build-time output.
                # The separate CI build still realizes the actual systems.
                vmSystem = builtins.unsafeDiscardStringContext vm.system.build.toplevel.drvPath;
                sourceRevision = sourceRevision;
              };
              in assert !builtins.hasContext value; value;
            passAsFile = [ "report" ];
          } ''
            mkdir -p "$out"
            cp "$reportPath" "$out/profile-contract.json"
          '';
        supply-chain-trust =
          let
            contract = builtins.fromJSON (builtins.readFile ../production/trust-contract-v1.json);
            sourceRoot = ../..;
            lock = builtins.fromJSON (builtins.readFile ../../flake.lock);
            rootNode = builtins.getAttr lock.root lock.nodes;
            rootNixpkgsNode = builtins.getAttr contract.inputs.root_nixpkgs.lock_node lock.nodes;
            microvmNode = builtins.getAttr contract.inputs.microvm.lock_node lock.nodes;
            nixerNode = builtins.getAttr contract.inputs.nixer.lock_node lock.nodes;
            nixerRuntimeNixpkgsNode =
              builtins.getAttr contract.inputs.nixer.runtime_nixpkgs_lock_node lock.nodes;
            target = self.nixosConfigurations.heim-pc-storage-target.config;
          in
          assert target.nix.settings.substituters == contract.nix.substituters;
          assert target.nix.settings.trusted-substituters == contract.nix.trusted_substituters;
          assert target.nix.settings.trusted-public-keys == contract.nix.trusted_public_keys;
          assert target.nix.settings.trusted-users == contract.nix.trusted_users;
          assert target.nix.settings.require-sigs == contract.nix.require_sigs;
          assert target.nix.settings.accept-flake-config == contract.nix.accept_flake_config;
          assert target.nix.settings.experimental-features == contract.nix.experimental_features;
          assert target.nix.settings.trust-tarballs-from-git-forges
            == contract.nix.trust_tarballs_from_git_forges;
          assert rootNode.inputs.nixpkgs == contract.inputs.root_nixpkgs.lock_node;
          assert rootNixpkgsNode.locked.rev == contract.inputs.root_nixpkgs.required_revision;
          assert rootNixpkgsNode.original.ref == contract.inputs.root_nixpkgs.required_ref;
          assert rootNode.inputs.microvm == contract.inputs.microvm.lock_node;
          assert microvmNode.locked.rev == contract.inputs.microvm.required_revision;
          assert contract.inputs.microvm.nixpkgs_follows_root;
          assert microvmNode.inputs.nixpkgs == [ "nixpkgs" ];
          assert rootNode.inputs.nixer == contract.inputs.nixer.lock_node;
          assert nixerNode.locked.rev == contract.inputs.nixer.required_revision;
          assert contract.inputs.nixer.owns_runtime_nixpkgs;
          assert nixerNode.inputs.nixpkgs == contract.inputs.nixer.runtime_nixpkgs_lock_node;
          assert nixerRuntimeNixpkgsNode.locked.rev
            == contract.inputs.nixer.runtime_nixpkgs_required_revision;
          pkgs.runCommand "heim-pc-supply-chain-trust-contract" { } ''
            verifier_report="$TMPDIR/managed-nix-verifier-contract.json"
            PYTHONPATH=${sourceRoot} ${pkgs.python3}/bin/python ${sourceRoot}/scripts/ci/check_pinned_nix_find_contract.py \
              --trust-contract-only \
              --trust-contract ${../production/trust-contract-v1.json} \
              > "$verifier_report"
            mkdir -p "$out"
            cp ${../production/trust-contract-v1.json} "$out/trust-contract-v1.json"
            cp "$verifier_report" "$out/managed-nix-verifier-contract.json"
          '';

        nix-lifecycle-contract =
          let
            contract = builtins.fromJSON (builtins.readFile ../production/nix-lifecycle-contract-v1.json);
            target = self.nixosConfigurations.heim-pc-storage-target.config;
          in
          assert !target.nix.gc.automatic;
          assert builtins.hasAttr "heim-pc-nix-lifecycle-audit" target.systemd.services;
          assert builtins.hasAttr "heim-pc-nix-lifecycle-audit" target.systemd.timers;
          assert !contract.automatic_gc;
          assert !contract.budget.automatic_reclaim_authorized;
          assert contract.protected_generations.last_known_good_must_be_enumerated_gc_root;
          pkgs.runCommand "heim-pc-nix-lifecycle-contract" { } ''
            mkdir -p "$out"
            cp ${../production/nix-lifecycle-contract-v1.json} "$out/nix-lifecycle-contract-v1.json"
          '';

        host-protection-contract =
          let
            target = self.nixosConfigurations.heim-pc-storage-target.config;
            vm = self.nixosConfigurations.heim-pc-vm.config;
          in
          assert target.heimPc.hostProtection.enable;
          assert target.zramSwap.enable;
          assert target.zramSwap.memoryPercent == 25;
          assert target.zramSwap.algorithm == "zstd";
          assert target.zramSwap.priority == 1000;
          assert target.users.users.alex.linger == false;
          assert target.systemd.services.heim-pc-pytest-temp-gc.serviceConfig.Group
            == target.users.users.alex.group;
          assert builtins.hasAttr target.users.users.alex.group target.users.groups;
          assert target.systemd.oomd.enable;
          assert !target.systemd.oomd.enableRootSlice;
          assert !target.systemd.oomd.enableSystemSlice;
          assert !target.systemd.oomd.enableUserSlices;
          assert builtins.hasAttr "heim-pc-memory-pressure-snapshot" target.systemd.services;
          assert builtins.hasAttr "heim-pc-memory-pressure-snapshot" target.systemd.timers;
          assert builtins.hasAttr "heim-pc-pytest-temp-gc" target.systemd.services;
          assert builtins.hasAttr "heim-pc-pytest-temp-gc" target.systemd.timers;
          assert builtins.hasAttr "heim-pc-storage-pressure-watch" target.systemd.user.services;
          assert builtins.hasAttr "heim-pc-storage-pressure-watch" target.systemd.user.timers;
          assert builtins.hasAttr "heim-pc-home-hygiene" target.systemd.user.services;
          assert builtins.hasAttr "heim-pc-home-hygiene" target.systemd.user.timers;
          assert !(builtins.hasAttr "heim-pc-grabowski-memory-guard" target.systemd.services);
          assert !vm.heimPc.hostProtection.enable;
          pkgs.runCommand "heim-pc-host-protection-contract" { } ''
            mkdir -p "$out"
            touch "$out/pass"
          '';

        recovery-readiness-contract =
          let
            recoveryPath = ../production/recovery-contract-v1.json;
            criticalUserDataPath = ../production/critical-user-data-contract-v1.json;
            criticalUserHomePath = ../production/critical-user-home-data-contract-v1.json;
            contract = builtins.fromJSON (builtins.readFile recoveryPath);
            criticalUserData = builtins.fromJSON (builtins.readFile criticalUserDataPath);
            criticalUserHome = builtins.fromJSON (builtins.readFile criticalUserHomePath);
            criticalUserDataSha256 = builtins.hashFile "sha256" criticalUserDataPath;
            criticalUserHomeSha256 = builtins.hashFile "sha256" criticalUserHomePath;
            homeMember = builtins.elemAt criticalUserData.members 0;
            materialization = criticalUserHome.materialization_policy;
            bootstrapRole = builtins.getAttr "bootstrap-direct" materialization.roles;
            authorityRole = builtins.getAttr "authority-reconcile" materialization.roles;
            coldRole = builtins.getAttr "cold-preservation" materialization.roles;
            coldImportRoot = "/var/lib/heim-pc-data/import/legacy-2026";
            target = self.nixosConfigurations.heim-pc-storage-target.config;
          in
          assert contract.status == "external-evidence-required";
          assert contract.admission_scope.complete_evidence_required_for == "destructive-source-cutover";
          assert contract.admission_scope.excluded_installation.migration_mode == "isolated-parallel-disk-dual-os";
          assert contract.admission_scope.excluded_installation.source_preservation_mode == "retained-protected-source";
          assert !contract.admission_scope.excluded_installation.destructive_source_cutover;
          assert !contract.admission_scope.excluded_installation.pre_cutover_readiness_required;
          assert contract.admission.point_of_no_return_blocked_without_complete_evidence;
          assert contract.admission.destructive_source_cutover_blocked_without_complete_evidence;
          assert !(contract.admission ? production_storage_mutation_blocked_without_complete_evidence);
          assert contract.critical_user_data_scope.contract_kind == "heim_pc.critical_user_data_scope_contract";
          assert contract.critical_user_data_scope.scope == "critical-user-data";
          assert contract.critical_user_data_scope.sha256 == criticalUserDataSha256;
          assert contract.critical_user_data_scope.off_host_restore_critical_scope_sha256_bound;
          assert contract.critical_user_data_scope.off_host_restore_source_inventory_sha256_bound;
          assert contract.critical_user_data_scope.off_host_restore_restored_inventory_sha256_bound;
          assert contract.critical_user_data_scope.off_host_restore_inventory_sha256_equality_required;
          assert contract.critical_user_data_scope.aggregate_member_contracts_bound;
          assert contract.readiness_bundle.critical_user_data_contract_sha256_bound;
          assert criticalUserData.schema_version == 1;
          assert criticalUserData.kind == "heim_pc.critical_user_data_scope_contract";
          assert criticalUserData.scope == "critical-user-data";
          assert criticalUserData.scope_semantics == "explicit-positive-selection";
          assert criticalUserData.inventory_implementation.algorithm == "member-inventory-sha256-v1";
          assert criticalUserData.inventory_implementation.root_inventory_script == "scripts/nixos_critical_user_data_inventory.py";
          assert criticalUserData.inventory_implementation.aggregate_inventory_script == "scripts/nixos_critical_data_inventory.py";
          assert criticalUserData.inventory_implementation.aggregate_execution_mode == "external-verified-payload-exec-v1";
          assert criticalUserData.inventory_implementation.authoritative_member_source_stability == "kernel-local-pci-nvme-readonly-mountinfo-v3";
          assert builtins.length criticalUserData.members == 1;
          assert homeMember.id == "home";
          assert homeMember.contract_file == "critical-user-home-data-contract-v1.json";
          assert homeMember.contract_sha256 == criticalUserHomeSha256;
          assert homeMember.destination.nixos_storage_domain == "per-entry-policy";
          assert homeMember.destination.logical_path == "materialization-policy";
          assert homeMember.restore_mode == "source-scope-with-role-specific-materialization";
          assert criticalUserHome.scope == "critical-user-data-home";
          assert criticalUserHome.scope_semantics == "explicit-path-set";
          assert criticalUserHome.root == "/home/alex";
          assert criticalUserHome.inventory.algorithm == "canonical-record-stream-sha256-v7";
          assert criticalUserHome.inventory.uid_gid_bound;
          assert criticalUserHome.inventory.explicit_ancestor_metadata_bound;
          assert criticalUserHome.inventory.xattrs_sha256_bound;
          assert criticalUserHome.selection_policy.default == "exclude";
          assert !criticalUserHome.selection_policy.unlisted_paths_are_migration_data;
          assert materialization.schema_version == 1;
          assert materialization.kind == "heim_pc.critical_user_data_materialization_policy";
          assert materialization.source_scope_and_nixos_target_layout_are_separate;
          assert materialization.source_equivalent_disposable_restore_required;
          assert materialization.cold_import_root == coldImportRoot;
          assert !materialization.first_productive_boot_requires_cold_import_completion;
          assert bootstrapRole.nixos_storage_domain == "@home";
          assert bootstrapRole.target_mapping == "same-absolute-path";
          assert bootstrapRole.source_path_is_live_target_path;
          assert authorityRole.nixos_storage_domain == "@data";
          assert authorityRole.staging_root == "${coldImportRoot}/authority";
          assert !authorityRole.source_path_is_live_target_path;
          assert authorityRole.direct_activation_forbidden;
          assert coldRole.nixos_storage_domain == "@data";
          assert coldRole.staging_root == coldImportRoot;
          assert !coldRole.source_path_is_live_target_path;
          assert !coldRole.required_before_first_productive_boot;
          assert !criticalUserData.migration_policy.source_paths_define_nixos_target_layout;
          assert criticalUserData.migration_policy.cold_preservation_storage_domain == "@data";
          assert criticalUserData.migration_policy.cold_preservation_import_root == coldImportRoot;
          assert !criticalUserData.migration_policy.cold_preservation_required_before_first_productive_boot;
          assert !criticalUserData.migration_policy.local_only_repository_auto_checkout;
          assert !criticalUserData.migration_policy.legacy_library_source_path_restored;
          assert criticalUserData.migration_policy.operator_state_direct_restore_forbidden;
          assert builtins.hasAttr "heim-pc/recovery-contract.json" target.environment.etc;
          assert builtins.hasAttr "heim-pc/critical-user-data-contract.json" target.environment.etc;
          assert builtins.hasAttr "heim-pc/critical-user-home-data-contract.json" target.environment.etc;
          assert !builtins.hasAttr "heim-pc/critical-docker-volume-data-contract.json" target.environment.etc;
          pkgs.runCommand "heim-pc-recovery-readiness-contract" { } ''
            mkdir -p "$out"
            cp ${recoveryPath} "$out/recovery-contract-v1.json"
            cp ${criticalUserDataPath} "$out/critical-user-data-contract-v1.json"
            cp ${criticalUserHomePath} "$out/critical-user-home-data-contract-v1.json"
          '';

        intentional-break-rejected =
          let
            proofBase = {
              networking.hostName = "intentional-break-proof";
              fileSystems."/" = {
                device = "none";
                fsType = "tmpfs";
              };
              boot.loader.grub.enable = false;
              system.stateVersion = "26.05";
            };
            healthy = nixpkgs.lib.nixosSystem {
              inherit system;
              modules = [ proofBase ];
            };
            broken = nixpkgs.lib.nixosSystem {
              inherit system;
              modules = [ proofBase self.nixosModules.intentionalBreak ];
            };
            healthyEval = builtins.tryEval healthy.config.system.build.toplevel.drvPath;
            brokenEval = builtins.tryEval broken.config.system.build.toplevel.drvPath;
          in
          assert healthyEval.success;
          assert !brokenEval.success;
          pkgs.runCommand "heim-pc-intentional-break-rejected" { } ''
            mkdir -p "$out"
            touch "$out/pass"
          '';

        agent-zone-contract =
          let
            agent = self.nixosConfigurations.agent-zone.config;
          in
          assert agent.microvm.interfaces == [ ];
          assert agent.microvm.forwardPorts == [ ];
          assert agent.microvm.shares == [ ];
          assert agent.microvm.devices == [ ];
          assert agent.microvm.vsock.cid == 445;
          pkgs.runCommand "heim-pc-agent-zone-contract" { } ''
            mkdir -p "$out"
            touch "$out/pass"
          '';

        integration = import ./tests/integration.nix { inherit pkgs; };
        host-protection = import ./tests/host-protection.nix { inherit pkgs; };
        firstboot-credentials = import ./tests/firstboot-credentials.nix {
          inherit pkgs sourceRevision;
        };
        trust-zones = import ./tests/trust-zones.nix { inherit pkgs; };
      };

      devShells.${system}.default = pkgs.mkShell {
        packages = with pkgs; [ git gh nodejs python3 rustc cargo jq ripgrep ];
      };
    };
}