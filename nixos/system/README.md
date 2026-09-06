# NixOS Heim-PC vNext prototype

Non-production prototype for the long-term Heim-PC operating-system architecture.

This directory is deliberately safe to evaluate/build in isolation. It must not be interpreted as permission to install NixOS, change partitions, replace the bootloader or switch the running Heim-PC.

## Architecture thesis

NixOS is being tested not merely as a desktop distribution, but as the declarative control substrate for an autonomous operator machine:

```text
NixOS host
├── trusted control plane: Bureau / Grabowski / Rootbroker
├── trusted hardware services: NVIDIA/local-AI, audio/MIDI, backup, observability
└── disposable untrusted agent MicroVMs
    ├── no ambient IP
    ├── no host filesystem share
    ├── no raw GPU/audio/device access
    ├── AF_VSOCK capability broker only
    └── patch + test + evidence output
```

The hard security assumption is that an arbitrary coding agent may become root inside its own VM. It must still not inherit the host filesystem, desktop session, Docker socket, raw hardware or an unscoped privileged broker.

## Important files

- `flake.nix`: host, VM, MicroVM, lifecycle and check graph.
- `hosts/heim-pc/default.nix`: shared Heim-PC host assembly; the default root remains a non-installing placeholder unless `storage-layout.nix` is explicitly layered in.
- `modules/storage-layout.nix`: contract-derived EFI/recovery/LUKS2/Btrfs boot/storage target used by the managed build and physical gate profiles.
- `modules/*.nix`: desktop, NVIDIA, audio, development, containers, Grabowski, Bureau, networking, backup and observability.
- `zones/agent.nix`: fail-closed untrusted coding-agent zone and capability manifest.
- `tests/integration.nix`: original whole-host VM integration proof.
- `tests/trust-zones.nix`: adversarial trust-zone proof.
- `tests/vsock-broker.nix`: test-only no-IP AF_VSOCK broker handshake.
- `../../tests/test_nixos_system_source.py`: repository-level static safety and source-snapshot checks.

## Configuration graph

The host-shaped configurations have deliberately different roles:

- `heim-pc` is the desktop-shaped placeholder. Its root uses `NIXOS_PROTOTYPE_DO_NOT_INSTALL`, so it is not a bare-metal install target.
- `heim-pc-storage-target` is the managed-build candidate. It layers `storage-layout.nix`, which derives `/`, `/nix`, `/boot`, `/recovery` and the LUKS mapper from the rehearsal contract. Physical proof gates are disabled.
- `heim-pc-physical-gate-proprietary` and `heim-pc-physical-gate-open` layer the **same** `storage-layout.nix` and enable the physical proof gates. Their intended A/B difference is only the NVIDIA kernel-module path.
- `heim-pc-live-gate-*` are non-installing tmpfs ISO proof media. They do not use the storage target and no longer import the container module because Gate A/B does not require Podman/Docker.
- `heim-pc-vm` keeps the placeholder root, disables physical hardware policy and evaluates without NVIDIA hardware enablement.

The physical host profiles enable AMD microcode for the Ryzen platform. The VM proof does not. `alex` is in the `networkmanager` group so the desktop user can manage NetworkManager connections.

A secure credential/first-boot bootstrap is **not yet defined** for a fresh physical installation. No password or password hash is embedded in Git or the Nix Store. Therefore the storage target is a build/proof candidate, not yet a login-ready bare-metal install. This is a blocking pre-bare-metal successor gate, not something this publication PR may silently invent.

## Agent-zone contract

The default zone declares:

```text
interfaces       = []
forwardPorts     = []
shares           = []
devices          = []
storeOnDisk      = true
vsock.cid        = 445
```

The embedded capability manifest currently permits only named broker/workspace/git/GitHub/LLM/artifact operations and explicitly denies host shell/filesystem/home, SSH keys, Docker socket, host systemd, raw network, raw GPU/audio and unscoped Rootbroker access.

This manifest is an architecture contract, not yet the final production authorization protocol.

## Current snapshot evidence status

The current snapshot has not re-established Nix/QEMU/KVM execution evidence yet. The source now carries a dedicated `heim-pc-nix` CI lane. It is designed to run `nix flake check --no-build`, evaluate the storage target, both gated physical profiles and the VM profile, assert the evaluated storage/boot/microcode/user-group/gate values, and build the storage-target and VM system closures without activating either. Presence of that workflow is **not** itself a passing result: PR metadata may claim current Nix evidence only after GitHub reports the exact PR head green.

Historical Store paths, QEMU/KVM runs and earlier Nix evaluations remain historical. They cannot be promoted to evidence for a later source revision after NixOS modules, storage profiles, tests or workflow definitions change. Exact-head CI/review evidence and historical architecture evidence must remain separately labelled.

The current source statically exports `nixosModules.intentionalBreak` as an explicit negative-path module. That source shape is not an execution claim until the exact revision has actually passed the Nix evaluation lane.

## Historical evidence from earlier revisions — not re-established for this snapshot

Every result below is historical evidence from the explicitly named revision/artifact where one is given, or from an earlier prototype run where the old record did not bind a revision in this file. None of these results establishes that the current PR head evaluates, builds, boots, reproduces the same Store path or passes the current test definitions.

### Whole host (historical)

Earlier prototype runs recorded successful NixOS 26.05 host evaluation/build, repeated closure realization, a QEMU integration pass and a normal `nix flake check --no-build` pass. Those runs predate the current NixOS-module/test changes and are **not** current-snapshot acceptance evidence.

### Foreign-binary corpus

The original Claude-only A/B proof has been expanded to fourteen real executable/install-path cases in offline NixOS 26.05 KVM VMs.

Bare NixOS passed only the two static cases (Codex and `gh`). One common `nix-ld` profile plus the C++ runtime then made eleven additional cases start successfully: Claude, Cline's cached native CLI, Antigravity, Jules, OpenCode, Goose, `uv`, UV-managed CPython, the current system Node binary, Docker CLI and Aider's UV environment.

OpenHands also crossed the foreign-loader boundary and initialized its UV Python/OpenHands/LiteLLM stack. Follow-up showed that a network-unshared host run returns 0 and that `LITELLM_LOCAL_MODEL_COST_MAP=True` suppresses the remote model-cost-map fetch. A 60-second NixOS follow-up then showed the real timing: `import openhands.sdk` and `openhands --version` both returned 0 after about 23 seconds, with the CLI printing `OpenHands CLI 1.16.0`. The earlier short-harness timeouts were insufficient observation windows, not lifecycle failures.

Machine classification:

```text
native-portable                                  2
nix-ld-required-pass                            11
nix-ld-loader-pass-offline-startup-timeout       1
needs-followup compatibility failures            0
```

The previously open software classes were then exercised directly:

- Qwen native npm addons: audio capture, `node-pty` and clipboard all loaded successfully in an offline NixOS VM (3/3);
- real Cargo/Rust prebuilts: `cargo-audit`, `cargo-deny`, `lychee` and `sqlx` all returned 0 (4/4). NixOS 26.05's normal `nix-ld` baseline already includes the common OpenSSL/runtime libraries needed here, so no per-tool library rule was added;
- official Obsidian 1.13.7 x86-64 AppImage, SHA-256 `e0d8e0a611624de8c9c7dcd8a9e648279fb0a0d552faa1312b7e4f3a5fa72663`: both explicit `appimage-run` and the configured AppImage path recognized and fully unpacked it. A current NixOS 26.05 follow-up (`5dfba6236110080a54247d6460bc2ff5dda939cc`) then ran the same artifact as a normal guest user under Xvfb with networking disabled. Obsidian loaded `resources/obsidian.asar` and remained alive for the full 12-second observation window until the deliberate timeout; only the expected offline update checks failed. Earlier root-sandbox and headless-segfault results were harness artifacts rather than AppImage/NixOS compatibility failures.

This is now a PASS for the hypothesis that one stable NixOS compatibility contract can cover the representative current agent/tool corpus, native addons, Rust prebuilts, OpenHands and a real AppImage. It is not a claim of universal third-party compatibility; long-duration real desktop observation remains.

### Secure Boot software/VM subgate

A separate ephemeral build against the prototype's exact pinned NixOS 26.05 revision `c5c4a43b0e8056328ec4529f735cabdb8f1942bb` enabled the native Limine bootloader plus `boot.loader.limine.secureBoot.enable = true`. Evaluation succeeded and the full system toplevel built:

`/nix/store/9hkm1xnw4b5cjbjfzvkhd2dlrknl9di6-nixos-system-gate-d-limine-proof-26.05.20260829.c5c4a43`

The pinned Limine module requires `enrollConfig`, `validateChecksums` and `panicOnChecksumMismatch` when Secure Boot is active, and the build graph materialized `limine-install.json`.

A stronger runtime proof then passed on current NixOS 26.05 revision `5dfba6236110080a54247d6460bc2ff5dda939cc`: NixOS' own `nixosTests.limine.secureBoot` booted under OVMF Secure Boot and completed at

`/nix/store/2xi8y74ijvfylrz2q8fzrrap5spsqlxl-vm-test-run-secureBoot`

with `NIXOS_LIMINE_SECUREBOOT_PASS`.

A direct active-enforcement A/B tightened that result. With pre-enrolled OVMF Secure-Boot variables, a correctly signed Limine fallback EFI reached NixOS userspace and emitted `ENFORCED_SECUREBOOT_RUNTIME secure=1 setup=0`, `ENFORCED_LIMINE_BOOT_FILES_PRESENT` and `ENFORCED_SECUREBOOT_RUNTIME_PASS`. A one-byte modification of the same signed EFI invalidated its signature; OVMF then rejected the same `Boot0003 "UEFI Misc Device"` path with `Access Denied`, and no NixOS runtime-pass marker appeared. A read-only validator returned `TAMPERED_LIMINE_FALLBACK_REJECTED_PASS`.

A second route was tested independently. Lanzaboote v1.1.0 at revision `7c9a54a7f87b4539ddbd8bda09a8a5f5f9361aa9` built against NixOS 26.05; an intentional systemd-boot conflict failed closed, while its `basic`, `hash-mismatch-kernel-sb`, `hash-mismatch-initrd-sb` and `auto-generate-enroll` KVM checks all passed.

**Secure-Boot software/VM verdict: strong PASS through two routes, including causal Limine signature enforcement.** Limine is the preferred baseline because its option, installer and upstream KVM test are inside the NixOS graph; Lanzaboote remains a credible fallback if the physical ASUS firmware behaves better with it.

### LUKS reconstruction and manual-passphrase VM subgates

The terminal replacement-disk proof uses current NixOS 26.05 revision `5dfba6236110080a54247d6460bc2ff5dda939cc` with Disko 1.13.0. Starting from a blank virtual disk, it creates a GPT with a 500 MiB EFI System Partition and a LUKS partition containing ext4 root. Explicit test-only secret staging lets the test exercise the storage/boot path without pretending that a Nix Store key is an acceptable production secret design.

The persisted test-driver log shows LUKS opening in the initrd, `/dev/mapper/crypted` becoming root, ext4 mounting as `/sysroot`, switch-root completing, `/boot` mounting as vfat and the guest reaching Multi-User System. All explicit runtime assertions pass. The v7 harness then explicitly shuts the guest down; the complete build returns `BUILD_RC=0` at `/nix/store/i45fzfw5nxbng33px5vs8mdbdw6bjgbn-vm-test-run-disko-heim-pc-gate-d-luks-replacement-v7`.

Disko 1.13.0's own systemd-initrd encrypted-test helper predates upstream fix `baf057aa5b861c549b9ee92807e43ae49ab50cf6`, which stages `/tmp/secret.key` through `boot.initrd.secrets`. That release lag is tracked separately; it did not prevent the underlying Disko/LUKS contract from working once the already-upstream behavior was modeled.

A separate interactive test proves the passphrase path rather than inferring it. A causal A/B exposed two test-harness issues: the current nested-harness `switch-to-configuration boot` path did not select the encrypted specialisation, and bounded `wait_for_console_text()` can lag behind the already-complete serial log because it drains one queued line per retry. Using the pre-June direct systemd-boot test definition only for boot selection, current NixOS 26.05 runtime bits, and a bounded full-console prompt check produced `BUILD_RC=0` at `/nix/store/2zrj2nlrpmxrdpmplkwqlrf7a6g9q1d7-vm-test-run-heim-pc-gate-d-manual-luks-full-console-current-nixos`. One passphrase unlocked both `cryptroot` and `cryptroot2`; the upstream mount assertions passed, multi-user was reached and the guest shut down cleanly.

**Virtual encryption/reconstruction and manual-passphrase verdict: PASS.** No physical key enrollment, EFI-variable mutation, production-ESP mutation or firmware change occurred. The injected test key was a world-readable Nix Store object and is explicitly test-only; production encryption/recovery material must live outside the Store. Gate D remains open for real ASUS enrollment/boot selection, independent recovery and rollback, firmware-update behavior, and repetition on a separate physical test disk.

### Agent MicroVM

The strict agent zone has been evaluated with empty network/share/device lists, built as a real MicroVM closure, rebuilt to the same Store path and booted under KVM. Its fail-closed contract service completed successfully.

### No-IP host capability transport

The test-only VSOCK variant booted under KVM and completed a real guest-to-host request:

```text
guest CID 445 -> host CID 2 : port 18446
request: broker.status
response: broker-ok
```

The host listener observed CID 445 and the exact request while the guest had no configured IP interface, host directory share or raw device passthrough.

That historical run proved the transport primitive for its tested source. It has not been re-established for the current snapshot. Production authorization, authentication, replay protection, structured schemas, task binding and workspace artifact transfer remain future work.

### Git→build→runtime provenance

Clean Git commit `1b396a483b93d4534fdc0136496384e0a78130da` passed the strict prototype provenance gate. Path-only/unbound sources fail closed at the explicit `provenance-guard`.

The resulting bundle records separate identities for:

```text
declared-system
declared-etc
vm-runner
runtime-system
runtime-etc
source-revision
```

The separation is intentional: NixOS `system.build.vm` boots `virtualisation.vmVariant`, whose runtime system closure is not identical to the declared proof configuration closure.

Final proof bundle:

`/nix/store/6c57ajnarcg01zy48l3sqx7zmr8mvgs1-heim-pc-provenance-bundle`

The booted guest reported the same Git revision and exactly the bundle's runtime system closure:

`/nix/store/3ma3hghj35n3pfzpb8fihhfj9iw34gl8-nixos-system-heim-pc-26.05.20260829.c5c4a43`

The declarative Grabowski runtime-readback completed, multi-user was reached, and a control-code-neutral validation returned nine successful checks plus `GIT_BUILD_RUNTIME_PROVENANCE_PASS`.

That run closed Git→build→runtime identity for the historical prototype revision named above. It does **not** close Git→build→runtime identity for the current PR head; that requires a fresh exact-source Nix build and runtime readback. Bureau approval/promotion and physical bare-metal activation/readback remain separate production integration work.

## What this prototype does not prove

It does not yet establish:

- a successful exact-head Nix CI result until GitHub has actually completed the `heim-pc-nix` lane for that revision; workflow presence alone is not evidence;
- a current guest→host AF_VSOCK handshake or no-IP runtime proof for this exact PR head;
- real RTX 4070 Ti SUPER + KDE/Wayland reliability;
- CUDA/Ollama/llama.cpp/GPU-container behavior on the physical card;
- repeated suspend/resume;
- MOTU M2 / Roland FP-30X PipeWire/JACK/MIDI behavior;
- long-duration real desktop workload observation beyond bounded compatibility smokes;
- Secure Boot + LUKS + recovery on the real UEFI machine; blank-disk reconstruction and manual passphrase unlock already pass in KVM, but physical enrollment, current firmware boot selection, independent recovery/rollback and production secret handling do not;
- Bureau approval/promotion -> physical host activation -> exact runtime identity readback;
- production Rootbroker capability protocol;
- secure credential/first-boot bootstrap and login readiness for a fresh bare-metal installation.

Those are migration gates, not details to hand-wave away.

## Safety properties

The host prototype deliberately contains a non-existent placeholder root label rather than a real disk target and must remain non-destructive. Static tests reject destructive disk/install commands in the prototype sources.

No production `nixos-rebuild switch`, repartitioning, `mkfs`, bootloader install or similar action belongs in this prototype phase.

## Evaluation direction

Current strategic hypothesis:

- Fedora Atomic/bootc is the stronger "best today" option and the MAC/OCI reference challenger.
- NixOS is the conditional "best future" option because host, services, trust zones, tests and rollout identity can live in one coherent declarative graph.
- The decision remains reversible until the physical GPU/audio/Secure-Boot/recovery gates pass and long-duration real-workload behavior is acceptable.

See `../../architecture/os-future-evaluation-20260901.md` for the evidence-weighted comparison and flip conditions.
