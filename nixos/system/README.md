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
- `modules/storage-layout.nix`: production-contract-derived EFI/recovery/LUKS2/Btrfs boot/storage target used by the managed build and physical gate profiles; it is intentionally separate from the disposable Freecom rehearsal contract.
- `../production/contract-v1.json`: isolated parallel-disk production topology. It contains only public structural expectations and non-unique model/size anchors. Exact target/fallback by-id, serial/WWN, filesystem UUIDs and GPT PARTUUIDs come from the mandatory local private identity contract, which is bound to the exact source revision and public-contract digest.
- `modules/*.nix`: desktop, NVIDIA, audio, development, containers, Grabowski, Bureau, networking, backup and observability.
- `zones/agent.nix`: fail-closed untrusted coding-agent zone and capability manifest.
- `tests/integration.nix`: scoped Grabowski/Bureau VM integration proof.
- `tests/trust-zones.nix`: adversarial trust-zone proof.
- `tests/vsock-broker.nix`: test-only no-IP AF_VSOCK broker handshake.
- `../../tests/test_nixos_system_source.py`: repository-level static safety and source-snapshot checks.

## Configuration graph

The host-shaped configurations have deliberately different roles:

- `heim-pc` is the desktop-shaped placeholder. Its root uses `NIXOS_PROTOTYPE_DO_NOT_INSTALL`, so it is not a bare-metal install target.
- `heim-pc-storage-target` is the managed-build candidate. It layers `storage-layout.nix`, which derives `/`, `/nix`, `/boot`, `/recovery` and the LUKS mapper from the production topology contract. Physical proof gates are disabled.
- `heim-pc-physical-gate-proprietary` and `heim-pc-physical-gate-open` layer the **same** `storage-layout.nix` and enable the physical proof gates. Their intended A/B difference is only the NVIDIA kernel-module path.
- `heim-pc-live-gate-*` are non-installing tmpfs ISO proof media. They do not use the storage target and no longer import the container module because Gate A/B does not require Podman/Docker.
- `heim-pc-vm` keeps the placeholder root, disables physical hardware policy and evaluates without NVIDIA hardware enablement.

The physical host profiles enable AMD microcode for the Ryzen platform. The VM proof does not. `alex` is in the `networkmanager` group so the desktop user can manage NetworkManager connections.

The source now defines a fail-closed **first-boot credential contract** for storage-backed physical profiles. This closes the source-design gap only; it does not make the storage target login-ready until a separately authorized disposable installation proves desktop login and administrative recovery. No password, password hash or reusable credential is embedded in Git or the Nix Store.

### First-boot credential contract

The credential producer is a separately authorized privileged staging step outside the Nix build. It generates the **exact default-cost yescrypt form** accepted by the current contract (`$y$j9T$` with the expected 22-character salt and 43-character checksum) while supplying plaintext without putting it in shell history. A producer may use `mkpasswd --method=yescrypt`, but it must validate the generated form before staging and fail if the installed libxcrypt default ever changes away from the pinned `j9T` contract. The consumer also enforces canonical crypt-base64 padding: for the contract's 16-byte salt the final salt character must be one of the first four crypt64 symbols (`./01`), and for the 256-bit checksum the final checksum character must be one of the first sixteen (`./0123456789ABCD`). Exact length plus alphabet membership alone is intentionally insufficient. It does not copy plaintext or hash material into Git, derivations, logs or public receipts. Delivery is target-bound: before the first physical boot, the staging step places two root-owned, single-link `0600` files below the already unlocked encrypted target: the newline-terminated hash at `/persist/secrets/heim-pc/first-boot/alex-password-hash` and a non-secret `/persist/secrets/heim-pc/first-boot/alex-password-bootstrap-authority` record whose exact bytes authorize `initialize-password` for `alex`, the exact 40-hex source revision being booted, **and the SHA-256 of the exact newline-terminated hash file**. This rejects stale or mismatched authority/hash pairs; it is not intended as a defense against a malicious root process. The authority is the provenance signal that permits initialization from the otherwise ambiguous bare lock states `!`, `!!` or `*`; a locked pre-existing hash such as `!$y$…` is still rejected. `/persist` is a canonical real mountpoint in this contract, not a symlink; it must be root-owned and not group/other writable, and each bootstrap namespace directory below it is root-owned `0700`. The repository task stages neither file.

`heim-pc-firstboot-credentials.service` is enabled only for the current **physical + desktop + `/persist`** profiles. Physical first-boot profiles reject dirty or unbound source revisions at Nix evaluation time, and a physical headless profile is an evaluation error until it gains an explicit credential design. A physical desktop profile that omits `/persist` is also an evaluation error unless its root is the explicit `/dev/disk/by-label/NIXOS_PROTOTYPE_DO_NOT_INSTALL` prototype surface; this prevents future real-looking profiles from silently disabling credential admission by forgetting the persistent mount. The prototype host, VM proof and live media do not inherit the bootstrap implicitly. Console autologin is separately restricted to non-physical, non-desktop VM-shaped profiles. The service requires `persist.mount` and is a required predecessor of `systemd-user-sessions.service` and the display manager. This keeps the normal PAM login gate closed until the complete credential transaction succeeds; merely writing `/etc/shadow` is not enough. A root-owned lock file serializes cooperating bootstrap/recovery invocations. Recovery tooling that mutates the account or marker must acquire the same `/persist/heim-pc/bootstrap/.alex-password-bootstrap.lock`; `flock` cannot serialize an unrelated `passwd` or `vipw` process that ignores this contract.

The physical-install workflow must treat credential staging as a **pre-boot admission check**, not rely on a failed login gate as normal operator feedback. Before allowing the first physical boot it must verify that `/persist` is the intended real mount, that both staged files exist with the required owner/mode/link count, that the authority binds the selected source revision and exact hash-file digest, and that the generated hash satisfies the pinned yescrypt contract. Missing staging deliberately keeps the PAM/display-manager gate closed.

The security-critical state machine lives in `hosts/heim-pc/firstboot-credentials.py`; the Nix module reads that file, substitutes only the JSON-encoded source revision, places the result in the Store, and wires the service. Tests execute the helper source directly instead of regex-extracting Python from Nix text. The helper uses descriptor-relative, no-follow filesystem operations below a validated root-owned `/persist` descriptor. It validates the exact source-and-hash-bound authority record, exact default-cost yescrypt structure including canonical crypt64 padding bits, and re-reads both staged bytes plus inode metadata immediately before mutation and again before consumption so a same-length in-place rewrite cannot be silently accepted. Before `chpasswd` can start it creates and fsyncs the **fixed** durable intent `/persist/heim-pc/bootstrap/.alex-password-initialized.pending`, which is also the actual future marker inode, and proves a same-directory hard-link create/unlink cycle. A later normal boot that sees this pending intent fails immediately into recovery instead of consulting a possibly rolled-back shadow value. Pre-mutation failures may remove only the pending inode created by that same invocation; from the instant a `chpasswd` attempt begins until the success marker has itself been durably published, every non-success path preserves the pending evidence — including timeout or non-zero exit even when `/etc/shadow` still contains a bare lock. Once the marker link has been fsynced, a later cleanup/fsync error may leave either the durable marker alone or the marker plus the still-visible pending name. A later boot accepts only the marker-only state; if pending survived it remains recovery-required. Neither state can replay `chpasswd`. The hash is sent to `chpasswd -e` on stdin with a 10-second child timeout; systemd also caps the complete oneshot start at 30 seconds so a stall before or around that child cannot hold the login gate indefinitely. If the service-level deadline lands after durable pending creation, the next boot remains recovery-required rather than replaying `chpasswd`. Afterwards the helper verifies the exact `alex` field from `/etc/shadow`, requires a single-link root-owned shadow file with safe `0600` or NixOS-standard root:`shadow` `0640` permissions, validates that the shadow parent directory is root-owned and not group/other writable, proves that the `/etc/shadow` path still resolves to the verified inode before and after fsyncing that inode plus its directory, consumes the exact previously read secret and authority entries, fsyncs their directory, and re-verifies the shadow value. Regular-file reads use nonblocking no-follow opens so a mistakenly staged FIFO is rejected promptly instead of wedging the login gate.

The success marker is deliberately **create-if-absent**, not replace-on-success. Publication uses a descriptor-relative hard link from the already-fsynced fixed pending inode to `/persist/heim-pc/bootstrap/alex-password-initialized`; if any destination appears concurrently, publication fails without overwriting it. The marker directory is fsynced before and after removal of the pending second link, and the final marker must be one root-owned, single-link `0600` file with the exact schema/content. On later boots, a valid marker never replays `chpasswd`, but it still checks that `alex` has the same canonical default-cost yescrypt shape required by the bootstrap, optionally with the single leading `!` produced by `passwd -l`, and verifies that the path still names the inode that was inspected. This is intentionally aligned with pinned NixOS 26.05, whose `login.defs` default is `YESCRYPT` and whose PAM `passwd` rule explicitly enables yescrypt. It catches a marker that survived an independent root-subvolume rollback or corruption to an empty, bare-lock, truncated, or foreign-scheme shadow value while allowing normal `passwd` rotations and locks. A future password-hash policy change must update this contract explicitly rather than silently widening the login gate. Restaged material, corrupt marker, stale pending intent, missing/mismatched authority, non-initialization-compatible shadow state, malformed hash or unsafe path/ownership/mode fails closed. Any crash, timeout or indeterminate result after the durable pending intent crosses the `chpasswd` boundary but before durable marker completion leaves a recovery-required, **non-replaying** state even if `/etc/shadow` later appears to contain the original bare lock. Only separate recovery authority may reconcile or remove that intent.

Recovery is separate authority. A trusted recovery boot may unlock the encrypted target, acquire the bootstrap lock, inspect the exact shadow/secret/marker state, restore administrative access with `passwd alex` if needed, and reconcile the marker only after independently verifying the intended account state. Normal boot never clears the marker or silently restages credentials. `users.mutableUsers = true` is an explicit host-wide policy (and the NixOS default), not an `alex`-only switch; whenever the first-boot bootstrap is active, Nix evaluation asserts that `alex` has none of `password`, `hashedPassword`, `hashedPasswordFile`, `initialPassword`, or `initialHashedPassword`, and the account UID is pinned to the current persistent identity `1000`. A separately authorized disposable installation must still prove real graphical login and administrative recovery before bare-metal login readiness can be claimed; source tests and VM console autologin are explicitly not substitutes for that proof.

Managed activation v1 supports only `test` and `next-boot`. Receipt-bound persistent promotion is separate v2 work tracked as `HEIM-PC-NIXOS-MIGRATION-V1-PERSISTENT-V2`.

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

Workflow presence alone has not re-established Nix/QEMU/KVM execution evidence. Current acceptance comes only from the exact checked-out revision and completed step results below. The source now carries a dedicated `heim-pc-nix` CI lane. It is designed to run `nix flake check --no-build`, evaluate the storage target, both gated physical profiles and the VM profile, assert the evaluated storage/boot/microcode/user-group/gate values, and build the storage-target and VM system closures without activating either. Presence of that workflow is **not** itself a passing result: PR metadata may claim current Nix evidence only after GitHub reports the exact PR head green.

The `profile-contract` report is evaluated configuration metadata, not a system-build receipt. Its VM derivation path deliberately carries no build dependency; the separate storage-target/VM closure build remains mandatory. `live-block-inventory.jq` is exercised by executable JSON and shell-failure tests; the CI also builds the live safety script and runs the scoped VM checks. None of these establishes a physical live-ISO boot.

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
- runtime credential readiness for a fresh bare-metal installation: the fail-closed source contract and separately authorized disposable graphical-login/admin-recovery proof now exist; target-bound secret staging and later physical acceptance remain unproven, so bare-metal login readiness remains blocked.

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


### Production Seagate installer

The production path is deliberately split into **prepare -> plan -> apply** and remains separate from the disposable Freecom/T017 rehearsal authority. `../../scripts/nixos_production_prepare.py` routes automated work through `../../scripts/managed_build.py` plan/run, accepts only a clean exact Git revision, bundles that revision, evaluates and builds `heim-pc-storage-target` in the pinned Nix Docker image, retains the resulting `/nix` closure in a revision-named Docker volume, and emits a private crash-safe create-only install-artifact JSON. It has no block-device mutation surface. A branch-head artifact is technically marked `proof-only`; `merged-main` can only be prepared after a fresh `origin/main` fetch proves the exact source revision, and Apply rejects `proof-only` artifacts unconditionally.

`../../scripts/nixos_production_install.py` consumes the exact artifact plus a mandatory local `--identity-contract`. The private identity file is bound to the artifact source revision and public-contract digest and supplies the exact disk identities outside Git. Kernel names remain observation-only. Closure verification uses the pinned-image Nix binary against the prepared store mounted separately read-only.

Before any effect, the planner requires the target to remain blank and unmounted, checks hidden signatures with read-only `wipefs`, proves `/` and `/boot/efi` still resolve to the protected WD, verifies all declared WD by-id aliases, captures the live GPT disk GUID plus partition offsets/type GUIDs/names/attributes into the preimage fingerprint, rejects target/protected alias collisions, verifies the exact artifact/source revision and scratch state, and binds the plan to the private identity digest. The default CLI output contains only a redacted plan summary; a full private plan requires explicit `--write-plan` and is create-only mode 0600. Apply additionally requires root, a `merged-main` artifact, the exact plan confirmation, and interactive credentials. GPT creation uses private plan-bound PARTUUIDs; formatting and LUKS address only target-derived stable by-id partition paths. Containerized filesystem/install tools no longer receive global `--privileged` or `/dev:/dev`; only the target mapper is exposed where a block device is required. The installed profile, Seagate ESP, encrypted `@persist`, EFI/NVRAM state, complete fallback GPT fingerprint and closed mapper are all verified after the run.
