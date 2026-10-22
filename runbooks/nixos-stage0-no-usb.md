# USB-free NixOS Stage0 on the internal Seagate (NONPRODUCTION)

Source and PR authority: heimgewebe/heim-pc PR #238.
Hardware-executor handoff and results: heimgewebe/heim-pc Issue #237.
This document and development-thread tests DO NOT authorize physical apply.

## Immutable source and realized artifacts

- Stage0 profile: nixosConfigurations.heim-pc-stage0
- Built source commit: e68efce49eaba0014865fd1c4e0b62f692f016af
- Built system: /nix/store/9imhrwyy6bf5fkhqrjfx6dqn4rva8y67-nixos-system-heim-pc-stage0-26.05.20260829.c5c4a43
- Original build Docker Nix image: sha256:98edc6813218e179ce84587373e0b52d4aa58babae2d26b51fb01e7fdacf815f
- Original build-only Nix volume: heim-pc-nixos-stage0-e68efce49eab
- Runtime installation source: **standalone, digest-bound OCI image** sha256:91b210f35fe468e2901448b5d9dadbadcf12e3240121d573c08255028f874aa9; complete store at /sealed-nix inside its image lower layer
- Pinned internal helper SHA256: b3c1009e1b5c927e537487c80639cdf404f69e3eb49371d9be5d841672be3ff9 (/busybox)
- Measured NAR hash + NAR size, bound in `SEALED_NAR` and root release seal:
  - NixOS system: `sha256-ocr+cay5yrcarnw5ZzFxQnht7pTQwC1HEMbU/i8zN4U=`, 200200 bytes
  - Official `nixos-install`: `sha256-bxwMQvK0elYQJUdV2+uKVeGDf9TVHTz5v/8uhagZPs8=`, 15464 bytes
  - `util-linux-minimal`: `sha256-QTeruJR6p/tf7gNryZqDMHuT63N9rqrADmS2aBuRB4I=`, 8905168 bytes
- Physical-source admission candidate: root-owned private file /etc/heim-pc/stage0-sealed-oci-source-v1.json (not yet issued or independently approved)
- Local store evidence directory: /home/alex/.local/state/heim-pc-stage0-e68efce49eab
- The exact realized official nixos-install store path is in stage0-tools.
- Driver: scripts/nixos_stage0_install.py (separate from the production installer).
- The driver requires committed, clean Git HEAD descended from the build
  source; it rejects differences under nixos/system since that build and
  binds its own script hash to the plan. Do not modify the NixOS system module
  while reusing this system closure.

These artifacts prove local build and verification, not independent
attestation of an unmodifiable installation store or physical bootability.

## Physical target limits

WD_BLACK SN850X (2TB NVMe) remains Pop!_OS with independent WD ESP;
neither its GPT, bootloader, filesystems nor EFI NVRAM is an installation
target. The only intended destination is internal Seagate ZP4000GP304001
(4TB NVMe), with existing GPT:
- p1: own 1GiB vfat NIXOS2_EFI; mount on Stage0 /boot, no reformat
- p2: own ~4GiB ext4 NIXOS2_RECOVERY; do not mount/write
- p3: ~3.995TB unformatted, historical GPT Linux-LUKS type, PARTLABEL
  NIXOS2_CRYPT; rewrite p3 type to Linux filesystem and name, format p3
  (only) Btrfs label NIXOS_STAGE0_ROOT, with no force flag. Absence of a recognized signature does not prove that
  all p3 bytes are unused; a separate explicit p3 data-loss decision is mandatory
- No USB media is needed. External Freecom and Game Drive are not targets.

The physical Plan/Apply is **hard-bound to the exact pre-identified
two internal NVMe drives**, not merely models of similar capacity:

- Seagate: `/dev/disk/by-id/nvme-Seagate_ZP4000GP304001_7VS01DX7`,
  model `Seagate ZP4000GP304001`, serial `7VS01DX7`,
  WWN `eui.6479a7716f000a39`, exactly `4000787030016` bytes,
  GPT disk GUID `B862830A-C8F1-4968-BF65-636B87BC2E85`.
- Protected WD: `/dev/disk/by-id/nvme-WD_BLACK_SN850X_2000GB_25025T802519`,
  model `WD_BLACK SN850X 2000GB`, serial `25025T802519`,
  WWN `eui.e8238fa6bf530001001b448b4d59e756`, exactly
  `2000398934016` bytes, GPT GUID
  `79AA7645-4DEA-4992-BF90-72E8D75E117B`.

Stage0 refuses swapped, differently numbered, similar model, mismatched
serial/WWN/geometry or changed GPT-disk-ID inputs **before planning**.
The physical unit identities and byte sizes were re-observed read-only
on 22 October 2026. They do **not** prove permission to destroy p3.

The operator must still freshly prove matching private partition aliases,
GPT partition types/PARTUUIDs, read-only `wipefs` signatures, kernel
holders, all mounts, unique filesystem labels, and protected WD
root/ESP mount lineage. Never infer identity from `nvme0n1/nvme1n1`;
Plan and Apply fail closed on hardware drift, occupied labels or ESP loader
conflict. A non-root `wipefs --no-act` probe returned permission denied;
this cannot substitute for a privileged read-only p3 signature check.

## No-effect plan (hardware executor only, root-owned 0600)

Only the authorized physical hardware executor may run this
**effect-free**, create-only Plan, after receiving access through the
legitimate root/TTY route and proving the source checkout and built-store
revision. A generic substitute NVMe alias is deliberately rejected:

    sudo python3 scripts/nixos_stage0_install.py --plan \
      --seagate-by-id /dev/disk/by-id/nvme-Seagate_ZP4000GP304001_7VS01DX7 \
      --wd-by-id /dev/disk/by-id/nvme-WD_BLACK_SN850X_2000GB_25025T802519 \
      --plan-file /root/nixos-stage0-plan.json

The plan is create-only, private mode 0600, and records source/script/store
identity, precise live Seagate/WD observations, fingerprints of WD GPT,
entire WD ESP contents, Seagate GPT, and EFI boot listing. Output prints
the SHA256 of the plan, not its private contents. Planning creates no GPT,
filesystem, mount, NVRAM or boot effects.

## Apply remains subject to new hardware authority and independent review

**Physical Apply remains blocked in the current host state.** The
previous unconditional guard has been replaced in the *published Stage0
source branch* by a strictly evaluated admission contract. It does not
constitute release authority. It rejects
any mutable/source-volume identity and requires an **absent by default**
root-owned, 0600, NOFOLLOW `/etc/heim-pc/stage0-sealed-oci-source-v1.json`
in a root-owned non-group-writable directory. The schema binds original
Nix build revision/image, exact pinned current source HEAD and installer
script bytes, OCI image digest, system/installer/util-linux store paths,
their independent expected NAR hashes/sizes, BusyBox SHA256, two
historical evidence report SHA256 values and a
review-receipt SHA256. An actual *separate* root-owned 0600 file
`/etc/heim-pc/stage0-independent-source-review-v1.json` is required:
the content hash must match the seal; its source HEAD, script SHA, OCI ID,
review disposition, reviewer and exact PR #238 review URL must match.
**Neither root-only ownership nor a plausible GitHub URL authenticates
reviewer identity or constitutes an independent approval.** Independent
issuance and verification of the review receipt and source-chain authority
are **not implemented or approved**.
A syntactically valid review digest is not proof of review. Therefore **do
not create this seal or run physical Apply** pending exact independent
security review and hardware authority. Missing/mismatching seal is
rejected before any hardware snapshot, GPT write, store copy or install.

The actual four Docker execution phases (recursive verify, namespace
preflight, Nix copy, official nixos-install) are now tied to the same
`--pull=never` immutable OCI image, with no original named source
volume mounted. The Nix metadata writable state is transient and
container-local, discarded at `--rm`. The Docker daemon and privileged
host root remain part of the trusted computing base; a pinned image ID
and COW isolation alone do not defend against their compromise.

Do not run Apply until this issue/PR names the reviewed immutable HEAD,
fresh green checks, successful synthetic installation proof (not just
mocked unit tests), ability to select the Seagate's independent EFI boot
path, and explicit physical authority. This thread NEVER runs Apply.
Only the hardware executor may consider, after checking those gates:

    sudo python3 scripts/nixos_stage0_install.py --apply \
      --plan-file /root/nixos-stage0-plan.json \
      --confirm 'APPLY-STAGE0:EXACT-PLAN-SHA256'

Root-owned 0600 plan, real interactive TTY, exact confirmation SHA256,
snapshot equality and matching Git/script/closure/build sources are
mandatory. The private 0600 plan is read from one NOFOLLOW file descriptor
with fstat on the same inode, then checked against the exact Seagate p3-GPT
type rewrite and root label. Git source inspection uses an explicit,
checkout-scoped safe.directory without changing global Git configuration.
Source store integrity must pass a fresh recursive verification
before any physical disk mutation. Existing Pop!_OS and EFI variables are
outside mutation scope. Before changing GPT, Apply now probes all host
storage tools (including btrfs, mkfs.btrfs, sgdisk) and runs the pinned
NixOS chroot mount-namespace preflight in a Docker container without
host-device binds or networking. This addresses the previously observed
missing-host-btrfs-tools and Docker default-AppArmor denial.
The exact pinned util-linux/minimal closure is also verified recursively;
the mount namespace probe executes its unshare/mount directly (without
using the unverified default-profile Bash executable).

The user password is now requested, confirmed (up to three attempts),
and hashed BEFORE the very first ESP mount/GPT/filesystem write; only
the private SHA-512-crypt hash remains for final /etc/shadow insertion.
Credential input errors therefore cannot produce a half-formatted target.
No password, salt/credential plaintext or hash is placed in Git or logs.

Expected guarded sequence, not yet a physical install receipt:

1. Recheck source/target and existing Seagate EFI loader absence. The
   preflight mounts Seagate p1 only, never the WD ESP; after unmount it
   removes the temporary HOST /mnt/.../boot stub and verifies no active
   mount remains. The parent mountpoint is removed on clean completion
   only if this invocation created it.
2. Change the Linux-LUKS historical GPT type of ONLY Seagate p3 to
   Linux filesystem; rename its partition label NIXOS_STAGE0_ROOT.
   Verify all three Seagate PARTUUIDs remain unchanged and the protected
   WD/EFI invariants remain unchanged.
3. Recheck no hidden p3 signatures, mkfs.btrfs without -f on by-id p3.
4. Create Btrfs subvolumes @root, @nix, @home, @persist. Mount
   target /, /nix, /home, /persist and the existing Seagate p1 on /boot.
5. First populate the fresh target Nix store from the source-bound built
   system closure via official Nix copy --to local?root=/mnt. Offline copy
   requires source Nix DB metadata temporarily writable and --no-check-sigs
   for locally built unsigned paths; the source is verified before GPT.
   OCI runtime needs namespace-local SYS_ADMIN to bind its sealed lower
   image layer /sealed-nix to /nix; no host physical device is passed to
   Docker and the original source volume is not mounted. Before the
   privileged installation, the new driver verifies the recursively
   copied target system content with
   `nix store verify --no-trust --recursive --store local?root=/mnt`.
   Here `--no-trust` only disables the signature requirement for an
   unsigned local source build; it does **not** disable content checks.
   The source verifies all three pre-pinned NAR identities after its
   recursive store verification and before writing GPT.
6. Run source-bound official nixos-install in the pinned standalone OCI
   image, with image lower-layer /sealed-nix privately bound to /nix and
   only the Seagate target mount writable (no shared source volume):
   --root /mnt --system BUILT-SYSTEM --no-root-passwd --no-channel-copy.
   Verified chroot use requires Docker SYS_ADMIN, seccomp=unconfined and
   apparmor=unconfined; this is a security-sensitive installation container
   with no network or raw host-disk device mounts. The NixOS profile has
   boot.loader.efi.canTouchEfiVariables=false.
7. Verify nonempty Seagate EFI/BOOT/BOOTX64.EFI, referenced kernel/initrd
   files, unique loader arguments including exact init=BUILT-SYSTEM/init,
   and NixOS 26.05's evaluated root=fstab (the Btrfs label is resolved
   through the initrd filesystems). Install ONLY the previously prepared
   private crypt hash into the installed /etc/shadow; no second interactive
   prompt after disk mutation. Refuse an existing alex password; root
   remains locked. Validate WD GPT/ESP and EFI boot entry fingerprints
   before/after. Unmount in reverse order and verify every mount is gone;
   cleanup errors require manual recovery.
8. There is no automatic reboot or automatic firmware entry update.
   Any partially completed GPT/format/install effects require
   explicit diagnosis, never an unreviewed retry.

This is unencrypted, nonproduction Stage0; no confidential user data
or productive workloads should be migrated.

## Proof boundaries and current root-broker constraint

An actual source-bound NixOS scratch install was followed by
nixos-enter --root /mnt inside an isolated Docker volume. After adding
Docker apparmor=unconfined (the tested minimum change needed for its
unshare/mount logic), NixOS activation created the alex account and
/etc/shadow; the probe succeeded and the scratch volume was removed.
The pinned source has effective boot.kernelParams containing root=fstab,
so verifying a literal NIXOS_STAGE0_ROOT label inside the EFI loader
entry would incorrectly reject a valid NixOS boot configuration.
Neither probe establishes a FAT ESP bootloader install, real first
login, UEFI firmware disk selection or a physical NixOS boot.

An independent virtual UEFI boot using the NixOS
`vmWithBootLoader` derivation was also **actually run** in QEMU/KVM with
OVMF: firmware launched systemd-boot, and a captured 1280×800 VGA frame
showed `Welcome to NixOS ... tty1` and `heim-pc-stage0 login:`.
See Issue #237 comment 6334889268 and the private screenshot hash
`696b5faabdba72138c0b648fc5539455e8b78c4aaed1d9774a5788077c38238a`.
That VM uses a specially generated ext4/QCOW2 root and does not prove
the actual Btrfs/Seagate installer, physical UEFI device selection,
password authentication or Pop!_OS WD rollback.

The currently audited root broker cannot access the source checkout
under /home/alex or a developer interactive TTY. This exact source
driver therefore CANNOT be considered directly executable through
that broker. Do not bypass sudo, the broker, source seals, hardware
permission or protected WD boot verification to work around it.
Root-authorized staging/credential input and **physical** firmware/rollback
control are required before physical Apply. A separate actual *virtual*
Btrfs/ESP installation and tty1 login with test-only credentials has since
been completed, but does not validate the real Seagate, host root broker,
Pop!_OS restart, or the complete physical script's hardware-apply path. Pop!_OS's
current initrd changed and was regenerated after a package trigger;
a complete physical Pop!_OS boot has not yet been proven. Preserve
the updated WD ESP/boot preimage and do not assert that WD files were
byte-unchanged from the older pre-package baseline.

## Independent PR security review: bounded fixes and unresolved P1

At the published R2 baseline (c7ca36e2d5b070f1740e20e0c1024ccb6f0ef2bd),
an independent review of earlier commit e2712dd identified three concrete
correctness/security issues:

- P1, trusted installer source: `stage0-tools` formerly accepted any
  syntactically valid Nix Store installer path. The helper now pins the exact
  realized `nixos-install` store path and verifies **both** the NixOS system
  and the installer recursively before any disk write. This closes only the
  unpinned-installer and omitted-verification subissues. The verification
  is a point-in-time check against local Store metadata; it is **not** an
  independent attestation of an immutable installation source.
- P1, source store lifetime: the old volume was mutable between verify
  and install. The new source candidate completely eliminates that
  volume from the installer pipeline, using pinned image lower layers.
  A separate OCI/Review-admission mechanism is now required before
  any physical disk observation, but its external attestation authority
  and full scratch install/boot tests still require review. The P1
  thread remains open until independently confirmed at the final HEAD;
  a documented conditional guard is not a compensating approval.
- P2, cleanup false success: the helper now reports installation success
  only after all target mountpoints have been unmounted and read back as
  detached. Failed umount or persistent mounts produce a nonzero failure
  and a manual-recovery alarm. Negative tests cover both cases.

The GitHub CI `validate` failure for the earlier R2 head was caused by a
test inadvertently reading the runner's real kernel holder state. The
test now uses an entirely synthetic sysfs fixture, with a separate
negative holder regression. The full local Python suite subsequently
passed (2167 tests, 1 skipped, 465 subtests), as did the 37 Stage0 tests
and 52 NixOS-source unit regressions. **These tests do not resolve the
outstanding immutable-source P1 or constitute physical boot evidence.**

## Sealed OCI candidate: actual integration proof, not a source release

An independently created, self-contained OCI image now embeds a snapshot of
the built Nix Store, rather than sharing the mutable Docker volume:
`sha256:91b210f35fe468e2901448b5d9dadbadcf12e3240121d573c08255028f874aa9`.
Its layer-separated Nix content and concurrent-container COW isolation were
tested without any Seagate/WD device mount; see the independent source
review thread and
`/home/alex/labs/heim-pc-stage0-sealed-oci-prototype-20261022.md`.
A further **real** no-bootloader scratch installation from this exact image
finished successfully in a disposable target Docker volume, task
`547d1aa18bf34756b76cea25`, marker
`STAGE0_SELFCONTAINED_OCI_OFFLINE_NO_BOOTLOADER_INSTALL_OK`.
It did not share the old source Docker volume with the installation
container. This is an actual executable integration candidate, but
**not a reviewed root-owned attestation of the provenance or physical
bootability of the final installer**; Docker-daemon/root tampering and
end-to-end Seagate ESP/Btrfs installation have not been excluded.
The current source candidate has switched all verify/copy/install subprocesses
to the pinned standalone OCI image and refuses missing/malformed private
source attestations or review receipts. Real execution of its own
`verify_source_store()` and `verify_install_namespace()` succeeded in
Grabowski task `bcfdc076144849888d016c68`, Exit 0.
Its actual `copy_source_closure_to_target()` and `run_container(...,
"--no-bootloader")` generated commands were executed against a fresh,
safely labeled synthetic Docker target volume
`heim-pc-stage0-oci-pr238-integration-20261022-v1` (instead of the
physical host NIX_ROOT bind), task `00ff729ebc934f819e7cfb1b`, Exit 0,
with independent readonly /etc/NIXOS, system-store and profile postchecks.
After adding independent NAR pins and recursive *target-store* content
verification, a **fresh** second disposable source-to-target OCI workflow
ran under Grabowski task `b7292f816ad0453d8f729aff`, exit 0:
recursive source verify + exact NAR metadata, mount-namespace preflight,
real Nix copy, recursive target integrity verification, official
`nixos-install --no-bootloader`, read-only postconditions.
The script SHA remained `d7f8f314ae9c56265c7cdcffc7075467f58908de8cca7f7029b61d97a80dee80`
throughout that entire operation; volume
`heim-pc-stage0-oci-pr238-nar-20261022-v2` was specifically created
under label `heim-pc.stage0=oci-pr238-nar-scratch-20261022-v2`.
A **real negative target-content mutation** was then performed on
exactly that still-labeled, idle, isolated v2 Docker scratch volume,
never on any host NVMe or the sealed image. A synthetic extra file
was inserted under the target NixOS system Store directory; the actual
target `nix store verify --no-trust --recursive` returned **exit 1**
as required. Grabowski task `32b8ea58447c49b6b46e5769`,
`STAGE0_CORRUPTED_TARGET_REAL_VERIFY_FAIL_CLOSED`. The scratch target
is hence deliberately invalid for later boot tests.

This is **not** a full root-mounted Btrfs/ESP installer with bootloader
or a physical boot. Do not equate any scratch receipt or unsigned local
NAR self-check with independent source authorization.
The Python suite on the then-current dirty source tested 2183 passing,
1 skipped, 465 subtests and NixOS-source tests 52 passing; new source
changes require fresh tests before publishing.
The host has no approved root-owned release seal;
physical Apply remains forbidden. Do not mint an attestation merely to
make the code run or treat candidate-image smoke tests as hardware approval.

## Deferred NixOS module-bound review items

The independent review recommends `usbhid`/`hid_generic` in the
initrd and stronger Nix assertions on all Btrfs subvolumes and passwordlessness.
Nixer's live NixOS effective-option evaluation on 2026-10-22 confirmed
**both `usbhid` and `hid_generic` already present**; no new HID source
modification is needed. Additional assertions would change
`nixos/system/` and require a **new, pinned, realized Stage0 system
closure, revised BUILD_REV and refreshed provenance**: the old closure
cannot truthfully be reused. Do not silently modify the module while
claiming the former built source is unchanged. These items remain
tracked pre-hardware-review work. The synthetic Btrfs/ESP installed-target VM
has since booted and authenticated a disposable test user (see below);
the real rootbroker TTY and physical Seagate/WD return paths remain blocked.

## Additional VM integration: synthetic GPT/Btrfs/UEFI boot and login

The previous `vmWithBootLoader` test used ext4. A **different real
virtual installation** now tests an 8-GiB QEMU disk with a separate
FAT32 ESP, ext4 recovery partition and Btrfs root with `@root`,
`@nix`, `@home`, `@persist`. The official NixOS `nixos-install`
installed the EFI fallback and loader entries, followed by a cold
OVMF/systemd-boot start from the same virtual disk.

- Verified standalone R3 test: Grabowski task `0af8953ec34b4916aa4ad721`,
  exit 0, outcome receipt
  `e1d6cae5b9159a605248977613b1583dde307071147563b63826472f3c54bb0e`.
  Source `/home/alex/labs/heim-pc-stage0-btrfs-install-test-20261022/stage0-btrfs-install-test-r3.nix`,
  SHA-256 `1a9fc803e38d4a99336f2b219971f4e1095b97765ab8c5710e20676e41c12162`.
  The actual installed target reached visible VGA `heim-pc-stage0 login:`
  (separately verified R3 report SHA
  `28dc572691a8e720229d1cf98e7242385734f8379069a89fb760ee9602b1bd09`).
- Additional reproducible test `tests/stage0-gpt-btrfs-efi-login-vm.nix`
  (source SHA-256 `5bbcf0000842f6524689884c032f617ae911e0a696176bef6a3699e820aa3374`)
  used **exclusively synthetic, disposable VM password data** after official
  installation; no real password is embedded. It sent `alex` and the
  matching test password through QEMU's VGA keyboard, then `sudo poweroff`
  and the sudo password. The NixOS test demanded a subsequent **QMP SHUTDOWN
  event and a completed guest shutdown** (not an SSH-backdoor assertion).
  Real successful run: Grabowski task `ac6e929f3c6a495d89e73293`,
  systemd exit 0 and receipt
  `d8ec714050b24588735cb825836a39d0b66bd7e8e79c5838e699de84c7d04136`;
  local built Nix test `/nix/store/qy0xqm93z8dry9s6nmlnbyxrhmw8431x-vm-test-run-stage0-fake-seagate-gpt-btrfs-uefi-login-r4`.
  Its separately read Nix derivation log contains
  `STAGE0_VIRTUAL_GPT_BTRFS_UEFI_REAL_USER_SUDO_POWEROFF_OK` (reader task
  `61347f401e8f4230b55bf8c4`, exit 0).
- A separate R5 synthetic experiment ran the actual Stage0
  `credential_bootstrap()` against VM `/mnt/etc/shadow` and reached VGA
  screenshot capture using test credentials, task
  `e87042e451af4a71a6edb5e7`, exit 0. R5 did **not** assert login
  and is independent of R4's test-only shadow injection; do not combine
  those into a single end-to-end hardware-credential claim.

**Limits:** VM-specific VirtIO modules and simulated disk/firmware are not
the built physical Seagate closure or the ASUS firmware. Neither
`scripts/nixos_stage0_install.py --apply` nor the host Rootbroker's
private TTY flow was exercised. This synthetic login is not a
successful physical NixOS login, permission to destroy p3, a
Pop!_OS boot/rollback receipt, or an independent OCI trust-source approval.
Physical `--apply` remains forbidden.

## Independent boot and rollback proof for Thread 2

Prior inspection showed Boot0002 UEFI OS points to external Freecom,
NOT Seagate. An independent Seagate ESP must be selectable via a real
firmware boot menu (or verified NVRAM-free fallback), without rewriting
the Pop!_OS/WD ESP. A prepared ESP alone is not a successful boot.

After authorized hardware Apply, capture genuine evidence:
- Boot heim-pc-stage0 from Seagate, confirm findmnt / is btrfs with
  subvol=@root on Seagate p3 and findmnt /boot points to Seagate p1.
- Console login for alex succeeds with private password; sudo prompts;
  NetworkManager starts; SSH/autologin remain disabled.
- /nix, /home and /persist mount from the Stage0 subvolumes.
- Reboot separately into WD Pop!_OS via firmware disk selection;
  verify Pop!_OS root/ESP on the protected WD and its GPT/ESP unchanged.
- Report exact source HEAD, closure, observed PARTUUIDs privately,
  boot/rollback receipts and any failure on Issue #237.

Physical installation and boot have NOT occurred in this development
thread. Production LUKS/TPM2/Secure Boot, data migration and Day-1
parity remain separate work and are not needed for this isolated test.