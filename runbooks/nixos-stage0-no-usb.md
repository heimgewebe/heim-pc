# USB-free NixOS Stage0 on the internal Seagate (NONPRODUCTION)

Source and PR authority: heimgewebe/heim-pc PR #238.
Hardware-executor handoff and results: heimgewebe/heim-pc Issue #237.
This document and development-thread tests DO NOT authorize physical apply.

## Immutable source and realized artifacts

- Stage0 profile: nixosConfigurations.heim-pc-stage0
- Built source commit: e68efce49eaba0014865fd1c4e0b62f692f016af
- Built system: /nix/store/9imhrwyy6bf5fkhqrjfx6dqn4rva8y67-nixos-system-heim-pc-stage0-26.05.20260829.c5c4a43
- Docker Nix image: sha256:98edc6813218e179ce84587373e0b52d4aa58babae2d26b51fb01e7fdacf815f
- Nix volume: heim-pc-nixos-stage0-e68efce49eab
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
  (only) Btrfs label NIXOS_STAGE0_ROOT, with no force flag
- No USB media is needed. External Freecom and Game Drive are not targets.

The operator must freshly prove private whole-NVMe /dev/disk/by-id/nvme-*
aliases, partition aliases -part1 and -part3, model, size, GPT type and
PARTUUIDs, read-only wipefs signatures, kernel holders, all mounts, unique
filesystem labels, and both protected WD root/ESP mounts. Never infer
hardware identity from nvme0n1/nvme1n1. Plan and Apply fail closed on
hardware drift, previously occupied root label or ESP loader conflict.

## No-effect plan (hardware executor only, root-owned 0600)

The command below has placeholders; no fabricated serial/by-id path may be
used. Source checkout must be the exact clean reviewed/committed PR #238
revision and the built store evidence must be present.

    sudo python3 scripts/nixos_stage0_install.py --plan \
      --seagate-by-id /dev/disk/by-id/nvme-EXACT-SEAGATE-ID \
      --wd-by-id /dev/disk/by-id/nvme-EXACT-PROTECTED-WD-ID \
      --plan-file /root/nixos-stage0-plan.json

The plan is create-only, private mode 0600, and records source/script/store
identity, precise live Seagate/WD observations, fingerprints of WD GPT,
entire WD ESP contents, Seagate GPT, and EFI boot listing. Output prints
the SHA256 of the plan, not its private contents. Planning creates no GPT,
filesystem, mount, NVRAM or boot effects.

## Apply remains subject to new hardware authority and independent review

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
mandatory. Source store integrity must pass a fresh recursive verification
before any physical disk mutation. Existing Pop!_OS and EFI variables are
outside mutation scope. Before changing GPT, Apply now probes all host
storage tools (including btrfs, mkfs.btrfs, sgdisk) and runs the pinned
NixOS chroot mount-namespace preflight in a Docker container without
host-device binds or networking. This addresses the previously observed
missing-host-btrfs-tools and Docker default-AppArmor denial.

Expected guarded sequence, not yet a physical install receipt:

1. Recheck source/target and existing Seagate EFI loader absence.
2. Change the Linux-LUKS historical GPT type of ONLY Seagate p3 to
   Linux filesystem; rename its partition label NIXOS_STAGE0_ROOT.
   Verify all three Seagate PARTUUIDs remain unchanged and the protected
   WD/EFI invariants remain unchanged.
3. Recheck no hidden p3 signatures, mkfs.btrfs without -f on by-id p3.
4. Create Btrfs subvolumes @root, @nix, @home, @persist. Mount
   target /, /nix, /home, /persist and the existing Seagate p1 on /boot.
5. First populate the fresh target Nix store from the source-bound built
   system closure via official Nix copy --to local?root=/mnt. Offline copy
   requires source Nix DB temporarily writable and --no-check-sigs for
   locally built unsigned paths (the source is verified before writing
   GPT; no network or SYS_ADMIN during the copy). This exact
   no-bootloader Nix-store transfer plus nixos-install was exercised on
   isolated Docker volumes and completed successfully.
6. Run source-bound official nixos-install in the pinned offline Docker
   image with SOURCE Nix volume READONLY and target mount writable:
   --root /mnt --system BUILT-SYSTEM --no-root-passwd --no-channel-copy.
   Verified chroot use requires Docker SYS_ADMIN, seccomp=unconfined and
   apparmor=unconfined; this is a security-sensitive installation container
   with no network or raw host-disk device mounts. The NixOS profile has
   boot.loader.efi.canTouchEfiVariables=false.
7. Verify Seagate own EFI/BOOT/BOOTX64.EFI and generated loader entries,
   installed shadow, and NixOS 26.05's evaluated kernel parameter
   root=fstab (the root's Btrfs label is resolved through NixOS initrd
   filesystems, not expected literally in the EFI entry). Ask interactively for a
   new 16+ character password for alex, hash it only into the installed
   /etc/shadow; no secret in Git, store, argv or logs. Refuse an existing
   alex password; root remains locked. Validate WD GPT/ESP and EFI
   boot entry fingerprints before/after. Unmount every target in reverse
   order; cleanup errors require manual recovery.
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

The currently audited root broker cannot access the source checkout
under /home/alex or a developer interactive TTY. This exact source
driver therefore CANNOT be considered directly executable through
that broker. Do not bypass sudo, the broker, source seals, hardware
permission or protected WD boot verification to work around it.
Root-authorized staging/credential input and a true isolated
bootloader test are required before physical Apply. Pop!_OS's
current initrd changed and was regenerated after a package trigger;
a complete physical Pop!_OS boot has not yet been proven. Preserve
the updated WD ESP/boot preimage and do not assert that WD files were
byte-unchanged from the older pre-package baseline.

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