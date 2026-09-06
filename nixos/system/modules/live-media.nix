{
  config,
  lib,
  pkgs,
  heimPcLiveProfile ? {
    nvidiaOpen = false;
    edition = "proprietary";
  },
  ...
}:
let
  liveUser = "alex";
  edition = heimPcLiveProfile.edition;
  liveSafety = pkgs.writeShellApplication {
    name = "heim-pc-live-safety";
    runtimeInputs = with pkgs; [
      coreutils
      gnugrep
      jq
      shadow
      systemd
      util-linux
    ];
    text = ''
      set -u
      failed=0
      pass() { printf 'PASS %s\n' "$1"; }
      fail() { printf 'FAIL %s\n' "$1" >&2; failed=1; }

      root_type="$(findmnt -rn -o FSTYPE / 2>/dev/null || true)"
      if [ "$root_type" = "tmpfs" ]; then
        pass "tmpfs-root"
      else
        printf 'root fstype=%s\n' "$root_type" >&2
        fail "tmpfs-root"
      fi

      # Physical Gate A/B is intentionally copy-to-RAM. This removes the USB
      # medium itself from the persistent block-device path before tests begin.
      iso_type="$(findmnt -rn -o FSTYPE /iso 2>/dev/null || true)"
      if [ "$iso_type" = "tmpfs" ]; then
        pass "copytoram-live-media"
      else
        printf '/iso fstype=%s (expected tmpfs after copytoram)\n' "$iso_type" >&2
        fail "copytoram-live-media"
      fi

      # All three probes and their JSON schemas must succeed before an empty
      # device list can count as safe. The loop exception is bound to the pinned
      # ISO module's RAM-backed /iso/nix-store.squashfs, not a name prefix.
      mount_inventory="$(findmnt --json --list -o TARGET,SOURCE,FSTYPE,OPTIONS,MAJ:MIN)" || {
        fail "persistent-disk-mount-inventory"; exit 1;
      }
      block_inventory="$(lsblk --json --list --paths -o PATH,TYPE,MAJ:MIN)" || {
        fail "raw-block-device-inventory"; exit 1;
      }
      loop_inventory="$(losetup --json --list -o NAME,BACK-FILE)" || {
        fail "loop-backing-inventory"; exit 1;
      }
      checked_devices="$(
        printf '%s\n' "$mount_inventory" "$block_inventory" "$loop_inventory" |
          jq --compact-output --exit-status --slurp --from-file ${./live-block-inventory.jq}
      )" || { fail "persistent-disk-mount-inventory"; exit 1; }
      raw_devices="$(printf '%s\n' "$checked_devices" | jq -r '.[]')" || {
        fail "raw-block-device-inventory"; exit 1;
      }
      pass "persistent-disk-mount-inventory"
      pass "no-persistent-disk-mounts"

      groups="$(id -nG ${liveUser})" || {
        fail "live-user-identity"; exit 1;
      }
      if [ -z "$groups" ] || printf '%s\n' "$groups" | tr ' ' '\n' | grep -Eq '^(wheel|disk)$'; then
        fail "live-user-not-privileged-storage-admin"
      else
        pass "live-user-not-privileged-storage-admin"
      fi
      # A failed privilege drop is an observation failure, never a denial proof.
      runuser -u ${liveUser} -- true || { fail "live-user-probe"; exit 1; }
      raw_access=0
      while IFS= read -r device; do
        [ -n "$device" ] || continue
        if [ ! -b "$device" ]; then
          fail "block-device-disappeared"; raw_access=1; continue
        fi
        if ! runuser -u ${liveUser} -- ${pkgs.runtimeShell} -c \
          'if test -r "$1" || test -w "$1"; then exit 42; fi' live-block-probe "$device"; then
          printf 'raw block access or failed user probe: %s\n' "$device" >&2
          raw_access=1
        fi
      done <<< "$raw_devices"
      if [ "$raw_access" -eq 0 ]; then
        pass "raw-block-devices-inaccessible-to-live-user"
      else
        fail "raw-block-devices-inaccessible-to-live-user"
      fi

      # Keep the boot-safety path limited to its declared runtime inputs. Avoid
      # incidental awk/sed dependencies that are absent from the live closure.
      root_status=""
      IFS=' ' read -r _root_name root_status _root_rest < <(passwd -S root 2>/dev/null || true) || true
      if [ "$root_status" = "L" ]; then
        pass "root-password-locked"
      else
        printf 'root password status=%s\n' "$root_status" >&2
        fail "root-password-locked"
      fi

      if [ -x /run/current-system/sw/bin/sudo ]; then
        fail "sudo-absent"
      else
        pass "sudo-absent"
      fi

      if systemctl is-active --quiet udisks2.service 2>/dev/null; then
        fail "udisks2-inactive"
      else
        pass "udisks2-inactive"
      fi

      if [ "$failed" -ne 0 ]; then
        printf 'HEIM_PC_LIVE_SAFETY_FAIL\n' >&2
        exit 1
      fi
      printf 'HEIM_PC_LIVE_SAFETY_PASS\n'
    '';
  };
in
{
  assertions = [
    {
      assertion = !config.security.sudo.enable;
      message = "physical gate live media must not enable sudo";
    }
    {
      assertion = !config.services.udisks2.enable;
      message = "physical gate live media must not expose UDisks disk-mutation surface";
    }
    {
      assertion = !config.services.openssh.enable;
      message = "physical gate live media must not expose SSH";
    }
    {
      assertion = !(lib.elem "wheel" config.users.users.${liveUser}.extraGroups);
      message = "physical gate live user must remain outside wheel";
    }
    {
      assertion = !(lib.elem "disk" config.users.users.${liveUser}.extraGroups);
      message = "physical gate live user must remain outside disk group";
    }
    {
      assertion = config.boot.loader.efi.canTouchEfiVariables == false;
      message = "physical gate live media must not mutate firmware boot variables";
    }
    {
      assertion = lib.elem "copytoram" config.boot.kernelParams;
      message = "physical gate live media must copy itself to RAM before hardware testing";
    }
    {
      assertion = !config.heimPc.physicalGates.bootReadiness;
      message = "physical gate live media must not expose Gate D against its tmpfs root";
    }
    {
      assertion = !config.heimPc.physicalGates.modelRuntime;
      message = "physical gate live media must keep Ollama/llama CUDA out of the copytoram image";
    }
  ];

  nixpkgs.config.allowUnfree = true;

  networking = {
    hostName = "heim-pc-gate-live-${edition}";
    networkmanager.enable = true;
    firewall.enable = true;
  };

  hardware.enableAllHardware = true;
  boot.initrd.systemd.enable = true;
  boot.kernelParams = [ "copytoram" ];
  boot.loader.efi.canTouchEfiVariables = false;

  isoImage = {
    makeBiosBootable = true;
    makeEfiBootable = true;
    makeUsbBootable = true;
    edition = "heim-gate-${edition}";
    volumeID = if edition == "open" then "NIXOS-HEIM-GATE-OPEN" else "NIXOS-HEIM-GATE-PROP";
    appendToMenuLabel = " Heim-PC Gate A/B Live";
    configurationName = if edition == "open" then "Open NVIDIA" else "Proprietary NVIDIA";
    squashfsCompression = "zstd -Xcompression-level 6";
  };

  system.nixos.variant_id = "heim-pc-gate-live";
  system.stateVersion = "26.05";

  # This intentionally acknowledges NixOS' lockout assertion. The live system
  # has no administrative password or wheel user by design; SDDM autologin is
  # only for the unprivileged hardware-test user below. NetworkManager control
  # is allowed so the live user can reach test resources without gaining disk
  # or administrative privileges.
  users.allowNoPasswordLogin = true;
  users.mutableUsers = false;
  users.users.root.hashedPassword = "!";
  users.users.${liveUser} = {
    isNormalUser = true;
    hashedPassword = "!";
    extraGroups = [
      "audio"
      "video"
      "networkmanager"
    ];
  };

  security.sudo.enable = lib.mkForce false;
  security.polkit.enable = true;

  services = {
    openssh.enable = lib.mkForce false;
    udisks2.enable = lib.mkForce false;
    displayManager.autoLogin = {
      enable = true;
      user = liveUser;
    };
  };

  # Build the safety script independently without realizing the full ISO.
  system.build.heimPcLiveSafety = liveSafety;

  systemd.services.heim-pc-live-safety = {
    description = "Fail closed before Heim-PC physical Gate A/B desktop";
    wantedBy = [ "multi-user.target" ];
    before = [ "display-manager.service" ];
    after = [
      "local-fs.target"
      "systemd-user-sessions.service"
    ];
    serviceConfig = {
      Type = "oneshot";
      ExecStart = lib.getExe liveSafety;
      RemainAfterExit = true;
      StandardOutput = "journal+console";
      StandardError = "journal+console";
    };
  };

  # The graphical test surface must not become available when the storage and
  # privilege preflight failed.
  systemd.services.display-manager = {
    requires = [ "heim-pc-live-safety.service" ];
    after = [ "heim-pc-live-safety.service" ];
  };

  powerManagement.enable = true;

  heimPc = {
    desktop.enable = true;
    hardware.nvidia = {
      enable = true;
      openKernelModule = heimPcLiveProfile.nvidiaOpen;
    };
    physicalGates = {
      enable = true;
      bootReadiness = false;
      modelRuntime = false;
    };
  };

  environment.systemPackages = with pkgs; [
    liveSafety
    firefox
    usbutils
    pciutils
    vulkan-tools
    alsa-utils
    pipewire
    wireplumber
    jack2
    jq
    curl
  ];
}
