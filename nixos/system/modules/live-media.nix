{
  config,
  lib,
  pkgs,
  heimPcSourceRevision ? "prototype-unbound",
  heimPcLiveProfile ? {
    nvidiaOpen = false;
    edition = "proprietary";
    inventoryMode = false;
  },
  ...
}:
let
  liveUser = "alex";
  edition = heimPcLiveProfile.edition;
  inventoryMode = heimPcLiveProfile.inventoryMode or false;
  inventoryPayload = pkgs.runCommand "heim-pc-offline-inventory-payload" { } ''
    install -Dm0444 ${../../../scripts/nixos_production_identity.py} "$out/scripts/nixos_production_identity.py"
    install -Dm0444 ${../../../scripts/nixos_critical_user_data_inventory.py} "$out/scripts/nixos_critical_user_data_inventory.py"
    install -Dm0444 ${../../../scripts/nixos_critical_data_inventory.py} "$out/scripts/nixos_critical_data_inventory.py"
    install -Dm0444 ${../../production/contract-v1.json} "$out/nixos/production/contract-v1.json"
    install -Dm0444 ${../../production/critical-user-data-contract-v1.json} "$out/nixos/production/critical-user-data-contract-v1.json"
    install -Dm0444 ${../../production/critical-user-home-data-contract-v1.json} "$out/nixos/production/critical-user-home-data-contract-v1.json"
  '';
  offlineInventory = pkgs.writeShellApplication {
    name = "heim-pc-offline-critical-user-data-inventory";
    runtimeInputs = with pkgs; [
      coreutils
      python3
      util-linux
    ];
    text = ''
      exec ${pkgs.python3}/bin/python \
        ${../../../scripts/nixos_critical_user_data_offline_inventory.py} \
        --payload-root ${inventoryPayload} \
        --expected-source-revision ${lib.escapeShellArg heimPcSourceRevision} \
        --apply
    '';
  };
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
        # $1 is intentionally expanded by the inner shell, not this outer script.
        # shellcheck disable=SC2016
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
    {
      assertion = !inventoryMode || !config.networking.networkmanager.enable;
      message = "offline inventory live media must keep NetworkManager disabled";
    }
    {
      assertion = !inventoryMode || !config.networking.useDHCP;
      message = "offline inventory live media must keep DHCP disabled";
    }
    {
      assertion = !inventoryMode || !config.security.polkit.enable;
      message = "offline inventory live media must not expose Polkit";
    }
    {
      assertion = !inventoryMode || !config.services.displayManager.autoLogin.enable;
      message = "offline inventory live media must not auto-login a user";
    }
    {
      assertion = !inventoryMode || !config.heimPc.desktop.enable;
      message = "offline inventory live media must remain headless";
    }
    {
      assertion = !inventoryMode || !config.heimPc.hardware.nvidia.enable;
      message = "offline inventory live media must not load the NVIDIA desktop stack";
    }
    {
      assertion = !inventoryMode || !config.heimPc.physicalGates.enable;
      message = "offline inventory live media must not expose physical test gates";
    }
  ];

  nixpkgs.config.allowUnfree = true;

  networking = {
    hostName = if inventoryMode then "heim-pc-inventory-live" else "heim-pc-gate-live-${edition}";
    networkmanager.enable = !inventoryMode;
    useDHCP = lib.mkIf inventoryMode false;
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
    edition = if inventoryMode then "heim-inventory" else "heim-gate-${edition}";
    volumeID =
      if inventoryMode then "HEIMPC_INVENTORY"
      else if edition == "open" then "NIXOS-HEIM-GATE-OPEN"
      else "NIXOS-HEIM-GATE-PROP";
    appendToMenuLabel =
      if inventoryMode then " Heim-PC Offline Inventory"
      else " Heim-PC Gate A/B Live";
    configurationName =
      if inventoryMode then "Offline Critical-User-Data Inventory"
      else if edition == "open" then "Open NVIDIA"
      else "Proprietary NVIDIA";
    squashfsCompression = "zstd -Xcompression-level 6";
  };

  system.nixos.variant_id =
    if inventoryMode then "heim-pc-offline-inventory-live"
    else "heim-pc-gate-live";
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
    extraGroups = lib.optionals (!inventoryMode) [
      "audio"
      "video"
      "networkmanager"
    ];
  };

  security.sudo.enable = lib.mkForce false;
  security.polkit.enable = !inventoryMode;

  services = {
    openssh.enable = lib.mkForce false;
    udisks2.enable = lib.mkForce false;
    displayManager.autoLogin = {
      enable = !inventoryMode;
      user = liveUser;
    };
  };

  # Build proof helpers independently without realizing the full ISO.
  system.build.heimPcLiveSafety = liveSafety;
  system.build.heimPcOfflineCriticalUserDataInventory = offlineInventory;

  systemd.services.heim-pc-live-safety = {
    description =
      if inventoryMode
      then "Fail closed before Heim-PC offline inventory"
      else "Fail closed before Heim-PC physical Gate A/B desktop";
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
  systemd.services.display-manager = lib.mkIf (!inventoryMode) {
    requires = [ "heim-pc-live-safety.service" ];
    after = [ "heim-pc-live-safety.service" ];
  };

  systemd.services.heim-pc-offline-critical-user-data-inventory = lib.mkIf inventoryMode {
    description = "One-shot offline authoritative Heim-PC critical-user-data inventory";
    wantedBy = [ "multi-user.target" ];
    requires = [ "heim-pc-live-safety.service" ];
    wants = [ "systemd-udev-settle.service" ];
    after = [
      "heim-pc-live-safety.service"
      "systemd-udev-settle.service"
    ];
    unitConfig.ConditionPathExists = "/dev/disk/by-label/HEIMPC_EVIDENCE";
    serviceConfig = {
      Type = "oneshot";
      ExecStart = lib.getExe offlineInventory;
      RemainAfterExit = true;
      Restart = "no";
      User = "root";
      Group = "root";
      UMask = "0077";
      RuntimeDirectory = [
        "heim-pc-offline-inventory"
        "heim-pc-recovery-evidence"
      ];
      RuntimeDirectoryMode = "0700";
      RuntimeDirectoryPreserve = "yes";
      TimeoutStartSec = "6h";
      RuntimeMaxSec = "6h";
      Environment = "PYTHONDONTWRITEBYTECODE=1";
      PrivateNetwork = true;
      PrivateMounts = true;
      PrivateDevices = false;
      PrivateTmp = true;
      NoNewPrivileges = true;
      ProtectSystem = "strict";
      ProtectHome = false;
      ProtectKernelTunables = true;
      ProtectKernelModules = true;
      ProtectKernelLogs = true;
      ProtectControlGroups = true;
      ProtectHostname = true;
      ProtectClock = true;
      RestrictSUIDSGID = true;
      RestrictRealtime = true;
      LockPersonality = true;
      MemoryDenyWriteExecute = true;
      CapabilityBoundingSet = [
        "CAP_SYS_ADMIN"
        "CAP_DAC_OVERRIDE"
        "CAP_DAC_READ_SEARCH"
      ];
      ReadWritePaths = [
        "/run/heim-pc-offline-inventory"
        "/run/heim-pc-recovery-evidence"
      ];
      StandardOutput = "journal+console";
      StandardError = "journal+console";
    };
  };

  powerManagement.enable = true;

  heimPc = {
    desktop.enable = !inventoryMode;
    hardware.nvidia = {
      enable = !inventoryMode;
      openKernelModule = heimPcLiveProfile.nvidiaOpen;
    };
    physicalGates = {
      enable = !inventoryMode;
      bootReadiness = false;
      modelRuntime = false;
    };
  };

  environment.systemPackages =
    [ liveSafety ]
    ++ lib.optionals (!inventoryMode) (with pkgs; [
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
    ]);
}
