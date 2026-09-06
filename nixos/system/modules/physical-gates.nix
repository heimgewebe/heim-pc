{ config, lib, pkgs, ... }:
let
  cfg = config.heimPc.physicalGates;
  llamaCuda = pkgs.llama-cpp.override { cudaSupport = true; };
  nvidiaSmi = lib.getExe' config.hardware.nvidia.package "nvidia-smi";

  gateARuntimeInputs = (with pkgs; [
    coreutils
    gnugrep
    jq
    curl
    pciutils
    vulkan-tools
    mesa-demos
    systemd
    ollama-cuda
  ]) ++ [ llamaCuda ];

  gateBRuntimeInputs = with pkgs; [
    coreutils
    gnugrep
    usbutils
    alsa-utils
    pipewire
    wireplumber
    jack2
  ];

  gateDRuntimeInputs = with pkgs; [
    coreutils
    gnugrep
    util-linux
    cryptsetup
    mokutil
  ];

  gateAReport = pkgs.writeShellApplication {
    name = "heim-pc-gate-a-readiness";
    runtimeInputs = gateARuntimeInputs;
    text = ''
      set -u
      failed=0
      pass() { printf 'PASS %s\n' "$1"; }
      fail() { printf 'FAIL %s\n' "$1" >&2; failed=1; }
      defer() { printf 'DEFER %s\n' "$1"; }

      printf 'GATE A — NVIDIA/CUDA/DESKTOP READINESS\n'

      gpu_info="$(${nvidiaSmi} --query-gpu=name,driver_version,memory.total --format=csv,noheader 2>&1)" || {
        printf '%s\n' "$gpu_info" >&2
        fail "nvidia-smi"
        gpu_info=""
      }
      if printf '%s\n' "$gpu_info" | grep -Fq 'RTX 4070 Ti SUPER'; then
        pass "rtx-4070-ti-super-visible"
      else
        printf '%s\n' "$gpu_info" >&2
        fail "expected-gpu-model"
      fi

      session_type="''${XDG_SESSION_TYPE:-}"
      active_wayland_session=""
      if [ "$session_type" != "wayland" ]; then
        while read -r session_id _rest; do
          [ -n "$session_id" ] || continue
          observed_type="$(loginctl show-session "$session_id" --property=Type --value 2>/dev/null || true)"
          observed_active="$(loginctl show-session "$session_id" --property=Active --value 2>/dev/null || true)"
          if [ "$observed_type" = "wayland" ] && [ "$observed_active" = "yes" ]; then
            active_wayland_session="$session_id"
            break
          fi
        done <<EOF
$(loginctl list-sessions --no-legend --no-pager 2>/dev/null || true)
EOF
      fi
      if [ "$session_type" = "wayland" ] || [ -n "$active_wayland_session" ]; then
        pass "wayland-session"
      else
        printf 'observed XDG_SESSION_TYPE=%s and no active logind Wayland session\n' "$session_type" >&2
        fail "wayland-session"
      fi

      vulkan_summary="$(vulkaninfo --summary 2>&1)" || {
        printf '%s\n' "$vulkan_summary" >&2
        fail "vulkaninfo"
        vulkan_summary=""
      }
      if printf '%s\n' "$vulkan_summary" | grep -Eiq 'NVIDIA|4070 Ti SUPER'; then
        pass "vulkan-nvidia"
      else
        fail "vulkan-nvidia"
      fi

      if systemctl is-active --quiet nvidia-container-toolkit-cdi-generator.service; then
        pass "nvidia-cdi-generator-service"
      else
        fail "nvidia-cdi-generator-service"
      fi
      cdi_json=""
      for candidate in /run/cdi/nvidia-container-toolkit.json /etc/cdi/nvidia-container-toolkit.json; do
        if [ -r "$candidate" ]; then
          cdi_json="$candidate"
          break
        fi
      done
      if [ -n "$cdi_json" ] && jq -e '.devices[]?.name == "all"' "$cdi_json" >/dev/null; then
        pass "nvidia-cdi-all-device"
      else
        fail "nvidia-cdi-all-device"
      fi

      if systemctl is-active --quiet ollama.service; then
        pass "ollama-service"
      else
        fail "ollama-service"
      fi
      if curl --fail --silent --show-error --max-time 3 http://127.0.0.1:11434/api/version >/dev/null; then
        pass "ollama-loopback-api"
      else
        fail "ollama-loopback-api"
      fi

      if llama-server --version >/dev/null 2>&1; then
        pass "llama-cpp-cuda-binary"
      else
        fail "llama-cpp-cuda-binary"
      fi

      defer "local-model-gpu-inference"
      defer "gpu-container-runtime-smoke-with-cached-image"
      defer "repeated-suspend-resume"
      defer "browser-video-webgl"
      defer "generation-rollback-after-driver-change"

      if [ "$failed" -ne 0 ]; then
        printf 'GATE_A_READINESS_FAIL\n' >&2
        exit 1
      fi
      printf 'GATE_A_READINESS_PASS\n'
    '';
  };

  gateBReport = pkgs.writeShellApplication {
    name = "heim-pc-gate-b-readiness";
    runtimeInputs = gateBRuntimeInputs;
    text = ''
      set -u
      failed=0
      pass() { printf 'PASS %s\n' "$1"; }
      fail() { printf 'FAIL %s\n' "$1" >&2; failed=1; }
      defer() { printf 'DEFER %s\n' "$1"; }

      printf 'GATE B — MOTU/PIPEWIRE/JACK/MIDI READINESS\n'

      wp="$(wpctl status 2>&1)" || {
        printf '%s\n' "$wp" >&2
        fail "pipewire-wpctl"
        wp=""
      }
      if [ -n "$wp" ]; then
        pass "pipewire-wpctl"
      fi
      if printf '%s\n' "$wp" | grep -Eiq 'MOTU|M Series|(^|[^[:alnum:]])M2([^[:alnum:]]|$)'; then
        pass "motu-m2-pipewire"
      else
        printf '%s\n' "$wp" >&2
        fail "motu-m2-pipewire"
      fi

      playback="$(aplay -l 2>&1)" || playback=""
      if printf '%s\n' "$playback" | grep -Eiq 'MOTU|(^|[^[:alnum:]])M2([^[:alnum:]]|$)'; then
        pass "motu-m2-alsa-playback"
      else
        printf '%s\n' "$playback" >&2
        fail "motu-m2-alsa-playback"
      fi

      capture="$(arecord -l 2>&1)" || capture=""
      if printf '%s\n' "$capture" | grep -Eiq 'MOTU|(^|[^[:alnum:]])M2([^[:alnum:]]|$)'; then
        pass "motu-m2-alsa-capture"
      else
        printf '%s\n' "$capture" >&2
        fail "motu-m2-alsa-capture"
      fi

      midi="$(aconnect -l 2>&1)" || midi=""
      if printf '%s\n' "$midi" | grep -Eiq 'FP-30X|Roland Digital Piano'; then
        pass "roland-fp-30x-midi"
      else
        printf '%s\n' "$midi" >&2
        fail "roland-fp-30x-midi"
      fi

      jack_ports="$(pw-jack jack_lsp 2>&1)" || {
        printf '%s\n' "$jack_ports" >&2
        fail "pipewire-jack"
        jack_ports=""
      }
      if [ -n "$jack_ports" ]; then pass "pipewire-jack"; fi

      defer "browser-capture-playback"
      defer "realistic-load-xrun-and-latency-measurement"
      defer "repeated-suspend-resume"
      defer "existing-audio-tooling-workflow"

      if [ "$failed" -ne 0 ]; then
        printf 'GATE_B_READINESS_FAIL\n' >&2
        exit 1
      fi
      printf 'GATE_B_READINESS_PASS\n'
    '';
  };

  gateDReport = pkgs.writeShellApplication {
    name = "heim-pc-gate-d-boot-readiness";
    runtimeInputs = gateDRuntimeInputs;
    text = ''
      set -u
      failed=0
      pass() { printf 'PASS %s\n' "$1"; }
      fail() { printf 'FAIL %s\n' "$1" >&2; failed=1; }
      defer() { printf 'DEFER %s\n' "$1"; }

      printf 'GATE D — PHYSICAL BOOT/ENCRYPTION READINESS\n'

      if [ -d /sys/firmware/efi ]; then
        pass "uefi-runtime"
      else
        fail "uefi-runtime"
      fi

      sb="$(mokutil --sb-state 2>&1)" || sb=""
      if printf '%s\n' "$sb" | grep -Eiq 'SecureBoot enabled|Secure Boot enabled'; then
        pass "secure-boot-enabled"
      else
        printf '%s\n' "$sb" >&2
        fail "secure-boot-enabled"
      fi

      root_source="$(findmnt -rn -o SOURCE / 2>/dev/null || true)"
      case "$root_source" in
        /dev/mapper/*)
          pass "encrypted-root-mapper"
          mapper="''${root_source#/dev/mapper/}"
          if cryptsetup status "$mapper" >/dev/null 2>&1; then
            pass "cryptsetup-root-active"
          else
            fail "cryptsetup-root-active"
          fi
          ;;
        *)
          printf 'root source=%s\n' "$root_source" >&2
          fail "encrypted-root-mapper"
          ;;
      esac

      defer "manual-recovery-key-from-independent-copy"
      defer "independent-recovery-boot"
      defer "tampered-signed-artifact-rejection-and-rollback"
      defer "firmware-update-survival"
      defer "blank-physical-replacement-disk-reconstruction"

      if [ "$failed" -ne 0 ]; then
        printf 'GATE_D_BOOT_READINESS_FAIL\n' >&2
        exit 1
      fi
      printf 'GATE_D_BOOT_READINESS_PASS\n'
    '';
  };
in
{
  options.heimPc.physicalGates.enable = lib.mkEnableOption "read-only physical NixOS vNext acceptance tooling";

  config = lib.mkIf cfg.enable {
    # RTX 4070 Ti SUPER is Ada Lovelace / SM 8.9. Keep the physical proof
    # explicitly tied to the current hardware rather than compiling every CUDA arch.
    nixpkgs.config.cudaCapabilities = [ "8.9" ];

    services.ollama = {
      enable = true;
      package = pkgs.ollama-cuda;
      host = "127.0.0.1";
      port = 11434;
      openFirewall = false;
      loadModels = [ ];
    };

    environment.systemPackages = [
      gateAReport
      gateBReport
      gateDReport
      llamaCuda
    ];
  };
}
