#!/usr/bin/env bash
# Restore KRDP v13's user files without changing Plasma or monitor topology.
set -euo pipefail
mode="--check"
if [[ $# -ge 1 ]]; then mode="$1"; fi
if [[ $# -gt 1 || ( "$mode" != "--check" && "$mode" != "--apply" ) ]]; then
  printf 'usage: %s [--check|--apply]\n' "$0" >&2
  exit 2
fi
die() { printf 'KRDP_RECOVERY_ERROR %s\n' "$*" >&2; exit 1; }

# This v13 runtime is intentionally bound to the physical alex Wayland session.
[[ "$(id -u)" == 1000 && "$(id -un)" == alex && "$HOME" == /home/alex ]] ||
  die "must run as alex (uid 1000), never through sudo"

here="$(cd -- "$(dirname -- "$0")" && pwd -P)"
source_unit="$here/krdp-native-override.conf"
source_desktop="$here/org.kde.krdp-ipad-runtime-v13.desktop"
unit="app-org.kde.krdpserver.service"
runtime=/run/user/1000/krdp-ipad-native-v13/krdpserver
target_unit="$HOME/.config/systemd/user/$unit.d/override.conf"
target_desktop="$HOME/.local/share/applications/org.kde.krdp-ipad-runtime-v13.desktop"
gc_root="$HOME/.local/state/grabowski/krdp-ipad-native-v13"

# Derive the Store ELF from the checked-in unit; do not duplicate a version pin.
store_binary="$(awk -v target="$runtime" \
  '$1=="ExecStartPre=/run/current-system/sw/bin/install" && $2=="-Dm755" && $4==target { print $3 }' \
  "$source_unit")"
[[ "$store_binary" == /nix/store/*/bin/.krdpserver-wrapped ]] ||
  die "no pinned Store ELF in checked-in unit"
[[ "$(grep -c "^ExecStartPre=/run/current-system/sw/bin/install " "$source_unit")" == 1 ]] ||
  die "ambiguous Store ELF in unit"
[[ -x "$store_binary" ]] ||
  die "pinned Store ELF missing; rebuild with ./runtime/krdp-ipad/build.sh first"
grep -Fxq "Exec=$runtime" "$source_desktop" ||
  die "KWin desktop entry does not match runtime ELF"
grep -Fxq "ExecStart=$runtime --address 127.0.0.1 --port 3390 --monitor 0 --plasma" "$source_unit" ||
  die "source unit runtime has unexpected arguments"
store_root="$(dirname "$(dirname "$store_binary")")"

check() {
  [[ -L "$gc_root" && "$(readlink -f "$gc_root")" == "$store_root" ]] ||
    die "v13 Nix GC root is missing or targets different build"
  [[ -f "$target_unit" ]] && cmp -s "$source_unit" "$target_unit" ||
    die "KRDP user drop-in differs from checked-in source"
  [[ -f "$target_desktop" ]] && cmp -s "$source_desktop" "$target_desktop" ||
    die "KWin desktop registration differs from checked-in source"
  [[ "$(systemctl --user is-enabled "$unit")" == enabled ]] ||
    die "KRDP user unit not enabled"
  [[ "$(systemctl --user is-active "$unit")" == active ]] ||
    die "KRDP user unit not active"
  local pid
  pid="$(systemctl --user show "$unit" -p MainPID --value)"
  [[ "$pid" =~ ^[0-9]+$ && "$pid" -gt 1 ]] || die "KRDP process not running"
  [[ "$(readlink -f "/proc/$pid/exe")" == "$runtime" ]] ||
    die "executed ELF is not the KWin-authorized v13 runtime path"
  local source_sha runtime_sha
  source_sha="$(sha256sum "$store_binary" | cut -d' ' -f1)"
  runtime_sha="$(sha256sum "/proc/$pid/exe" | cut -d' ' -f1)"
  [[ "$source_sha" == "$runtime_sha" ]] ||
    die "executed ELF does not match Nix source binary"
  printf 'KRDP_RECOVERY_CHECK_OK pid=%s store=%s\n' "$pid" "$store_root"
}

if [[ "$mode" == "--check" ]]; then
  check
  exit 0
fi

# Never replace a server with an active RDP client or absent Wayland socket.
[[ -S /run/user/1000/wayland-0 ]] ||
  die "Wayland session missing; do not restart the physical desktop"
connections="$(ss -Htn state established sport :3390)" ||
  die "could not determine whether a KRDP client is connected"
[[ -z "$connections" ]] || die "KRDP has an active client; not restarting"
if cmp -s "$source_unit" "$target_unit" && cmp -s "$source_desktop" "$target_desktop" &&
   [[ -L "$gc_root" && "$(readlink -f "$gc_root")" == "$store_root" ]] &&
   [[ "$(systemctl --user is-enabled "$unit" 2>/dev/null)" == enabled ]] &&
   [[ "$(systemctl --user is-active "$unit" 2>/dev/null)" == active ]]; then
  check
  printf 'KRDP_RECOVERY_ALREADY_CURRENT\n'
  exit 0
fi

# Pin the exact Store closure before changing any user configuration.
if [[ ! -L "$gc_root" ]]; then
  mkdir -p -- "$(dirname "$gc_root")"
  nix-store --add-root "$gc_root" --realise "$store_root" >/dev/null
fi
[[ "$(readlink -f "$gc_root")" == "$store_root" ]] ||
  die "GC root points at another Store build"

mkdir -p -- "$HOME/.local/state/grabowski"
backup="$(mktemp -d "$HOME/.local/state/grabowski/krdp-recovery.XXXXXXXX")"
chmod 700 "$backup"
old_active="$(systemctl --user is-active "$unit" 2>/dev/null || true)"
old_enabled="$(systemctl --user is-enabled "$unit" 2>/dev/null || true)"
[[ -f "$target_unit" ]] && cp -p -- "$target_unit" "$backup/unit" || :
[[ -f "$target_desktop" ]] && cp -p -- "$target_desktop" "$backup/desktop" || :
committed=0
rollback() {
  local status=$?
  if [[ "$committed" != 1 ]]; then
    if [[ -f "$backup/unit" ]]; then
      install -Dm644 "$backup/unit" "$target_unit"
    else
      rm -f -- "$target_unit"
    fi
    if [[ -f "$backup/desktop" ]]; then
      install -Dm644 "$backup/desktop" "$target_desktop"
    else
      rm -f -- "$target_desktop"
    fi
    systemctl --user daemon-reload || :
    if [[ "$old_enabled" != enabled ]]; then systemctl --user disable "$unit" || :; fi
    if [[ "$old_active" == active ]]; then
      systemctl --user restart "$unit" || :
    else
      systemctl --user stop "$unit" || :
    fi
    printf 'KRDP_RECOVERY_ROLLED_BACK backup=%s\n' "$backup" >&2
  fi
  exit "$status"
}
trap rollback EXIT

install -Dm644 "$source_unit" "$target_unit"
install -Dm644 "$source_desktop" "$target_desktop"
systemctl --user daemon-reload
systemctl --user enable "$unit"
systemctl --user restart "$unit"
check
committed=1
printf 'KRDP_RECOVERY_APPLIED backup=%s\n' "$backup"