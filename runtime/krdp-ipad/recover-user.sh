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
source_monitor="$here/ipad-krdp-monitor.service"
monitor_unit=ipad-krdp-monitor.service
target_monitor="$HOME/.config/systemd/user/$monitor_unit"
source_desktop="$here/org.kde.krdp-ipad-runtime-v13.desktop"
unit="app-org.kde.krdpserver.service"
runtime=/run/user/1000/krdp-ipad-native-v13/krdpserver
target_unit="$HOME/.config/systemd/user/$unit.d/override.conf"
target_desktop="$HOME/.local/share/applications/org.kde.krdp-ipad-runtime-v13.desktop"
gc_root="$HOME/.local/state/grabowski/krdp-ipad-native-v13-qt-close-guard"

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
grep -Fxq "ExecStart=$runtime --address 127.0.0.1 --port 3390 --monitor-name Virtual-iPadKrdp --plasma" "$source_unit" ||
  die "source unit runtime has unexpected arguments"
grep -Fxq 'ExecStart=/home/alex/.local/state/nix/profiles/krfb-virtual-ipad-no-vnc/bin/krfb-virtualmonitor --resolution 1168x768 --name iPadKrdp --scale 1 --port -1' "$source_monitor" ||
  die "iPad monitor source does not expose the verified 1168x768 output"
store_root="$(dirname "$(dirname "$store_binary")")"

running_runtime_matches() {
  local pid expected_sha actual_sha
  pid="$(systemctl --user show "$unit" -p MainPID --value 2>/dev/null)" || return 1
  [[ "$pid" =~ ^[0-9]+$ && "$pid" -gt 1 ]] || return 1
  [[ "$(readlink -f "/proc/$pid/exe" 2>/dev/null)" == "$runtime" ]] || return 1
  expected_sha="$(sha256sum "$store_binary" | cut -d' ' -f1)" || return 1
  actual_sha="$(sha256sum "/proc/$pid/exe" | cut -d' ' -f1)" || return 1
  [[ "$expected_sha" == "$actual_sha" ]]
}

check() {
  [[ -f "$target_monitor" ]] && cmp -s "$source_monitor" "$target_monitor" ||
    die "iPad virtual monitor user unit differs from checked-in source"
  [[ "$(systemctl --user is-enabled "$monitor_unit")" == enabled ]] || die "iPad monitor not enabled"
  [[ "$(systemctl --user is-active "$monitor_unit")" == active ]] || die "iPad monitor not active"
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
# Replacing the unit text while the helper remains active leaves an old KWin
# output behind. Restarting the helper blindly can duplicate that output and
# produce black PipeWire frames. Refuse an unsafe silent-success recovery.
if ! cmp -s "$source_monitor" "$target_monitor" &&
   [[ "$(systemctl --user is-active "$monitor_unit" 2>/dev/null || true)" == active ]]; then
  die "iPad monitor unit drift while active; stop/reconcile the KWin output before applying a new monitor config"
fi
if cmp -s "$source_unit" "$target_unit" && cmp -s "$source_monitor" "$target_monitor" &&
   [[ "$(systemctl --user is-enabled "$monitor_unit" 2>/dev/null)" == enabled ]] &&
   [[ "$(systemctl --user is-active "$monitor_unit" 2>/dev/null)" == active ]] && cmp -s "$source_desktop" "$target_desktop" &&
   [[ -L "$gc_root" && "$(readlink -f "$gc_root")" == "$store_root" ]] &&
   [[ "$(systemctl --user is-enabled "$unit" 2>/dev/null)" == enabled ]] &&
   [[ "$(systemctl --user is-active "$unit" 2>/dev/null)" == active ]] &&
   running_runtime_matches; then
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
backup_existing() {
  local source="$1" target="$2"
  if [[ -e "$source" || -L "$source" ]]; then
    [[ -f "$source" && ! -L "$source" ]] || die "unsafe existing recovery source $source"
    cp -p -- "$source" "$target" || die "backup copy failed for $source"
    cmp -s -- "$source" "$target" || die "backup verification failed for $source"
    sync -f "$target" || die "backup fsync failed for $source"
  fi
}
old_active="$(systemctl --user is-active "$unit" 2>/dev/null || true)"
old_monitor_active="$(systemctl --user is-active "$monitor_unit" 2>/dev/null || true)"
old_monitor_enabled="$(systemctl --user is-enabled "$monitor_unit" 2>/dev/null || true)"
old_enabled="$(systemctl --user is-enabled "$unit" 2>/dev/null || true)"
backup_existing "$target_monitor" "$backup/monitor"
backup_existing "$target_unit" "$backup/unit"
backup_existing "$target_desktop" "$backup/desktop"
sync -f "$backup" || die "backup directory fsync failed"
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
    if [[ -f "$backup/monitor" ]]; then
      install -Dm644 "$backup/monitor" "$target_monitor"
    else
      rm -f -- "$target_monitor"
    fi
    systemctl --user daemon-reload || :
    if [[ "$old_monitor_enabled" != enabled ]]; then systemctl --user disable "$monitor_unit" || :; fi
    if [[ "$old_monitor_active" == active ]]; then
      systemctl --user start "$monitor_unit" || :
    else
      systemctl --user stop "$monitor_unit" || :
    fi
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

install -Dm644 "$source_monitor" "$target_monitor"
install -Dm644 "$source_unit" "$target_unit"
install -Dm644 "$source_desktop" "$target_desktop"
systemctl --user daemon-reload
systemctl --user enable --now "$monitor_unit"
systemctl --user enable "$unit"
systemctl --user restart "$unit"
check
committed=1
printf 'KRDP_RECOVERY_APPLIED backup=%s\n' "$backup"
