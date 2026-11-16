---
role: reality
status: report
temporal_scope: point_in_time
observed_at: "2026-11-16T17:53:25+00:00"
---

# NixOS-Programminventar

Zeitgebundene Beobachtung auf Heim-PC, kein canonical live state und kein Vollinventar.
Versionen und Unit-Enablement gelten nur zum jeweiligen Beobachtungszeitpunkt; keine Health-/Aktivitätsaussage.
Nix-Profilnamen betreffen das aufrufende Nutzerprofil, nicht alle NixOS-Systempakete.
Desktopstarter sind nur sichtbare systemweite NixOS-Launcher; keine Nutzerprofile oder KDE-Einstellungs-Unterdialoge.
`unavailable`: Befehl fehlt. `error`: Abfrage/Format fehlgeschlagen; keine leere Installation ableiten.

Erneuern (ohne Installation/Downloads): `python3 scripts/generate_nixos_program_inventory.py`.
JSON: [nixos-program-inventory.v1.json](nixos-program-inventory.v1.json). Rollen/Restore: [selfhosted-apps.md](selfhosted-apps.md).

Die [Juli-Programme](program-inventory-summary.md) und das [Softwareinventar](software-inventory.md) bleiben HISTORISCHE Pop!_OS-Quellen vom 9. Juli 2026.

## os

Quelle: `nixos-version`; beobachtet: `2026-11-16T17:53:25+00:00`; Ergebnis: **ok** (rc=0).

- name: `NixOS`; version: `26.05.20261031.fa13731`

## desktop_apps

Quelle: `NixOS system desktop entries (system-only)`; beobachtet: `2026-11-16T17:53:25+00:00`; Ergebnis: **ok** (rc=0).

- id: `xfce4-about`; name: `About Xfce`
- id: `xfce4-accessibility-settings`; name: `Accessibility`
- id: `nm-connection-editor`; name: `Advanced Network Configuration`
- id: `xfce-ui-settings`; name: `Appearance`
- id: `xfce4-appfinder`; name: `Application Finder`
- id: `org.kde.ark`; name: `Ark`
- id: `btop`; name: `btop++`
- id: `thunar-bulk-rename`; name: `Bulk Rename`
- id: `xfce4-color-settings`; name: `Color Profiles`
- id: `org.kde.drkonqi.coredump.gui`; name: `Crashed Processes Viewer`
- id: `xfce4-mime-settings`; name: `Default Applications`
- id: `xfce-backdrop-settings`; name: `Desktop`
- id: `org.kde.discover`; name: `Discover`
- id: `xfce-display-settings`; name: `Display`
- id: `org.kde.dolphin`; name: `Dolphin`
- id: `org.kde.elisa`; name: `Elisa`
- id: `org.kde.plasma.emojier`; name: `Emoji Selector`
- id: `xfce4-file-manager`; name: `File Manager`
- id: `gvim`; name: `GVim`
- id: `org.kde.gwenview`; name: `Gwenview`
- id: `org.kde.khelpcenter`; name: `Help Center`
- id: `org.kde.kinfocenter`; name: `Info Center`
- id: `org.kde.kate`; name: `Kate`
- id: `kdesystemsettings`; name: `KDE System Settings`
- id: `xfce-keyboard-settings`; name: `Keyboard`
- id: `org.kde.konsole`; name: `Konsole`
- id: `org.kde.kwalletmanager`; name: `KWalletManager`
- id: `org.kde.kwrite`; name: `KWrite`
- id: `LocalSend`; name: `LocalSend`
- id: `xfce4-session-logout`; name: `Log Out`
- id: `xfce4-mail-reader`; name: `Mail Reader`
- id: `org.kde.kmenuedit`; name: `Menu Editor`
- id: `xfce-mouse-settings`; name: `Mouse and Touchpad`
- id: `org.xfce.mousepad`; name: `Mousepad`
- id: `nixos-manual`; name: `NixOS Manual`
- id: `xfce4-notifyd-config`; name: `Notifications`
- id: `nvidia-settings`; name: `NVIDIA X Server Settings`
- id: `org.kde.okular`; name: `Okular`
- id: `panel-preferences`; name: `Panel`
- id: `org.xfce.Parole`; name: `Parole Media Player`
- id: `com.github.jeromerobert.pdfarranger`; name: `PDF Arranger`
- id: `xfce4-power-manager-settings`; name: `Power Manager`
- id: `org.kde.qrca`; name: `Qrca`
- id: `org.xfce.ristretto`; name: `Ristretto Image Viewer`
- id: `xfce4-run`; name: `Run Program...`
- id: `xfce4-screenshooter`; name: `Screenshot`
- id: `xfce-session-settings`; name: `Session and Startup`
- id: `xfce4-settings-editor`; name: `Settings Editor`
- id: `xfce-settings-manager`; name: `Settings Manager`
- id: `org.kde.spectacle`; name: `Spectacle`
- id: `org.kde.plasma-systemmonitor`; name: `System Monitor`
- id: `systemsettings`; name: `System Settings`
- id: `xfce4-taskmanager`; name: `Task Manager`
- id: `xfce4-terminal-emulator`; name: `Terminal Emulator`
- id: `thunar`; name: `Thunar File Manager`
- id: `thunar-settings`; name: `Thunar Preferences`
- id: `vim`; name: `Vim`
- id: `org.pulseaudio.pavucontrol`; name: `Volume Control`
- id: `xfce4-web-browser`; name: `Web Browser`
- id: `xfce-wm-settings`; name: `Window Manager`
- id: `xfce-wmtweaks-settings`; name: `Window Manager Tweaks`
- id: `xfce-workspaces-settings`; name: `Workspaces`
- id: `xfce4-screensaver-preferences`; name: `Xfce Screensaver`
- id: `xfce4-terminal`; name: `Xfce Terminal`
- id: `xterm`; name: `XTerm`

## nix_profiles

Quelle: `nix profile list --json`; beobachtet: `2026-11-16T17:53:25+00:00`; Ergebnis: **ok** (rc=0).

- `bubblewrap`
- `claude-code`
- `codex`
- `de_DE`
- `de_DE-1`
- `discord`
- `google-chrome`
- `hunspell`
- `kdialog`
- `libreoffice-qt`
- `localsend`
- `pdfarranger`
- `podman-compose`
- `pulseaudio`
- `python3.13-ocrmypdf`
- `qpdf`
- `rustdesk-flutter`
- `signal-desktop`
- `spotify`
- `tesseract`

## flatpak

Quelle: `flatpak list --app --columns=application,name,version`; beobachtet: `2026-11-16T17:53:25+00:00`; Ergebnis: **unavailable** (rc=127).


## podman

Quelle: `podman ps --all --format {{.Names}}	{{.Image}}`; beobachtet: `2026-11-16T17:53:25+00:00`; Ergebnis: **ok** (rc=0).

- name: `heimgewebe-audiobookshelf`; image_version: `2.37.2`
- name: `heimgewebe-filebrowser`; image_version: `2.0.2-stable`
- name: `heimgewebe-it-tools`; image_version: `2024.10.22-7ca5933`
- name: `heimgewebe-paperless_paperless-broker_1`; image_version: `8.1`
- name: `heimgewebe-paperless_paperless-web_1`; image_version: `3.4.2`
- name: `heimgewebe-penpot_penpot-backend_1`; image_version: `2.19.1`
- name: `heimgewebe-penpot_penpot-exporter_1`; image_version: `2.19.1`
- name: `heimgewebe-penpot_penpot-frontend_1`; image_version: `2.19.1`
- name: `heimgewebe-penpot_penpot-postgres_1`; image_version: `15`
- name: `heimgewebe-penpot_penpot-valkey_1`; image_version: `8.1`
- name: `heimgewebe-readeck`; image_version: `0.23.5`
- name: `immich_machine_learning`; image_version: `v3.4.1`
- name: `immich_postgres`; image_version: `digest-pinned`
- name: `immich_redis`; image_version: `digest-pinned`
- name: `immich_server`; image_version: `v3.4.1`

## CLI ffmpeg

Quelle: `ffmpeg -version`; beobachtet: `2026-11-16T17:53:25+00:00`; Ergebnis: **unavailable** (rc=127).


## CLI gh

Quelle: `gh --version`; beobachtet: `2026-11-16T17:53:25+00:00`; Ergebnis: **ok** (rc=0).

- `2.103.3`

## CLI git

Quelle: `git --version`; beobachtet: `2026-11-16T17:53:25+00:00`; Ergebnis: **ok** (rc=0).

- `2.54.0`

## CLI jq

Quelle: `jq --version`; beobachtet: `2026-11-16T17:53:25+00:00`; Ergebnis: **ok** (rc=0).

- `1.8.2`

## CLI mcp-inspector

Quelle: `mcp-inspector --version`; beobachtet: `2026-11-16T17:53:25+00:00`; Ergebnis: **ok** (rc=0).

- `2.14.0`

## CLI nix

Quelle: `nix --version`; beobachtet: `2026-11-16T17:53:25+00:00`; Ergebnis: **ok** (rc=0).

- `2.34.9`

## CLI node

Quelle: `node --version`; beobachtet: `2026-11-16T17:53:25+00:00`; Ergebnis: **ok** (rc=0).

- `24.22.1`

## CLI npm

Quelle: `npm --version`; beobachtet: `2026-11-16T17:53:25+00:00`; Ergebnis: **ok** (rc=0).

- `11.19.1`

## CLI ocrmypdf

Quelle: `ocrmypdf --version`; beobachtet: `2026-11-16T17:53:25+00:00`; Ergebnis: **ok** (rc=0).

- `17.4.2`

## CLI podman

Quelle: `podman --version`; beobachtet: `2026-11-16T17:53:25+00:00`; Ergebnis: **ok** (rc=0).

- `5.8.9`

## CLI python3

Quelle: `python3 --version`; beobachtet: `2026-11-16T17:53:25+00:00`; Ergebnis: **ok** (rc=0).

- `3.13.17`

## CLI restic

Quelle: `restic version`; beobachtet: `2026-11-16T17:53:25+00:00`; Ergebnis: **ok** (rc=0).

- `0.18.1`

## CLI rg

Quelle: `rg --version`; beobachtet: `2026-11-16T17:53:26+00:00`; Ergebnis: **ok** (rc=0).

- `15.1.0`

## CLI tesseract

Quelle: `tesseract --version`; beobachtet: `2026-11-16T17:53:26+00:00`; Ergebnis: **ok** (rc=0).

- `5.5.3`

## CLI uv

Quelle: `uv --version`; beobachtet: `2026-11-16T17:53:26+00:00`; Ergebnis: **unavailable** (rc=127).


## user:heimgewebe-audiobookshelf.service

Quelle: `systemctl --user is-enabled heimgewebe-audiobookshelf.service`; beobachtet: `2026-11-16T17:53:26+00:00`; Ergebnis: **ok** (rc=0).

- exists: `True`; is_enabled: `generated`

## user:heimgewebe-filebrowser.service

Quelle: `systemctl --user is-enabled heimgewebe-filebrowser.service`; beobachtet: `2026-11-16T17:53:26+00:00`; Ergebnis: **ok** (rc=0).

- exists: `True`; is_enabled: `generated`

## user:heimgewebe-immich.service

Quelle: `systemctl --user is-enabled heimgewebe-immich.service`; beobachtet: `2026-11-16T17:53:26+00:00`; Ergebnis: **ok** (rc=0).

- exists: `True`; is_enabled: `enabled`

## user:heimgewebe-it-tools.service

Quelle: `systemctl --user is-enabled heimgewebe-it-tools.service`; beobachtet: `2026-11-16T17:53:26+00:00`; Ergebnis: **ok** (rc=0).

- exists: `True`; is_enabled: `generated`

## user:heimgewebe-paperless.service

Quelle: `systemctl --user is-enabled heimgewebe-paperless.service`; beobachtet: `2026-11-16T17:53:26+00:00`; Ergebnis: **ok** (rc=0).

- exists: `True`; is_enabled: `enabled`

## user:heimgewebe-penpot.service

Quelle: `systemctl --user is-enabled heimgewebe-penpot.service`; beobachtet: `2026-11-16T17:53:26+00:00`; Ergebnis: **ok** (rc=0).

- exists: `True`; is_enabled: `enabled`

## user:heimgewebe-readeck.service

Quelle: `systemctl --user is-enabled heimgewebe-readeck.service`; beobachtet: `2026-11-16T17:53:26+00:00`; Ergebnis: **ok** (rc=0).

- exists: `True`; is_enabled: `generated`

## system:podman.service

Quelle: `systemctl --system is-enabled podman.service`; beobachtet: `2026-11-16T17:53:26+00:00`; Ergebnis: **ok** (rc=1).

- exists: `True`; is_enabled: `linked`

## system:restic-backups-heim-pc.service

Quelle: `systemctl --system is-enabled restic-backups-heim-pc.service`; beobachtet: `2026-11-16T17:53:26+00:00`; Ergebnis: **ok** (rc=1).

- exists: `True`; is_enabled: `linked`

## system:restic-backups-heim-pc.timer

Quelle: `systemctl --system is-enabled restic-backups-heim-pc.timer`; beobachtet: `2026-11-16T17:53:26+00:00`; Ergebnis: **ok** (rc=0).

- exists: `True`; is_enabled: `enabled`
