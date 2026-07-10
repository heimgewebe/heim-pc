---
id: program-inventory-summary
role: reality
status: canonical
last_reviewed: 2026-07-09
depends_on:
  - software-inventory
verifies_with:
  - scripts/generate_program_inventory.py
  - runtime/program-inventory.v1.json
---

# Program Inventory Summary

Generated at: `2026-07-09T18:15:00Z`
Raw inventory source: `~/.local/share/heim-utilities/program-inventory/20260709-195458`

## Boundary

This document is a compact, reviewable summary of the current heim-pc program surface. Large raw inventories stay outside Git under `~/.local/share/heim-utilities/program-inventory/`.

The summary may include program names, executable metadata counts, package managers, service/container names and safe paths to local inventory artifacts. It must not contain secrets, browser profiles, private file contents, keyrings or raw history.

## Counts

| Area | Count |
|---|---:|
| Running process rows | 932 |
| Unique running process names | 552 |
| Desktop starters | 265 |
| Flatpak apps | 25 |
| Snap packages | 12 |
| Docker containers | 19 |
| Executables in curated program roots | 29361 |
| Executables on rootfs, non-sudo | 95049 |
| Executables on rootfs, sudo | 109443 |
| Executables additionally visible through sudo | 14394 |

## Running process focus

- `bash`: 112
- `tee`: 55
- `postgres`: 18
- `docker-proxy`: 17
- `brave`: 17
- `s6-supervise`: 13
- `ferdium`: 13
- `python`: 13
- `claude`: 12
- `chrome`: 12
- `containerd-shim`: 11
- `bwrap`: 11
- `python3`: 9
- `nvidia-drm/time`: 9
- `node`: 8
- `kworker/R-scsi_`: 6
- `cat`: 6
- `UVM`: 5
- `kworker/R-nvme-`: 4
- `plugin-linux-am`: 4
- `chrome_crashpad`: 4
- `nv_queue`: 3
- `nv_mem_pool_scr`: 3
- `dbus-broker-lau`: 3
- `dbus-broker`: 3
- `sh`: 3
- `xdg-desktop-por`: 3
- `gjs`: 3
- `xdg-dbus-proxy`: 3
- `Web`: 3
- `init-without-oc`: 3
- `espanso`: 3
- `systemd`: 2
- `rcu_exp_par_gp_`: 2
- `kworker/R-md_ll`: 2
- `nvidia-modeset/`: 2
- `kworker/R-kcryp`: 2
- `avahi-daemon`: 2
- `system76-schedu`: 2
- `touchegg`: 2

## Docker containers

- `brave_cori` — `henrygd/beszel:latest` — Created
- `compose-api-1` — `rust:1.89.0-bookworm` — Created
- `compose-caddy-1` — `caddy:2.7` — Created
- `compose-db-1` — `postgres:16` — Exited (0) 2 weeks ago
- `compose-pgbouncer-1` — `edoburu/pgbouncer:latest` — Exited (0) 2 weeks ago
- `compose-web-1` — `node:20.19.0-alpine` — Created
- `cranky_satoshi` — `vsc-weltgewebe-2e0be6136de82270214db448dd0fe39fcc62e683bc65d441110dc01323796585-uid` — Exited (0) 5 weeks ago
- `heim-util-backrest` — `ghcr.io/garethgeorge/backrest:latest` — Up 14 hours
- `heim-util-beszel` — `henrygd/beszel:latest` — Up 10 hours
- `heim-util-beszel-agent` — `henrygd/beszel-agent:latest` — Up 2 hours
- `heim-util-paperless-broker` — `redis:7-alpine` — Up 14 hours
- `heim-util-paperless-db` — `postgres:16-alpine` — Up 14 hours
- `heim-util-paperless-webserver` — `ghcr.io/paperless-ngx/paperless-ngx:latest` — Up 14 hours (healthy)
- `heim-util-stirling-pdf` — `ghcr.io/stirling-tools/s-pdf:latest` — Up 14 hours (healthy)
- `mm-app` — `mattermost/mattermost-team-edition:9.5` — Up 4 days (healthy)
- `mm-db` — `24a90047f2d2` — Up 4 days
- `unifi-mongo` — `mongo:6` — Up 4 days
- `unifi-network` — `lscr.io/linuxserver/unifi-network-application` — Up 4 days
- `wg-pg-proof` — `24a90047f2d2` — Exited (0) 4 days ago

## Flatpak apps

- Ardour 9.7.0 — `org.ardour.Ardour` (user)
- Bitwarden 2026.6.1 — `com.bitwarden.desktop` (system)
- Chromium Web Browser 150.0.7871.100 — `org.chromium.Chromium` (user)
- Discord 1.0.146 — `com.discordapp.Discord` (user)
- Easy Effects 8.2.7 — `com.github.wwmm.easyeffects` (user)
- Ente Auth 4.4 — `io.ente.auth` (user)
- Ferdium 7.1.2 — `org.ferdium.Ferdium` (user)
- Flameshot 14.0.0 — `org.flameshot.Flameshot` (user)
- Flatseal 2.4.1 — `com.github.tchx84.Flatseal` (user)
- GitHub Desktop 3.4.13-linux1 — `io.github.shiftey.Desktop` (user)
- GitKraken 12.3.0 — `com.axosoft.GitKraken` (user)
- Insomnia 12.6.0 — `rest.insomnia.Insomnia` (user)
- Kdenlive 26.04.3 — `org.kde.kdenlive` (user)
- LocalSend 1.17.0 — `org.localsend.localsend_app` (user)
- Mattermost 6.2.2 — `com.mattermost.Desktop` (system)
- OBS Studio 32.1.2 — `com.obsproject.Studio` (user)
- Obsidian 1.12.7 — `md.obsidian.Obsidian` (system)
- Postman 12.18.3 — `com.getpostman.Postman` (user)
- Shortwave 5.1.0 — `de.haeckerfelix.Shortwave` (system)
- Signal Desktop 8.17.0 — `org.signal.Signal` (user)
- Spotify 1.2.92.147.g5b8f9367 — `com.spotify.Client` (system)
- Sunshine 2026.516.143833 — `dev.lizardbyte.app.Sunshine` (system)
- Syncthing GTK v0.9.4.5 — `me.kozec.syncthingtk` (user)
- WezTerm 20240203-110809-5046fc22 — `org.wezfurlong.wezterm` (user)
- WhatsApp Desktop 1.2.3 — `io.github.mimbrero.WhatsAppDesktop` (user)

## Snap packages

- bare 1.0 — latest/stable
- core18 20260204 — latest/stable
- core20 20260410 — latest/stable
- core22 20260225 — latest/stable
- core24 20260410 — latest/stable
- espanso 2.2.4 — latest/edge
- gnome-3-28-1804 3.28.0-19-g98f9e67.98f9e67 — latest/stable
- gnome-46-2404 0+git.f1cd5fa-sdk0+git.ca9c59c — latest/stable
- gtk-common-themes 0.1-81-g442e511 — latest/stable
- helm 4.2.2 — latest/stable
- mesa-2404 25.0.7-snap211 — latest/stable
- snapd 2.76 — latest/stable

## Desktop programs by work area

### Audio / Video / Medien (19)

- Ardour
- Ardour6
- Audacity
- Calf Plugin Pack for JACK
- Carla
- Carla Control
- Easy Effects
- Fullscreen
- Kdenlive
- mpv Media Player
- OBS Studio
- Open in standalone mode
- PulseAudio Volume Control
- Qsynth
- Shortwave
- Sound Juicer
- Spotify
- VLC media player
- Xjadeo

### Browser / Kommunikation / Netzwerk (21)

- Advanced Network Configuration
- Brave Opti
- ChatGPT
- Discord
- Ferdium
- iCloud Drive Auth
- iCloud Drive Mount
- iCloud Drive Status
- LocalSend
- Mattermost
- Mono Signal Generator
- New Incognito Window
- New Window
- Open Profile Manager
- Proton VPN
- Remote Viewer
- Signal
- Sunshine
- Syncthing GTK
- WhatsApp Desktop
- Zoom Workplace

### Dokumente / Wissen / Office (14)

- Calendar
- Contacts
- Document Scanner
- iCloud
- Math
- MuseScore Studio
- New Document
- New Drawing
- New Formula
- New PDF
- New Presentation
- New Spreadsheet
- New Window
- Obsidian

### Entwicklung / Operator (21)

- Antigravity
- DataGrip 2025.3
- DB Browser for SQLite
- Fleet
- Fleet 1.48.261 Public Preview
- GitHub Desktop
- GitKraken
- HausKI Dashboard
- Insomnia
- JetBrains Toolbox
- Neovim
- New Empty Window
- Nsight Eclipse Edition
- NVIDIA Nsight Compute 2024.1.1
- NVIDIA Nsight Compute 2025.1.1
- NVIDIA Nsight Systems 2023.4.4
- NVIDIA Nsight Systems 2024.6.2
- NVIDIA Visual Profiler
- Postman
- PyCharm 2025.3
- Vim

### Grafik / Bilder (3)

- Image Viewer
- ImageMagick (color depth=q16)
- Open launcher

### System / Sicherheit / Utilities (58)

- About Eddy
- Additional Drivers
- Archive Manager
- Bitwarden
- Calculator
- Character Map
- Check for Updates
- CopyQ
- Disk Usage Analyzer
- Disks
- Ente Auth
- Extension Manager
- Extensions
- fish
- Flatseal
- Fonts
- GNOME System Monitor
- GParted
- Help
- IBus Preferences
- Input Method
- kitty
- Language Support
- Mozc Setup
- New Tab
- New Window
- NVIDIA X Server Settings
- OpenJDK Java 8 Policy Tool
- Passwords and Keys
- Popsicle USB Flasher
- Power Statistics
- Preferences
- Printers
- Psensor
- Raspberry Pi Imager
- Repoman
- Settings
- Show Applications
- Show Launcher
- Show Workspaces
- Software
- Software & Updates
- Solaar
- Stacer
- Startup Applications
- Synaptic Package Manager
- System Monitor
- System76 Driver
- Task Terminal
- TeXInfo
- Timeshift
- Tweaks
- UXTerm
- VeraCrypt
- Virtual Machine Manager
- Weather
- WezTerm
- XTerm

### Sonstige Desktop-Starter (122)

- 12 Channel Spectrum Analyzer
- 16 Channel Spectrum Analyzer
- Artistic Delay Mono
- Artistic Delay Stereo
- Direct Out 12 Instrument Sample Player
- Direct Out 24 Instrument Sample Player
- Direct out 48 Instrument Sample Player
- Eight Channel Spectrum Analyzer
- Four Channel Spectrum Analyzer
- ICF Bewertungsassistent
- Latency Meter
- Mid-Side Crossover
- Mid-Side Split Multiband Compressor
- Mid-Side Split Multiband Expander
- Mid-Side Split Multiband Gate
- Mid-Side Split Multiband Sidechain Expander
- Mid-Side Split Multiband Sidechain Gate
- Mid-Side Split Stereo Compressor
- Mid-Side Stereo 16 Band Graphic Equalizer
- Mid-Side Stereo 16 Band Parametric Equalizer
- Mid-Side Stereo 32 Band Graphic Equalizer
- Mid-Side Stereo 32 Band Parametric Equalizer
- Mid-Side Stereo Dynamic Processor
- Mid-Side Stereo Dynamic Sidechain Processor
- Mid-Side Stereo Expander
- Mid-Side Stereo Gate
- Mid-Side Stereo Sidechain Expander
- Mid-Side Stereo Sidechain Gate
- Mid-Side Stereo Sidechain Multiband Compressor
- Mid-Side Stero Sidechain Compressor
- Mono 16 Band Graphic Equalizer
- Mono 16 Band Parametric Equalizer
- Mono 32 Band Parametric Equalizer
- Mono Audio Profiler
- Mono Audio Trigger
- Mono Compressor
- Mono Convolution Reverb
- Mono Crossover
- Mono Delay Compensator
- Mono Dynamic Processor
- Mono Dynamic Sidechain Processor
- Mono Expander
- Mono Gate
- Mono Impulse Responses
- Mono Limiter
- Mono Loudness Compensator
- Mono MIDI Sample Player
- Mono MIDI Trigger
- Mono Multiband Compressor
- Mono Multiband Expander
- Mono Multiband Gate
- Mono Multiband Sidechain Expander
- Mono Multiband Sidechain Gate
- Mono Room Impulse Response Builder
- Mono Sidechain Compressor
- Mono Sidechain Expander
- Mono Sidechain Gate
- Mono Sidechain Limiter
- Mono Sidechain Multiband Compressor
- Mono Slap Delay
- Mono Surge Filter
- One Channel Spectrum Analyzer
- Oscilloscope 1 Channel
- Oscilloscope 2 Channels
- Oscilloscope 4 Channels
- Phase Detector
- Split Crossover
- Split Multiband Compressor
- Split Multiband Expander
- Split Multiband Gate
- Split Multiband Sidechain Expander
- Split Multiband Sidechain Gate
- Split Stereo 16 Band Graphic Equalizer
- Split Stereo 16 Band Parametric Equalizer
- Split Stereo 32 Band Graphic Equalizer
- Split Stereo 32 Band Parametric Equalizer
- Split Stereo Compressor
- Split Stereo Delay Compensator
- Split Stereo Dynamic Processor
- Split Stereo Dynamic Sidechain Processor
- Split Stereo Expander
- Split Stereo Gate
- Split Stereo Sidechain Compressor
- Split Stereo Sidechain Expander
- Split Stereo Sidechain Gate
- Split Stereo Sidechain Multiband Compressor
- Stereo 12 Instrument Sample Player
- Stereo 16 Band Graphic Equalizer
- Stereo 16 Band Parametric Equalizer
- Stereo 24 Instrument Sample Player
- Stereo 32 Band Graphic Equalizer
- Stereo 32 Band Parametric Equalizer
- Stereo 48 Instrument Sample Player
- Stereo Audio Profiler
- Stereo Audio Trigger
- Stereo Compressor
- Stereo Convolution Reverb
- Stereo Crossover
- Stereo Delay Compensator
- Stereo Dynamic Processor
- Stereo Dynamic Sidechain Processor
- Stereo Expander
- Stereo Gate
- Stereo Impulse Responses
- Stereo Limiter
- Stereo Loudness Compensator
- Stereo MIDI Sample Player
- Stereo MIDI Trigger
- Stereo Multiband Compressor
- Stereo Multiband Expander
- Stereo Multiband Gate
- Stereo Multiband Sidechain Expander
- Stereo Multiband Sidechain Gate
- Stereo Room Impulse Response Builder
- Stereo Sidechain Expander
- Stereo Sidechain Gate
- Stereo Sidechain Limiter
- Stereo Sidechain Multiband Compressor
- Stereo Slap Delay
- Stereo Surge Filter
- Stero Sidechain Compressor
- Two Channel Spectrum Analyzer

## Operator CLI tools

- `aider`: `~/.local/bin/aider`
- `bats`: `/usr/bin/bats`
- `bw`: `/var/lib/flatpak/app/com.bitwarden.desktop/x86_64/stable/7f3d809af95deb28a4b56a547103b6830e75bf26a5c7228f7bf94f8edab0ebf1/files/bin/bw`, `~/.local/bin/bw`, `~/.npm-global/bin/bw`
- `claude`: `~/.local/bin/claude`
- `codex`: `~/.local/bin/codex`, `~/.npm-global/bin/codex`
- `difft`: `~/.local/bin/difft`
- `docker`: `/usr/bin/docker`
- `docling`: `~/.local/bin/docling`
- `ffmpeg`: `/usr/bin/ffmpeg`, `/var/lib/flatpak/.removed/org.freedesktop.Platform-3f0cb4a807750a19ed8a3dea96be9bf562271bd8e84137fb2d678e665b549b73/files/bin/ffmpeg`, `/var/lib/flatpak/runtime/org.freedesktop.Platform/x86_64/24.08/9a6d66049b19987a22bf81015ce0d1fde260df85a45e54695aad3c82f1e198ee/files/bin/ffmpeg`, `/var/lib/flatpak/runtime/org.freedesktop.Platform/x86_64/25.08/fdad08cc10905f9175f0224652a7b1c1b4d37fc1a5fa8c97843ccef846c642a0/files/bin/ffmpeg`, `/var/lib/flatpak/runtime/org.gnome.Platform/x86_64/48/0ebc10e5cc1fbe0836505fa203d75902606bcd4763c2c3cb0678795690dc506c/files/bin/ffmpeg`
- `ffprobe`: `/var/lib/flatpak/.removed/org.freedesktop.Platform-3f0cb4a807750a19ed8a3dea96be9bf562271bd8e84137fb2d678e665b549b73/files/bin/ffprobe`, `/var/lib/flatpak/runtime/org.freedesktop.Platform/x86_64/24.08/9a6d66049b19987a22bf81015ce0d1fde260df85a45e54695aad3c82f1e198ee/files/bin/ffprobe`, `/var/lib/flatpak/runtime/org.freedesktop.Platform/x86_64/25.08/fdad08cc10905f9175f0224652a7b1c1b4d37fc1a5fa8c97843ccef846c642a0/files/bin/ffprobe`, `/var/lib/flatpak/runtime/org.gnome.Platform/x86_64/48/0ebc10e5cc1fbe0836505fa203d75902606bcd4763c2c3cb0678795690dc506c/files/bin/ffprobe`, `/var/lib/flatpak/runtime/org.gnome.Platform/x86_64/49/4936bdd3020c5d5bae52a4b217b0abe0e3cad28f6ad755d88042e257419aada8/files/bin/ffprobe`
- `gemini`: `~/.local/bin/gemini`, `~/.npm-global/bin/gemini`
- `gh`: `/usr/bin/gh`, `/var/lib/flatpak/app/md.obsidian.Obsidian/x86_64/stable/888de8f4928c6e0ead8265c71b1defa7c29259090479922ee501de179c61ddc2/files/bin/gh`
- `jq`: `/usr/bin/jq`, `/var/lib/flatpak/.removed/org.freedesktop.Platform-3f0cb4a807750a19ed8a3dea96be9bf562271bd8e84137fb2d678e665b549b73/files/bin/jq`, `/var/lib/flatpak/runtime/org.freedesktop.Platform/x86_64/24.08/9a6d66049b19987a22bf81015ce0d1fde260df85a45e54695aad3c82f1e198ee/files/bin/jq`, `/var/lib/flatpak/runtime/org.freedesktop.Platform/x86_64/25.08/fdad08cc10905f9175f0224652a7b1c1b4d37fc1a5fa8c97843ccef846c642a0/files/bin/jq`, `/var/lib/flatpak/runtime/org.gnome.Platform/x86_64/48/0ebc10e5cc1fbe0836505fa203d75902606bcd4763c2c3cb0678795690dc506c/files/bin/jq`
- `node`: `~/.local/bin/node`
- `npm`: `/usr/bin/npm`, `~/.local/bin/npm`
- `npx`: `/usr/bin/npx`, `~/.local/bin/npx`
- `ocrmypdf`: `/usr/bin/ocrmypdf`
- `ollama`: `/usr/local/bin/ollama`
- `openhands`: `~/.local/bin/openhands`
- `pnpm`: `~/.local/bin/pnpm`
- `python3`: `/var/lib/flatpak/.removed/org.freedesktop.Platform-3f0cb4a807750a19ed8a3dea96be9bf562271bd8e84137fb2d678e665b549b73/files/bin/python3`, `/var/lib/flatpak/runtime/org.freedesktop.Platform/x86_64/24.08/9a6d66049b19987a22bf81015ce0d1fde260df85a45e54695aad3c82f1e198ee/files/bin/python3`, `/var/lib/flatpak/runtime/org.freedesktop.Platform/x86_64/25.08/fdad08cc10905f9175f0224652a7b1c1b4d37fc1a5fa8c97843ccef846c642a0/files/bin/python3`, `/var/lib/flatpak/runtime/org.gnome.Platform/x86_64/48/0ebc10e5cc1fbe0836505fa203d75902606bcd4763c2c3cb0678795690dc506c/files/bin/python3`, `/var/lib/flatpak/runtime/org.gnome.Platform/x86_64/49/4936bdd3020c5d5bae52a4b217b0abe0e3cad28f6ad755d88042e257419aada8/files/bin/python3`
- `qpdf`: `/usr/bin/qpdf`
- `qwen`: `~/.local/bin/qwen`, `~/.npm-global/bin/qwen`
- `rclone`: `/usr/bin/rclone`, `~/.local/bin/rclone`
- `repomix`: `~/.npm-global/bin/repomix`
- `restic`: `/usr/bin/restic`
- `rg`: `/usr/bin/rg`, `/var/lib/flatpak/app/md.obsidian.Obsidian/x86_64/stable/888de8f4928c6e0ead8265c71b1defa7c29259090479922ee501de179c61ddc2/files/bin/rg`
- `rga`: `~/.local/bin/rga`
- `ruff`: `~/.local/bin/ruff`
- `shellcheck`: `/usr/bin/shellcheck`
- `shfmt`: `/usr/bin/shfmt`
- `tailscale`: `/usr/bin/tailscale`
- `tesseract`: `/usr/bin/tesseract`
- `tmux`: `/usr/bin/tmux`, `/usr/local/bin/tmux`
- `uv`: `~/.local/bin/uv`
- `yt-dlp`: `/usr/bin/yt-dlp`, `~/.local/bin/yt-dlp`

## Sudo rootfs scan delta

Additional executables visible through sudo: **14394**

### Top additional path prefixes

- `/var/lib`: 14390
- `/root/grabowski-power-worker-backup-20260709T072346Z`: 2
- `/root/.cache`: 1
- `~`: 1

### Top additional executable names

- `index.js`: 59
- `run`: 54
- `script`: 35
- `hostname`: 33
- `install-sh`: 28
- `dpkg`: 26
- `getconf`: 24
- `node-gyp`: 24
- `node-gyp.cmd`: 24
- `install`: 21
- `getent`: 20
- `hosts`: 20
- `iconv`: 20
- `ldconfig`: 20
- `ldd`: 20
- `resolv.conf`: 20
- `setup_dir`: 20
- `teardown_dir`: 20
- `.dockerenv`: 19
- `console`: 19
- `cli.js`: 18
- `install.sh`: 18
- `realpath`: 17
- `test`: 17
- `apt`: 16

## Raw artifact policy

- `PROGRAMME-UEBERSICHT.md`
- `SUMMARY.md`
- `apt_manual.txt`
- `cargo_installs.txt`
- `desktop_apps.csv`
- `docker_images.tsv`
- `docker_ps.tsv`
- `dpkg_packages.tsv`
- `executables.csv`
- `executables_added_by_sudo.csv`
- `executables_full_rootfs.csv`
- `executables_full_rootfs_sudo.csv`
- `flatpak_apps.tsv`
- `full-rootfs-scan-result.json`
- `full-rootfs-sudo-scan-result.json`
- `npm_globals.txt`
- `ollama_list.txt`
- `pipx_list.txt`
- `pnpm_globals.txt`
- `processes_ps.tsv`
- `programs_all.csv`
- `run-result.json`
- `running_processes.csv`
- `snap_list.txt`
- `sudo-delta-summary.json`
- `systemd_system_services.txt`
- `systemd_user_services.txt`
- `tailscale_targets.txt`

## Scan caveats

- `find: ‘~/iCloud/Drive’: Keine Berechtigung`
