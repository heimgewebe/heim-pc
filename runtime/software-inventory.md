---
id: software-inventory
role: reality
status: canonical
last_reviewed: 2026-07-09
depends_on:
  - home-entry
  - security
verifies_with:
  - scripts/generate_software_inventory.py
---

# Software Inventory

Generated at: `2026-07-09T09:52:21Z`

## Boundary

This is a small, reviewable inventory of operator-relevant software surfaces on heim-pc. It is not a full `/usr/bin`, dpkg, Home directory or private-content dump.

The inventory may record executable names, versions, package managers, local service URLs and safe configuration paths. It must not record secrets, browser profiles, keyrings, private documents or raw command histories.

## Command surfaces

| Command | Status | Path | Version / observation |
|---|---:|---|---|
| `node` | ok | `/home/alex/.local/bin/node` | v22.23.1 |
| `npm` | ok | `/home/alex/.local/bin/npm` | 10.9.8 |
| `npx` | ok | `/home/alex/.local/bin/npx` | 10.9.8 |
| `corepack` | ok | `/home/alex/.local/bin/corepack` | 0.34.6 |
| `pnpm` | ok | `/home/alex/.local/bin/pnpm` | 9.11.0 |
| `python3` | ok | `/usr/bin/python3` | Python 3.10.12 |
| `pipx` | ok | `/usr/bin/pipx` | 1.0.0 |
| `docker` | ok | `/usr/bin/docker` | Docker version 29.6.1, build 8900f1d |
| `docker-compose` | missing | `` | - |
| `flatpak` | ok | `/usr/bin/flatpak` | Flatpak 1.14.6 |
| `snap` | ok | `/usr/bin/snap` | snap          2.76<br>snapd         2.76<br>series        16<br>pop           22.04<br>kernel        7.0.11-76070011-generic<br>architecture  amd64 |
| `apt` | ok | `/usr/bin/apt` | apt 2.4.14 (amd64) |
| `restic` | ok | `/usr/bin/restic` | restic 0.12.1 compiled with go1.18.1 on linux/amd64 |
| `atuin` | ok | `/home/alex/.local/bin/atuin` | atuin 18.17.0 (0966e8b202ab4f9fbe869f22af8bca7cab4e7799) |
| `difft` | ok | `/home/alex/.local/bin/difft` | Difftastic 0.69.0<br><br>Revision:  90a0f1b 2026-04-29<br>Toolchain: 1.85.0<br>System:    linux x86_64 |
| `difftastic` | ok | `/home/alex/.local/bin/difftastic` | Difftastic 0.69.0<br><br>Revision:  90a0f1b 2026-04-29<br>Toolchain: 1.85.0<br>System:    linux x86_64 |
| `rga` | ok | `/home/alex/.local/bin/rga` | ripgrep-all 0.10.10 |
| `rg` | ok | `/usr/bin/rg` | ripgrep 13.0.0<br>-SIMD -AVX (compiled)<br>+SIMD +AVX (runtime) |
| `copyq` | ok | `/usr/bin/copyq` | CopyQ Clipboard Manager 6.0.1<br>Qt: 5.15.2<br>KNotifications: 5.89.0<br>Compiler: GCC<br>Arch: x86_64-little_endian-lp64<br>OS: Pop!_OS 22.04 LTS |
| `espanso` | rc=1 | `/snap/bin/espanso` | snap-confine is packaged without necessary permissions and cannot continue<br>required permitted capability cap_dac_override not found in current capabilities:<br>  = |
| `easyeffects` | missing | `` | - |
| `docling` | ok | `/home/alex/.local/bin/docling` | Docling version: 2.111.0<br>Docling Core version: 2.86.0<br>Docling IBM Models version: 3.13.3<br>Docling Parse version: 7.7.0<br>Python: cpython-310 (3.10.12)<br>Platform: Linux-7.0.11-76070011-generic-x86_64-with-glibc2.35 |
| `localsend` | missing | `` | - |
| `bw` | ok | `/home/alex/.local/bin/bw` | 2026.6.0 |
| `gh` | ok | `/usr/bin/gh` | gh version 2.96.0 (2026-07-02)<br>https://github.com/cli/cli/releases/tag/v2.96.0 |
| `git` | ok | `/usr/bin/git` | git version 2.34.1 |
| `curl` | ok | `/usr/bin/curl` | curl 7.81.0 (x86_64-pc-linux-gnu) libcurl/7.81.0 OpenSSL/3.0.2 zlib/1.2.13 brotli/1.0.9 zstd/1.4.8 libidn2/2.3.2 libpsl/0.21.0 (+libidn2/2.3.2) libssh/0.9.6/openssl/zlib nghttp2/1.43.0 librtmp/2.3 OpenLDAP/2.5.20<br>Release-Date: 2022-01-05<br>Protocols: dict file ftp ftps gopher gophers http https imap imaps ldap ldaps mqtt pop3 pop3s rtmp rtsp scp sftp smb smbs smtp smtps telnet tftp <br>Features: alt-svc AsynchDNS brotli GSS-API HSTS HTTP2 HTTPS-proxy IDN IPv6 Kerberos Largefile libz NTLM NTLM_WB PSL SPNEGO SSL TLS-SRP UnixSockets zstd |
| `jq` | ok | `/usr/bin/jq` | jq-1.6 |
| `qpdf` | ok | `/usr/bin/qpdf` | qpdf version 10.6.3<br>Run qpdf --copyright to see copyright and license information. |
| `pdfinfo` | ok | `/usr/bin/pdfinfo` | pdfinfo version 22.02.0<br>Copyright 2005-2022 The Poppler Developers - http://poppler.freedesktop.org<br>Copyright 1996-2011 Glyph & Cog, LLC |
| `tesseract` | ok | `/usr/bin/tesseract` | tesseract 4.1.1<br> leptonica-1.82.0<br>  libgif 5.1.9 : libjpeg 8d (libjpeg-turbo 2.1.1) : libpng 1.6.37 : libtiff 4.3.0 : zlib 1.2.11 : libwebp 1.2.2 : libopenjp2 2.4.0<br> Found AVX2<br> Found AVX<br> Found FMA<br>… |
| `ocrmypdf` | ok | `/usr/bin/ocrmypdf` | /usr/lib/python3/dist-packages/pikepdf/_version.py:7: UserWarning: pkg_resources is deprecated as an API. See https://setuptools.pypa.io/en/latest/pkg_resources.html. The pkg_resources package is slated for removal as early as 2025-11-30. Refrain from using this package or pin to Setuptools<81.<br>  from pkg_resources import DistributionNotFound<br>13.4.0+dfsg |
| `pandoc` | missing | `` | - |
| `libreoffice` | ok | `/usr/bin/libreoffice` | LibreOffice 7.3.7.2 30(Build:2) |
| `magick` | missing | `` | - |
| `convert` | ok | `/usr/bin/convert` | Version: ImageMagick 6.9.11-60 Q16 x86_64 2021-01-25 https://imagemagick.org<br>Copyright: (C) 1999-2021 ImageMagick Studio LLC<br>License: https://imagemagick.org/script/license.php<br>Features: Cipher DPC Modules OpenMP(4.5) <br>Delegates (built-in): bzlib djvu fftw fontconfig freetype heic jbig jng jp2 jpeg lcms lqr ltdl lzma openexr pangocairo png tiff webp wmf x xml zlib |
| `ffmpeg` | ok | `/usr/bin/ffmpeg` | ffmpeg version 4.4.2-0ubuntu0.22.04.1 Copyright (c) 2000-2021 the FFmpeg developers<br>built with gcc 11 (Ubuntu 11.2.0-19ubuntu1)<br>configuration: --prefix=/usr --extra-version=0ubuntu0.22.04.1 --toolchain=hardened --libdir=/usr/lib/x86_64-linux-gnu --incdir=/usr/include/x86_64-linux-gnu --arch=amd64 --enable-gpl --disable-stripping --enable-gnutls --enable-ladspa --enable-libaom --enable-libass --enable-libbluray --enable-libbs2b --enable-libcaca --enable-libcdio --enable-libcodec2 --enable-libdav1d --enable-libflite --enable-libfontconfig --enable-libfreetype --enable-libfribidi --enable-libgme --enable-libgsm --enable-libjack --enable-libmp3lame --enable-libmysofa --enable-libopenjpeg --enable-libopenmpt --enable-libopus --enable-libpulse --enable-librabbitmq --enable-librubberband --enable-libshine --enable-libsnappy --enable-libsoxr --enable-libspeex --enable-libsrt --enable-libssh --enable-libtheora --enable-libtwolame --enable-libvidstab --enable-libvorbis --enable-libvpx --enable-libwebp --enable-libx265 --enable-libxml2 --enable-libxvid --enable-libzimg --enable-libzmq --enable-libzvbi --enable-lv2 --enable-omx --enable-openal --enable-opencl --enable-opengl --enable-sdl2 --enable-pocketsphinx --enable-librsvg --enable-libmfx --enable-libdc1394 --enable-libdrm --enable-libiec61883 --enable-chromaprint --enable-frei0r --enable-libx264 --enable-shared<br>libavutil      56. 70.100 / 56. 70.100<br>libavcodec     58.134.100 / 58.134.100<br>libavformat    58. 76.100 / 58. 76.100<br>… |
| `ollama` | ok | `/usr/local/bin/ollama` | ollama version is 0.12.6 |
| `gemini` | ok | `/home/alex/.local/bin/gemini` | 1.1.0:<br>· Agent execution mode cycling is now publicly available: `default` -> `accept-edits` -> `plan`)<br>· Added `request-review` (default) mode as the default execution behavior: automatically pauses before file write operations to display an interactive, line-level diff preview (`f` shortcut) where users can review, accept, or reject individual code modifications before they are saved to disk.<br>· Added an `Agent Mode` option to the `/settings` panel so users can set and persist a default execution mode (`default`, `accept-edits`, `plan`) without manually editing `settings.json` or passing `--mode` on startup, with real-time synchronization so changes take effect immediately.<br>· Added a dedicated `"Create file"` confirmation preview for new file creations (`write_to_file` without overwrite): renders new content as an addition-only diff preview.<br>· Added `/plan` mode to replace legacy `/planning`, and removed `/fast` slash commands: consolidated and simplified execution mode switching around `shift+tab` mode cycling and the `/plan` mode prefix<br>… |
| `claude` | ok | `/home/alex/.local/bin/claude` | 2.1.205 (Claude Code) |
| `codex` | ok | `/home/alex/.local/bin/codex` | codex-cli 0.142.2 |
| `uv` | ok | `/home/alex/.local/bin/uv` | uv 0.9.18 |
| `cargo` | missing | `` | - |
| `rustc` | missing | `` | - |
| `go` | missing | `` | - |

## Localhost web services

| Service | Local URL | Authority boundary |
|---|---|---|
| Backrest | http://127.0.0.1:9898 | Helper UI only; no public exposure implied. |
| Beszel | http://127.0.0.1:8090 | Helper UI only; no public exposure implied. |
| Stirling PDF | http://127.0.0.1:8084 | Helper UI only; no public exposure implied. |
| Paperless-ngx | http://127.0.0.1:8010 | Helper UI only; no public exposure implied. |

## Heim utility containers

```text
heim-util-beszel	henrygd/beszel:latest	Up 2 hours	127.0.0.1:8090->8090/tcp
heim-util-stirling-pdf	ghcr.io/stirling-tools/s-pdf:latest	Up 6 hours (healthy)	127.0.0.1:8084->8080/tcp
heim-util-paperless-webserver	ghcr.io/paperless-ngx/paperless-ngx:latest	Up 6 hours (healthy)	127.0.0.1:8010->8000/tcp
heim-util-paperless-db	postgres:16-alpine	Up 6 hours	5432/tcp
heim-util-backrest	ghcr.io/garethgeorge/backrest:latest	Up 6 hours	127.0.0.1:9898->9898/tcp
heim-util-paperless-broker	redis:7-alpine	Up 6 hours	6379/tcp
```

## Selected Flatpak apps

```text
com.github.wwmm.easyeffects	Easy Effects	8.2.7	flathub
org.localsend.localsend_app	LocalSend	1.17.0	flathub
```

## Selected apt/root packages

```text
nodejs	22.23.1-1nodesource1	install ok installed
gzip	1.10-4ubuntu4.2	install ok installed
tar	1.34+dfsg-1ubuntu0.1.22.04.4	install ok installed
restic	0.12.1-2ubuntu0.3	install ok installed
ripgrep	13.0.0-2ubuntu0.1	install ok installed
copyq	6.0.1-1	install ok installed
flatpak	1.14.6-1~1713976503~22.04~1a1043a	install ok installed
qpdf	10.6.3-1ubuntu0.1	install ok installed
poppler-utils	22.02.0-2ubuntu0.13	install ok installed
tesseract-ocr	4.1.1-2.1build1	install ok installed
tesseract-ocr-deu	1:4.00~git30-7274cfa-1.1	install ok installed
tesseract-ocr-eng	1:4.00~git30-7274cfa-1.1	install ok installed
pipx	1.0.0-1	install ok installed
```

## Utility timers

```text
NEXT                         LEFT     LAST PASSED UNIT                           ACTIVATES
Fri 2026-07-10 03:18:07 CEST 15h left n/a  n/a    heim-paperless-export.timer    heim-paperless-export.service
Fri 2026-07-10 03:46:15 CEST 15h left n/a  n/a    heim-restic-backup-local.timer heim-restic-backup-local.service

2 timers listed.
Pass --all to see loaded but inactive timers, too.
```

## Paperless end-state

```text
documents 1
tags 17
document_types 12
correspondents 13
```

## Beszel end-state

```text
users 1
_externalAuths 1
systems 0
system_stats 0
container_stats 0
```

## Local restic utility backup

```text
----------------------------------------------------------------------------------------------------------------------------------------------
b9332c01  2026-07-09 10:55:28  heim-pc     heim-utility,paperless-export,local-safety  /home/alex/.config/atuin
                                                                                       /home/alex/.config/espanso
                                                                                       /home/alex/.config/heim-utilities
                                                                                       /home/alex/.local/share/heim-utilities/paperless/export
                                                                                       /home/alex/Incoming/LocalSend
----------------------------------------------------------------------------------------------------------------------------------------------
1 snapshots
```

## Known local paths

- `~/.local/bin/node`
- `~/.local/bin/npm`
- `~/.local/bin/npx`
- `~/.local/bin/corepack`
- `~/.local/share/heim-node-wrapper/uninstall.sh`
- `~/.local/bin/heim-paperless-export`
- `~/.local/bin/heim-restic-backup-local`
- `~/.local/bin/heim-localsend-open`
- `~/.local/bin/atuin`
- `~/.local/bin/difft`
- `~/.local/bin/rga`
- `~/.local/bin/docling`
- `~/.config/atuin/config.toml`
- `~/.config/heim-utilities/paperless.env`
- `~/.local/share/heim-utilities`
- `~/.local/share/heim-utilities/paperless/export/current`
- `~/.local/share/heim-utilities/easyeffects/profile-plan.md`
- `~/.config/heim-utilities/restic-heim-pc-local.includes`
- `~/.config/heim-utilities/restic-heim-pc-local.excludes`
- `~/Incoming/LocalSend`
- `~/Incoming/LocalSend/paperless-consume`

## Known caveats

- Node is installed system-wide from NodeSource as `nodejs`. A local wrapper layer in `~/.local/bin/{node,npm,npx,corepack}` runs Node through `systemd-run --user` with executable-memory restrictions relaxed for Grabowski/service contexts. `/usr/bin/node` remains the root-owned package binary.
- Docling can download OCR/model artifacts on first use. Treat converted output as import/probe material, not canonical truth.
- Paperless credentials are local-only in `~/.config/heim-utilities/paperless.env` and must not be committed.
- Localhost service availability does not prove UI onboarding is complete. Beszel is active, but the 2026-07-09 database check still shows no monitored systems/stats rows, so monitoring acceptance remains open.
- Paperless has a starter taxonomy and a local export/backup path. This proves plumbing, not real document-classification quality.
- LocalSend has inbox paths and a launcher helper, but cross-device transfer still needs iPad/Samsung-side interaction.
- EasyEffects has a profile plan only; no profile is blindly activated without listening/recording validation.
