# Mobile Transfer Targets

This contract separates stable target identity from live availability.

- `ipad-10th-gen-wifi` is the primary remote device and participates in both the Google Drive shared workspace and Taildrop direct delivery.
- `a54-von-alexander` is the Android phone fallback for remote use and can use the Google Drive shared workspace as well as Taildrop direct delivery.
- The canonical persistent cross-device workspace is Google Drive at `${HOME}/GDrive` on the heim-pc, backed by `gdrive:` and `google-drive-rclone.service` with rclone scope `drive`.
- iCloud Drive is not the canonical shared exchange path. It may remain available for explicit provider-specific or legacy workflows.
- Live Taildrop target availability and successful direct delivery must always be read from Tailscale at execution time. Google Drive health must be read from the service, mount and remote at execution time.

The operator entry remains the transport-policy entry point. `manifest/mobile-transfer-targets.v1.json` is the canonical target inventory. The operator entry references this manifest for both shared-workspace eligibility and Taildrop target resolution. Taildrop live availability is still read from `tailscale file cp --targets` at execution time.

## NixOS Google Drive restoration

The desktop module installs rclone for alex and declares the user service. It
starts at the user default target when a private rclone configuration exists;
without credentials it is skipped, rather than blocking login. No OAuth token
or client secret belongs in this repository, the Nix store, operator receipts
or chat transcripts.

If no valid private configuration was recovered, run `rclone config` as alex
in a local terminal, create the remote named `gdrive` with backend
`drive` and scope `drive`, and complete Google's browser consent. Keep
`~/.config/rclone/rclone.conf` private (mode 0600). Start the mount with
`systemctl --user start google-drive-rclone.service` after authentication.

The mount uses an on-demand VFS cache, not a local mirror. The 20 GiB cache
target is soft (open and pending-upload files may exceed it); writes may remain
pending until uploaded. Do not copy into the underlying directory when it is
not mounted. Before treating a transfer as complete, verify the service, the
actual mount source and remote visibility. A non-empty unmounted directory
must be reconciled, never hidden with `--allow-non-empty`.

Readiness checks (run as alex, without printing private file names):

```sh
systemctl --user is-active google-drive-rclone.service
findmnt --mountpoint "$HOME/GDrive" -n -o SOURCE,FSTYPE
rclone lsf gdrive: --max-depth 1 >/dev/null
```

For functional acceptance, create a unique harmless probe via the mounted
directory, wait for the remote upload, compare its bytes using direct remote
read, and remove only that probe. Repeat after a service restart and verify
the mount after the next managed NixOS activation/reboot. A healthy service
alone does not prove remote write delivery.

The external Restic backup excludes the canonical GDrive mount: backing up a
user-only FUSE cloud filesystem can fail the host backup or traverse remote
data. This is a dedicated mountpoint, not a local storage folder; OAuth
configuration remains covered by the normal private home backup policy.
