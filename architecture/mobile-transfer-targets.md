# Mobile Transfer Targets

This contract separates stable target identity from live availability.

- `ipad-10th-gen-wifi` is the primary remote device and participates in both the Google Drive shared workspace and Taildrop direct delivery.
- `a54-von-alexander` is the Android phone fallback for remote use and can use the Google Drive shared workspace as well as Taildrop direct delivery.
- The canonical persistent cross-device workspace is Google Drive at `${HOME}/GDrive` on the heim-pc, backed by `gdrive:` and `google-drive-rclone.service` with rclone scope `drive`.
- iCloud Drive is not the canonical shared exchange path. It may remain available for explicit provider-specific or legacy workflows.
- Live Taildrop target availability and successful direct delivery must always be read from Tailscale at execution time. Google Drive health must be read from the service, mount and remote at execution time.

The operator entry remains the transport-policy entry point. `manifest/mobile-transfer-targets.v1.json` is the canonical target inventory. The operator entry references this manifest for both shared-workspace eligibility and Taildrop target resolution. Taildrop live availability is still read from `tailscale file cp --targets` at execution time.
