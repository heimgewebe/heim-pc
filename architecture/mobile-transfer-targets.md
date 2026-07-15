# Mobile Transfer Targets

This contract separates stable target identity from live availability.

- `ipad-10th-gen-wifi` is the primary remote device and participates in both the iCloud shared workspace and Taildrop direct delivery.
- `a54-von-alexander` is the Android phone fallback for remote use and participates in Taildrop direct delivery.
- Live online status and successful delivery must always be read from Tailscale at execution time.

The operator entry remains the transport-policy entry point. `manifest/mobile-transfer-targets.v1.json` is the canonical target inventory. The operator entry now references this manifest for Taildrop target resolution instead of embedding one iPad-only target. Live availability is still read from `tailscale file cp --targets` at execution time.
