---
role: reality
status: report
temporal_scope: point_in_time
observed_at: "2026-11-16"
---

# Selbstgehostete Anwendungen: Heim-PC

Host-lokale Orientierung nach Operatorauftrag vom 16. November 2026, keine
zweite Systemkarte. Die kuratierte Rollenzuordnung steht in
`scripts/generate_nixos_program_inventory.py` (`APPS`); Beobachtungen stehen im
NixOS-Report unter `~/.local/state/heim-pc/inventory/nixos-program-inventory.md`. Ein Rolleneintrag beweist weder
Installation noch laufenden Dienst. Kostenlose Selbsthosting-Nutzung bedeutet
hier keine automatische Cloud- oder API-Freigabe.

| Anwendung | Zweck | Start-/Runtime-Authority | Lokale Konfigurationsquelle (Klasse) |
|---|---|---|---|
| Paperless | Dokumente und OCR | systemd User / rootless Podman Compose | `~/.config/systemd/user/heimgewebe-paperless.service`, `~/.local/share/heimgewebe/paperless/compose.yaml` |
| Audiobookshelf | Hörbücher und Podcasts | systemd User / rootless Podman Quadlet | `~/.config/containers/systemd/heimgewebe-audiobookshelf.container` |
| Readeck | Leseliste und Webarchiv | systemd User / rootless Podman Quadlet | `~/.config/containers/systemd/heimgewebe-readeck.container` |
| Immich | Fotoverwaltung | systemd User / rootless Podman Compose | `~/.config/systemd/user/heimgewebe-immich.service`, `~/.local/share/heimgewebe/immich/compose.yaml` |
| Penpot | Design und Prototypen | systemd User / rootless Podman Compose | `~/.config/systemd/user/heimgewebe-penpot.service`, `~/.local/share/heimgewebe/penpot/compose.yaml` |
| FileBrowser Quantum | Dateiverwaltung | systemd User / rootless Podman Quadlet | `~/.config/containers/systemd/heimgewebe-filebrowser.container` |
| IT Tools | Lokale Entwicklerwerkzeuge | systemd User / rootless Podman Quadlet | `~/.config/containers/systemd/heimgewebe-it-tools.container` |
| ntfy Heimberry | Benachrichtigungen | Heimberry, **kein Heim-PC-Dienst** | Heimberry: `/etc/systemd/system/ntfy.service.d/10-heimgewebe.conf`; kein Heim-PC-Dienst |
| MCP Inspector | MCP-Werkzeuge interaktiv prüfen | on-demand CLI, kein Daemon | `~/.local/bin/mcp-inspector` und `~/.local/opt/heimgewebe-mcp-inspector`; Generator prüft nur `mcp-inspector --version`, kein `npx`-Download |

Die Quellpfadklassen wurden an installierten Dienstdefinitionen verifiziert; Konfigurationsinhalte
werden weder gelesen noch kopiert. Bei abweichenden Unit-/Containernamen muss
die Allowlist anhand der zuständigen lokalen Authority gezielt angepasst werden.
`is-enabled` beweist keine aktuelle Aktivität; Containerexistenz keine Health.

## Wiederherstellung

Für die sieben Heim-PC-Webdienste ist die Haupt-Verlässlichkeit die bestehende
Restic-Sicherung von Home und `/persist`, ergänzt durch sechs konsistente
DB-Exporte und isolierte DB-Restore-Checks. Diese Angabe ist **kein in dieser
Writer-Sandbox frisch geprüfter Backupnachweis**. Der vorhandene Datenbank-Exporter liegt unter `~/.local/bin/heimgewebe-app-db-export`;
seine Einheiten sind `~/.config/systemd/user/heimgewebe-app-db-export.service`
und `~/.config/systemd/user/heimgewebe-app-db-export.timer`.
App-Backupartefakte liegen in
der Quellpfadklasse `~/.local/share/heimgewebe/app-backups`; die lokalen
App-Konfigurationen verbinden Laufzeit und Daten. Restic ist die
Backup-/Restore-Authority, nicht dieser Report.

Der versionierte Host-Vertrag liegt in
[`restic-seagate-backup.nix`](../nixos/system/modules/restic-seagate-backup.nix),
die Root-Recovery-Prüfung in
[`heim-pc-restic-recovery-probe.py`](../nixos/system/modules/heim-pc-restic-recovery-probe.py).
Für App-Daten müssen vor einem Restore die zuständigen Export-/Restore-Belege,
die tatsächlich gesicherten Datenpfade und passende DB-/Imageversionen lokal
neu geprüft werden. Exporte allein ersetzen keinen erfolgreichen Restore.

**ntfy auf Heimberry ist ausdrücklich nicht vom Heim-PC-Restic gesichert.**
Seine Konfiguration und Wiederherstellung müssen beim separaten Heimberry-Host geprüft werden.

Eine echte Neuinstallation benötigt NixOS, lokale Start-/Konfigurationsquellen
und einen Datenrestore einschließlich Datenbanken und Medien. Der Zustand ist
nicht vollständig Git-deklarativ und lässt sich nicht allein aus dieser
Dokumentation rekonstruieren. Der Inventargenerator startet keine Dienste,
liest keine Container-Umgebung und führt keine Backup- oder Restore-Aktion aus.
