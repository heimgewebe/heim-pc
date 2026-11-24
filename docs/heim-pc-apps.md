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

## Aufgabenorientierte Auswahl für Agenten

Bei einem passenden Auftrag diese bereits vorhandenen Anwendungen **in Betracht ziehen**, bevor zusätzliche Dienste eingerichtet werden:

- **Paperless-ngx:** Dokumente importieren, organisieren und suchen. Für reine Textextraktion die vorhandene Document-Text-Engine bevorzugen.
- **Immich:** Fotos und Videos verwalten, sichern und Alben pflegen.
- **Readeck:** Webartikel und Quellen für spätere Lektüre aufbewahren.
- **Audiobookshelf:** Hörbuch- und Podcastbibliotheken verwalten und wiedergeben.
- **Penpot:** editierbare Mockups, Designs und gemeinsame UI-Prototypen erstellen.
- **FileBrowser Quantum:** Dateien im freigegebenen Austauschordner bereitstellen und abholen, nicht das gesamte Home durchsuchen.
- **IT Tools:** interaktive Entwickler- und Textwerkzeuge; für automatisierte Schritte vorhandene CLI-Werkzeuge vorziehen, wenn geeigneter.
- **ntfy auf Heimberry:** unkritische Statusmeldungen an Geräte liefern; Topic-Zugriff und iOS-Zustellung prüfen, keine Secrets senden.
- **MCP Inspector:** MCP-Server und Tools bei Bedarf lokal diagnostizieren, kein permanenter Webdienst.

**Agentengrenze:** Der Katalog begründet weder laufende Dienste noch eine authentifizierte Browser-/API-Sitzung. Vor Zugriff vorhandene native Typed-Tools, Connectoren oder den autorisierten lokalen Operator prüfen; dann Live-Readback und Rechte der konkreten Anwendung. Keine neue Anwendungsinventur oder zweite Systemkatalog-Authority anlegen.

## Wiederherstellung

Die bestehende Restic-Sicherung von Home und `/persist` enthält auch die
lokalen Anwendungs- und Konfigurationspfade, soweit sie nicht ausgeschlossen
sind. Der vorhandene Datenbank-Exporter liegt unter
`~/.local/bin/heimgewebe-app-db-export`; seine Einheiten sind
`~/.config/systemd/user/heimgewebe-app-db-export.service` und
`~/.config/systemd/user/heimgewebe-app-db-export.timer`. Diese drei Dateien
gehören zum Wiederaufbau des Sicherungswegs. Der ältere
`heimgewebe-app-db-backup.timer` bleibt deaktiviert.

Nach der Erweiterung vom 24. November 2026 schreibt derselbe Timer vor
den Restic-Läufen zwei getrennte, manifestgebundene Exportsätze unter
`~/.local/share/heimgewebe/app-backups`:

- `current/`: PostgreSQL-Dumps für Penpot und Immich, SQLite-Exporte für
  Paperless, Audiobookshelf, Readeck und Home Assistant sowie Penpot-Assets.
- `music-assistant/current/`: konsistente Exporte von `library.db` und
  `auth.db` aus einem gemeinsamen Btrfs-Snapshot des laufenden Music Assistant.
  Ein Fehler dieses zusätzlichen Exports entwertet den bereits publizierten
  ersten Satz nicht. Jeweils `previous/` hält den vorherigen erfolgreichen Satz.

Beide Manifeste enthalten Erstellungszeit, Dateigrößen und SHA-256.
Vor dem Einsatz Dateiinhalte und Manifest prüfen und die Datenbanken isoliert
wiederherstellen; weder laufende Originaldatenbanken noch bestehende
Anwendungsdaten für eine Probe überschreiben. Medien, Anwendungssettings
und lokale Startdefinitionen sind zusätzlich aus dem tatsächlich gesicherten
Restic-Snapshot wiederherzustellen. Restic ist die Backup-/Restore-Authority,
nicht dieser Report.

**Besonderheit Music Assistant:** Der Dienst hält SQLite im exklusiven
WAL-Modus. Ein gewöhnlicher Online-Backup-Zugriff von außen kann deshalb
blockieren. Der Exporter nutzt das eigene Btrfs-Subvolume
`~/.local/share/heimgewebe/music-assistant` und entfernt den privaten Snapshot
nach dem Export. Bei einer Neuinstallation dieses Ziel vor der Datenrückgabe
als Benutzer `alex` auf Btrfs als Subvolume anlegen (nur bei fehlendem Ziel,
nicht über einem vorhandenen Datenverzeichnis). Der Restore muss diese
Topologie erhalten oder wiederherstellen: eine normale Verzeichniskopie
allein reicht für den nächsten Snapshotexport nicht. Die Anwendung danach
mit passenden Datenbank-/Imageversionen starten, Dienst- und HTTP-Funktion
prüfen und einen frischen Lauf des vorhandenen Exportdienstes verifizieren.
Die Sicherung benötigt weder einen zusätzlichen Timer noch regelmäßige
Music-Assistant-Dienststopps.

Der lokale Export und isolierte SQLite-Integritätsprüfungen wurden am
24. November 2026 erfolgreich ausgeführt; dies ist kein Nachweis einer
vollständigen Wiederherstellung aller Anwendungen vom externen Datenträger.

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
