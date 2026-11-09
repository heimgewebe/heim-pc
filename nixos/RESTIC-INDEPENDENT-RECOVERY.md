# Heim-PC: Restic-Backup auf der externen 4-TB-Platte

## Regelbetrieb

- Die vorhandene Festplatte **HEIM_BACKUP** wird automatisch unter
  `/var/lib/heim-pc-backup` eingebunden und nach Leerlauf wieder ausgehängt.
- Restic sichert den Heim-PC zweimal täglich (etwa 07:00 und 19:30 Uhr).
- Das Repository liegt auf der USB-Platte unter `restic/heim-pc`.
- Der bereits vorhandene Root-Schlüssel wird automatisch aus
  `/persist/secrets/restic/heim-pc-password` gelesen. **Keine Passwortabfrage
  für den Benutzer.** Die Verschlüsselung bleibt erhalten.
- Auf Heimberry liegt eine bereits byteweise abgeglichene Root-Kopie des
  Schlüssels unter `/var/lib/heimberry/restic-recovery/heim-pc.key` (0600).
  Eine Übertragung kann bei Schlüsseländerungen mit
  `scripts/restic-recovery-key-to-heimberry.sh` wiederholt werden.
  Der tatsächliche Entschlüsselungs-/Restore-Test auf Heimberry steht noch aus.

## Automatische Wartung

- Täglich nach dem morgendlichen Backup: Eine kleine Datei aus dem Snapshot
  testweise wiederherstellen und byteweise mit Restic `dump` vergleichen.
  Anschließend durch `restic check` jeweils ein Zehntel der Daten lesen.
  Zehn erfolgreiche Durchläufe prüfen sämtliche gespeicherten Daten einmal.
- Sonntags: Nur **NixOS-Snapshots** mit Host `heim-pc-nixos` und
  Tag `nixos-seagate` nach konservativer Regel aufräumen. Die letzten 14,
  alle innerhalb von 7 Tagen, 14 tägliche, 8 wöchentliche, 12 monatliche
  und 2 jährliche Sicherungsstände werden nach Restic-Regeln behalten.
- Voraussetzung für das Aufräumen ist lediglich ein höchstens **72 Stunden**
  alter vollständiger NixOS-Snapshot. Sonst wird nichts gelöscht.
- Pop!_OS-Snapshots anderer Hosts bleiben unberührt. Vor dem Löschen werden
  die konkreten Snapshot-IDs mit `forget --dry-run --json` verifiziert;
  bei einem Identitätswechsel von Platte oder Repository wird abgebrochen.
- Niemals pauschal `restic unlock` ausführen. Bei laufender Sicherung
  warten die Wartungsaufgaben auf die normale Repository-Sperre.
- **Keine Signaturfreigaben, keine monatlichen Umsteck-Aktionen,
  keine eigenständige Passwortverwaltung.**

## Wenn der Heim-PC ausfällt

Die USB-Platte kann an einen anderen Linux-Rechner angeschlossen werden.
Mit Restic und dem auf Heimberry gesicherten Schlüssel lassen sich die
Dateien in einen **separaten** Zielordner wiederherstellen, ohne dass das
ursprüngliche System booten muss. Ein vollständiges Test-Restore ist
optional und bislang **nicht** nachgewiesen.

Eine zweite physisch unabhängige Kopie wäre ein zusätzlicher Schutz gegen
Defekt oder Verlust der einzigen USB-Platte. Sie ist **keine**
Betriebsvoraussetzung für die vorhandene Backup-Automatik.

**Stand:** Die bestehende Backup-Automatik und eine kleine lokale
Wiederherstellungsprobe liefen erfolgreich. Ein vollständiger unabhängiger
Restore wurde nicht durchgeführt. Prüfergebnisse beweisen keine lückenlose
NixOS-Neuinstallation aus den Dateien allein.