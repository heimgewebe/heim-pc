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

- Der bestehende tägliche `grabowski-recovery-refresh.timer` löst über
  Grabowski/Rootbroker die feste Root-Systemd-Probe
  `heim-pc-restic-recovery-probe.service` aus. Es existiert **kein**
  separater Probe-Timer. Die Probe stellt eine kleine Datei aus dem Snapshot
  wieder her und vergleicht sie byteweise mit Restic `dump`.
  Anschließend liest `restic check` jeweils ein Zehntel der Daten;
  zehn erfolgreiche Durchläufe decken sämtliche gespeicherten Daten ab.
  Ist Grabowski oder dieser Auslöseweg gestört, entsteht kein neuer
  Root-Nachweis. Die Retention darf dann nicht löschen.
- Sonntags: Nur **NixOS-Snapshots** mit Host `heim-pc-nixos` und
  Tag `nixos-seagate` nach konservativer Regel aufräumen. Die letzten 14,
  alle innerhalb von 7 Tagen, 14 tägliche, 8 wöchentliche, 12 monatliche
  und 2 jährliche Sicherungsstände werden nach Restic-Regeln behalten.
- Voraussetzung für das Aufräumen sind ein höchstens **72 Stunden**
  alter vollständiger NixOS-Snapshot **und** ein ebenso frischer, root-eigener
  `proof.json`-Nachweis unter `/var/lib/heim-pc-restic-recovery-probe/`.
  Der Nachweis muss genau diesen Snapshot, die erfolgreiche Restore-Probe
  und den Repository-Check bestätigen; der Snapshot allein genügt nicht.
  Fehlt die Prüfung, wird nichts gelöscht.
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

**Nachweisstand 10.11.2026:** Die Root-Probe war am 09.11.2026 um
20:14 Uhr MEZ erfolgreich; `proof.json` meldete einen gültigen Restore
und Repository-Check. Die Retention war noch nicht produktiv ausgeführt.
Ein unabhängiger Restore auf Heimberry oder eine vollständige
NixOS-Neuinstallation wurde nicht nachgewiesen.