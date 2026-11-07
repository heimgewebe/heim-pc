# Restic — unabhängige Wiederherstellung und Retention-Freigabe

Status 2026-11-07: **kein vollständiger Restore auf unabhängiger Hardware nachgewiesen; Retention bleibt gesperrt.**

Der funktionierende lokale `heim-pc-restic-recovery-probe`-Nachweis ist **kein**
unabhängiger Restore. Seine JSON-Datei darf nie zur Retention-Freigabe verwendet
werden. Für diese Freigabe verlangt das System eine separat signierte, höchstens
30 Tage alte Erklärung eines anderen Rechners. Der private Signaturschlüssel
darf niemals auf dem Heim-PC liegen.

## Voraussetzungen

1. **Vorhandene externe 4-TB-Platte HEIM_BACKUP:** 3,6 TiB, davon am
   2026-11-07 rund 3,1 TiB frei. Das vorhandene Restic-Repository belegt
   rund 439 GiB. Platte bei angehaltenem Backup ordnungsgemäß vom Heim-PC
   aushängen und **auf Heimberry** anschließen. Der vollständige Restore
   (~407 GiB beim letzten Lauf) kann auf der selben Platte in einem
   **anderen Verzeichnis außerhalb von `restic/`** erfolgen; weder
   Repository noch Quell-Snapshots dürfen überschrieben werden.
2. **Kein Benutzerpasswort erforderlich:** Das bestehende Restic-Schlüsselmaterial
   wurde auf Heimberry nach `/var/lib/heimberry/restic-recovery/heim-pc.key`
   übertragen und byteweise mit dem Quellschlüssel verglichen (root:root 0600).
   Restic erhält diesen Schlüssel automatisch via `--password-file`; kein
   Mensch muss ein Passwort kennen oder eintippen. Ein echter off-host
   Entschlüsselungs-/Restore-Lauf steht bis zum Umstecken noch aus.
3. **Unabhängige Hardware ist Heimberry**, nicht ein zweiter Speicherdatenträger.
   Der Original-Backupdatenträger muss dabei intakt bleiben. Das ist ein
   realistischer Ausfalltest **des Heim-PCs**, aber **kein** Beweis für
   Datenträgerredundanz. Eine zweite Kopie schützt zusätzlich gegen Ausfall
   oder Verlust gerade dieser USB-Platte, ist jedoch keine Vorbedingung.
4. Ausreichende Laufzeit zum echten Lesen und Vergleichen aller Dateien.

Repositoryquelle: `/var/lib/heim-pc-backup/restic/heim-pc` auf
`9b626294-7913-4be0-88fa-96b314e96ee5`.
Repository-ID: `85ee278eeb58f42c26745796cb7b23239d4c7c01f5f4d00f2c10e216cefa4972`.
Kopien nur aus ruhendem Repository oder konsistentem Read-only-Dateisystem-Snapshot
übernehmen; keine laufenden Backup-/Forget-/Prune-Operationen während einer
unkonsistenten Dateikopie dulden.

## End-to-End-Nachweis ausschließlich auf unabhängiger Hardware

Die folgenden Platzhalter müssen *auf Heimberry* auf getrennte Verzeichnisse
zeigen: `REPO` (direkter USB-Backup-Datenträger oder unabhängige Kopie),
`PASS` (bereits hinterlegter root-only Schlüssel, ohne Benutzereingabe),
`SNAPSHOT` (volle 64-stellige ID eines gesicherten NixOS-Snapshots),
`RESTORE` (leeres Ziel), `VIEW` (leerer FUSE-Mountpunkt).

```bash
restic --repo "$REPO" --password-file "$PASS" cat config
restic --repo "$REPO" --password-file "$PASS" snapshots --json \
  --host heim-pc-nixos --tag nixos-seagate
restic --repo "$REPO" --password-file "$PASS" check --read-data
restic --repo "$REPO" --password-file "$PASS" restore "$SNAPSHOT" \
  --target "$RESTORE" --verify
```

In einem zweiten Terminal **des unabhängigen Hosts** die Read-only-Archivansicht
öffnen und den vollständigen Manifestvergleich ausführen:

```bash
restic --repo "$REPO" --password-file "$PASS" mount \
  --path-template 'ids/%I' "$VIEW"
# Erst wenn der FUSE-Mount wirklich bereit ist:
python3 scripts/restic_independent_inventory.py \
  --snapshot-root "$VIEW/ids/$SNAPSHOT" \
  --restore-root "$RESTORE" > independent-inventory.json
```

Das Vergleichsprogramm liest alle sieben kritischen Pfade, hasht **jede**
reguläre Datei in beiden Bäumen, berücksichtigt Dateienamen, leere
Verzeichnisse und Symlinkziele und beendet sich mit Fehler, wenn etwas fehlt.
Die Ausgabe darf nur bei Exitcode 0 als Beleg übernommen werden.
Zusätzlich Dateirechte, ACLs und benötigte Recovery-Dienste auf dem
unabhängigen Host prüfen; der Hashvergleich deckt diese Metadaten nicht ab.

## Signierte Attestierung

Erst nach erfolgreicher Wiederherstellung und nachgewiesener, automatischer Restic-Schlüsselverwendung eine
JSON-Datei mit exakt diesen Feldern erstellen (Platzhalter nicht als Belege
verwenden):

```json
{
  "kind": "heim_pc.restic_independent_full_restore.v1",
  "repository_id": "85ee278eeb58f42c26745796cb7b23239d4c7c01f5f4d00f2c10e216cefa4972",
  "backup_uuid": "9b626294-7913-4be0-88fa-96b314e96ee5",
  "source_host": "heim-pc-nixos",
  "restore_host": "<tatsaechlich-verwendeter-anderer-rechner>",
  "restore_medium": "external-backup-disk",
  "complete_restore": true,
  "off_host_recovery_access_verified": true,
  "completed_at_unix": 0,
  "snapshot_id": "<volle-64-stellige-Snapshot-ID>",
  "inventory": {
    "source_sha256": "<berechnete-64-stellige-SHA256>",
    "restored_sha256": "<identische-berechnete-SHA256>",
    "covered_paths": [
      "/home/alex", "/persist", "/etc",
      "/var/lib/tailscale", "/var/lib/NetworkManager",
      "/var/lib/nixos", "/var/lib/grabowski"
    ],
    "file_count": 0,
    "total_bytes": 0
  }
}
```

`inventory` aus `independent-inventory.json` übernehmen,
`completed_at_unix` nach Abschluss auf den tatsächlichen UTC-Unix-Zeitpunkt
setzen, Snapshot-/Repository-ID und Host nachprüfen. `complete_restore` und
`off_host_recovery_access_verified` nur bei tatsächlichem Erfolg auf `true`
setzen.

Den Schlüssel **auf dem unabhängigen Host** erzeugen und dort lassen:

```bash
openssl genpkey -algorithm RSA -pkeyopt rsa_keygen_bits:3072 \
  -out independent-restore-private.pem
chmod 600 independent-restore-private.pem
openssl pkey -in independent-restore-private.pem -pubout \
  -out independent-restore-public.pem
openssl dgst -sha256 -sign independent-restore-private.pem \
  -out independent-restore.json.sig independent-restore.json
openssl dgst -sha256 -verify independent-restore-public.pem \
  -signature independent-restore.json.sig independent-restore.json
```

Nur die **öffentliche** PEM-Datei, die signierte JSON-Datei und deren rohe
Signatur anschließend root-eigen mit nicht gruppen-/weltbeschreibbaren Rechten
nach `/persist/secrets/restic/` auf dem Heim-PC übernehmen:

- `independent-restore-public.pem`
- `independent-restore.json`
- `independent-restore.json.sig`

Der private Schlüssel **bleibt außerhalb**. Keine leere oder nachgestellte
Attestierung einspielen, um einen Timer grün zu bekommen. Ein neuer Signaturbeleg
ist für die spätere regelmäßige Retention zyklisch zu erneuern.

## Schutzbedingungen und Abnahme

Das `heim-pc-restic-retention`-System prüft vor `forget`/ `prune`
Repository-ID, Backup-Datenträger-UUID, Signatur, Frische, Snapshot,
Originalhost, die sieben Pfade und SHA256-Gleichheit. Ein echter `forget
--dry-run --json` wird ausgewertet; nur **exakte IDs** eigener NixOS-Snapshots
dürfen entfernt werden. Die attestierte ID und historische Pop!_OS-Snapshots
bleiben unangetastet. Ohne gültiges Attest startet der Löschjob nicht.

Eine durchgeführte unabhängige Wiederherstellung ist erst abgenommen, wenn
Snapshot-ID, Restore-Host, Inventar-SHA256, Recovery-Key-Zugriff, Restore-/Check-Logs
und unveränderte Historie frisch belegt sind. Die lokale Probe allein reicht
nicht. Keine pauschalen `restic unlock`-Befehle.

Die Verfügbarkeit des Schlüssels auf Heimberry wurde unabhängig vom PC-Dateisystem
geprüft; wiederholen lässt sich die Kopie über
`scripts/restic-recovery-key-to-heimberry.sh`, ohne den Schlüssel anzuzeigen.
Die Signatur der späteren Restore-Bestätigung ist eine automatisierte
Integritätsprüfung, **keine** zusätzliche Benutzerauthentifizierung.
Auch nach physischem PC-Ausfall wird kein manuelles Restic-Passwort verlangt.
