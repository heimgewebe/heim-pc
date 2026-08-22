---
id: home-hygiene
role: norm
status: canonical
last_reviewed: 2026-08-22
depends_on:
  - operatorium-entry
  - security
  - storage-lifecycle
  - managed-builds
verifies_with:
  - config/home-hygiene.v1.json
  - scripts/home_hygiene.py
  - scripts/install_home_hygiene.py
  - tests/test_home_hygiene.py
---

# Home-Hygiene und Artefaktlebenszyklus

## Zweck

Der persönliche Ordner ist eine menschliche Einstiegsebene und kein unbegrenzter Arbeits-, Build- oder Probenraum. Technische Produzenten dürfen dort nicht dauerhaft lose Diffs, Reviews, Screenshots, Logs, Core-Dumps oder temporäre Dateien ablegen.

Der Vertrag trennt vier Flächen:

1. sichtbare menschliche Einstiege unter `$HOME`;
2. bewusst sichtbare technische Ergebnisse unter `$HOME/artifacts`;
3. Laufzustände und Receipts unter `$HOME/.local/state/heim-pc`;
4. regenerierbare Daten unter `$HOME/.cache`.

Er ersetzt weder den Worktree-Lifecycle noch den Managed-Cargo-Vertrag. Git-Checkouts bleiben beim Checkout-Reconciler; verwaltete Cargo-Identitäten bleiben bei `scripts/managed_cargo_gc.py`.

## Maschinenvertrag

`config/home-hygiene.v1.json` definiert:

- erlaubte sichtbare Top-Level-Einstiege;
- Artefaktkategorien;
- kontrolliert migrierbare Legacy-Artefaktwurzeln;
- eng benannte Muster für lose technische Dateien;
- Core-Dump-Pfad und Retention;
- unveränderliche Sicherheitsgrenzen.

Unbekannte Top-Level-Einträge sind ein Aufmerksamkeitssignal, keine Löschberechtigung. Der Inventarlauf liest nur unmittelbare sichtbare Metadaten und die dedizierte Core-Dump-Ablage. Versteckte Secret-, Browser- und Keyring-Flächen werden nicht traversiert.

## Zielstruktur

```text
$HOME/
├── Apps/
├── Bilder/
├── Dokumente/
├── Downloads/
├── Incoming/
├── Musik/
├── Schreibtisch/
├── Videos/
├── artifacts/
│   ├── audits/
│   ├── cleanup-backups/
│   ├── diffs/
│   ├── exports/
│   ├── legacy-home-root/
│   ├── logs/
│   ├── merges/
│   ├── patches/
│   ├── probes/
│   ├── receipts/
│   └── reviews/
├── models/
├── repos/
└── vm/
```

Laufzustände liegen unter:

```text
$HOME/.local/state/heim-pc/home-hygiene/
$HOME/.local/state/heim-pc/coredumps/
```

## Read-only Inventar

Der Standardlauf ist rein beobachtend:

```text
python3 scripts/home_hygiene.py inventory
```

Er erzeugt:

- Klassifikation aller sichtbaren unmittelbaren Home-Einträge;
- eng gefasste Kandidatenliste loser technischer Dateien;
- unbekannte Einträge;
- Anzahl und Gesamtgröße kontrollierter Core-Dumps;
- einen SHA-256-gebundenen Inventarbeleg.

Er begründet ausdrücklich keine Mutation, Nutzungslosigkeit, Backupfähigkeit oder Löschberechtigung.

Der installierte Timer `heim-pc-home-hygiene.timer` schreibt dieses Inventar wöchentlich nach:

```text
$HOME/.local/state/heim-pc/home-hygiene/latest-inventory.json
```

## Reversible Quarantäne

Lose technische Dateien werden zweistufig behandelt:

1. `plan-quarantine` erstellt einen hashgebundenen Plan;
2. `apply-quarantine` verlangt Plan-SHA und die exakte Bestätigung `apply-home-quarantine`.

Vor der ersten Wirkung werden für alle Kandidaten erneut geprüft:

- unmittelbare Lage unter `$HOME`;
- reguläre Nicht-Symlink-Datei;
- Gerät, Inode, Größe und Nanosekunden-Mtime;
- bei Dateien bis 64 MiB zusätzlich Inhalts-SHA-256;
- keine tatsächlich beobachteten Prozessreferenzen;
- freier, Home-gebundener Zielpfad;
- gleiches Dateisystem.

Die Prozessbeobachtung erfasst Arbeitsverzeichnis, Prozesswurzel, ausführbare Datei, offene Dateideskriptoren und dateigebundene Memory-Mappings. Gehärtete Prozesse können einzelne `/proc`-Details verbergen. Solche Lesefehler bleiben als `process_observation_warnings` im Plan und Receipt sichtbar, blockieren die atomare, reversible Umbenennung aber nicht pauschal. Jede tatsächlich beobachtete Referenz auf einen Kandidaten blockiert weiterhin.

Die Dateien werden nicht gelöscht, sondern nach

```text
$HOME/artifacts/legacy-home-root/YYYY-MM-DD/
```

verschoben. Unmittelbar vor jeder einzelnen Umbenennung werden Quellfingerabdruck und Zielfreiheit erneut geprüft. Jede Welle erhält ein Receipt mit Quell- und Zielpfaden sowie Restaurationshinweis. Ein Fehler nach begonnener Wirkung wird als `partial_failure` receiptiert und nicht als Erfolg geglättet.

## Legacy-Artefaktwurzeln

Die Verzeichnisse `audits`, `cleanup-backups`, `diffs`, `logs`, `merges`, `patches` und `review-artifacts` können über einen getrennten Plan in die kanonischen Unterverzeichnisse von `$HOME/artifacts` verschoben werden.

Vor der Migration gelten dieselben Grundgrenzen:

- reales Quellverzeichnis und begrenzter vollständiger Baumfingerabdruck;
- kein Mount- oder Gerätewechsel;
- keine tatsächlich beobachteten Prozessreferenzen;
- erneuter Fingerprint unmittelbar vor jeder Wirkung;
- Symlinks bleiben grundsätzlich verboten, außer eine einzelne Legacy-Wurzel erlaubt ausdrücklich interne Links; solche Links müssen streng auf ein existierendes Ziel innerhalb derselben Quellwurzel und desselben Dateisystems auflösen. Absolute interne Links sind nur zulässig, wenn zugleich ein Root-Kompatibilitätssymlink erhalten bleibt;
- ein nichtleeres Ziel bleibt grundsätzlich blockiert. Nur ausdrücklich mit `merge_existing` markierte Wurzeln dürfen kollisionsfreie unmittelbare Quelleinträge in ein vorhandenes Ziel verschieben. Schon ein vorhandener gleichnamiger Zielpfad blockiert die gesamte Wurzel; es gibt kein Überschreiben, Deduping nach Vermutung oder `--force`.

Aktuell nutzt nur `diffs` den kollisionsfreien Merge-Pfad. `logs` darf seine sechs intern gebundenen historischen Links erhalten und behält den Kompatibilitätssymlink, weil aktuelle Producer den Altpfad noch verwenden. `merges` bleibt bei einem nichtleeren Ziel fail-closed; insbesondere wird ein unterschiedliches `weltgewebe-production-backups/latest-pull.receipt` nicht automatisch ersetzt. Die übrigen Legacy-Einstiege verschwinden nach erfolgreicher Migration aus der sichtbaren Home-Wurzel.

Diese Migration ist nie automatisch. `apply-aliases` verlangt Plan-SHA und `apply-home-alias-migration`.

## Core-Dumps

Der Host besitzt kein installiertes `systemd-coredump`. Deshalb wird der Kernelpfad explizit auf eine eigentümerkontrollierte absolute Ablage geroutet:

```text
$HOME/.local/state/heim-pc/coredumps/core.%e.%p.%t
```

Der Installationsbeleg enthält einen root-seitigen, aber noch nicht angewendeten Plan für:

```text
/etc/sysctl.d/60-heim-pc-coredump.conf
/etc/security/limits.d/60-heim-pc-coredump.conf
```

Der Sysctl-Vertrag setzt einen absoluten Core-Pfad, deaktiviert die zusätzliche PID-Erweiterung und verhindert SUID-Dumps. Die PAM-Limits begrenzen neue Sitzungen auf 2 GiB je Core-Datei.

Die tägliche Unit `heim-pc-coredump-retention.timer` wirkt ausschließlich in der dedizierten Core-Ablage. Sie entfernt:

- Dateien älter als 14 Tage;
- Dateien oberhalb von 2 GiB;
- zusätzlich die ältesten Dateien, bis höchstens 5 GiB verbleiben.

Jede Datei bleibt nach ihrer letzten Änderung mindestens fünf Minuten unangetastet. Damit kann der Retentionslauf einen noch geschriebenen Core-Dump weder wegen seiner Größe noch wegen des Gesamtbudgets entfernen. Reichen ausschließlich solche jungen Dateien über das Budget hinaus, meldet das Receipt `deferred_unsettled_over_budget` statt einen falschen Erfolg.

Offen referenzierte Dateien bleiben erhalten und werden im Receipt ausgewiesen. Verschwindet eine Datei während der initialen Bestandsmessung, unmittelbar vor der Entfernung oder während der abschließenden Bestandsmessung durch einen konkurrierenden Vorgang, bleibt Inventar oder Retentionslauf erfolgreich receiptiert und weist dies unter `observation_warnings`, `initial_observation_warnings`, `concurrent_removal_warnings` beziehungsweise `post_observation_warnings` aus. Andere Dateien oder Verzeichnisse kann dieser Pfad nicht entfernen.

## Installation

`scripts/install_home_hygiene.py` installiert ausschließlich Blob-Inhalte des sauberen, erwarteten Git-HEADs in eine unveränderliche Releasewurzel:

```text
$HOME/.local/lib/heim-pc/home-hygiene/releases/<commit>/
```

Er erstellt die Artefakt- und State-Verzeichnisse, rendert und verifiziert vier User-Units, lädt systemd neu und kann beide Timer aktivieren. Mit `--start` wird nur der read-only Inventarlauf gestartet.

Vor jeder Anlage oder Dateiinstallation prüft der Installer jede vorhandene Pfadkomponente ab `$HOME`. Symlinks, fremder Besitz, Nicht-Verzeichnisse und eine Releasewurzel außerhalb von `$HOME` führen zum Abbruch. Dadurch kann keine scheinbar Home-gebundene Installation über einen vorgeschalteten Symlink aus dem vorgesehenen Baum ausbrechen.

Der Installer schreibt keine Root-Dateien. Der Root-Plan wird als Inhalt, Zielpfad und SHA-256 im Installationsreceipt ausgegeben und muss separat über den privilegierten, auditierten Operatorpfad angewendet werden.

## Sicherheitsgrenzen

Der Vertrag erlaubt nicht:

- pauschales Leeren von `$HOME` oder `$HOME/.cache`;
- Traversieren von Secret-, Browser- oder Keyring-Flächen;
- Entfernen unbekannter Dateien oder Verzeichnisse;
- Worktree- oder Repository-Cleanup;
- Cargo-Cache-Cleanup außerhalb von `managed_cargo_gc.py`;
- automatische Migration oder Quarantäne ohne exakten Plan und Bestätigung;
- Behauptung, ein unerwarteter Eintrag sei unbenutzt.

## Recovery

Quarantäne und Aliasmigration schreiben vor und nach der Wirkung gebundene Receipts. Die Wiederherstellung erfolgt ausschließlich gegen diese Pfade:

- Quarantäne: Ziel zurück an die aufgezeichnete Quelle verschieben;
- Aliasmigration im Replace-Modus: Kompatibilitätssymlink entfernen und Ziel zurück an Quelle verschieben;
- Aliasmigration im Merge-Modus: Quelle wieder anlegen und ausschließlich die im Receipt einzeln aufgezeichneten verschobenen Ziele an ihre Quellpfade zurückbewegen;
- Root-Routing: versionierte Dateien aus `/etc/sysctl.d` und `/etc/security/limits.d` entfernen oder auf den belegten Vorgängerinhalt zurücksetzen, danach Sysctl erneut laden;
- User-Units: Timer deaktivieren und commitgebundene Units entfernen.

Keine Recovery darf fremde Leases, Tasks, Prozesse, Dirty-States oder historische Receipts verändern.
