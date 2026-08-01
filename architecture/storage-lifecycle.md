---
id: storage-lifecycle
role: norm
status: canonical
last_reviewed: 2026-07-30
depends_on:
  - security
verifies_with:
  - scripts/storage_inventory.py
  - tests/test_storage_inventory.py
  - scripts/worktree_target_maintenance.py
  - tests/test_worktree_target_maintenance.py
  - tests/test_install_worktree_target_maintenance.py
  - scripts/storage_pressure_watch.py
  - tests/test_storage_pressure_watch.py
  - tests/test_install_storage_pressure_watch.py
---

# Speicher-Lifecycle

## Zweck

Temporäre und regenerierbare Daten auf dem heim-pc werden als verwaltete
Ressourcen behandelt. Der Vertrag trennt kanonische Daten, Dauerbeweise,
temporäre Arbeitsdaten und regenerierbare Caches.

`config/storage-lifecycle.v1.json` ist die maschinenlesbare Richtlinie.
`scripts/storage_inventory.py` erzeugt ausschließlich read-only Inventare.
Ein Inventar ist niemals eine Löschfreigabe.

## Invarianten

1. Symbolische Links werden nicht verfolgt.
2. Dateisystemgrenzen werden standardmäßig nicht überschritten.
3. Jeder bekannte Produzent besitzt Klasse, Owner, Budget und
   Bereinigungsstrategie.
4. Unbekannte oder fehlende Owner autorisieren keine automatische Bereinigung.
   Große unregistrierte Worktree-Kandidaten werden über begrenzte, namentlich
   gefilterte Discovery-Wurzeln sichtbar gemacht, aber nicht klassifiziert oder
   entfernt.
5. Dirty Worktrees, aktive Tasks, Prozesse, Leases, Docker-Volumes und
   Recovery-Beweise erfordern eigene Primärprüfungen.
6. Snapshot-Retention begrenzt nur Inventarhistorie, nicht Nutzdaten. Sie
   rotiert ausschließlich reguläre, einfach verlinkte, benutzereigene Dateien
   mit passendem Inventar-Kind und Policy-Identifier in einem echten,
   benutzereigenen State-Verzeichnis.
7. Dauerbeweise und große regenerierbare Nutzdaten müssen getrennt werden.

## Schwellen

Die globale Dateisystembelegung wird bei 60 Prozent als Hinweis, bei
75 Prozent als Warnung und bei 85 Prozent als kritisch klassifiziert.
Produzenten besitzen zusätzliche Byte-Budgets. Eine Überschreitung erzeugt
einen Befund, aber keine Löschung.

Budgets beziehen sich auf tatsächlich belegte Dateisystemblöcke (`size_bytes`).
Die logische Größe einschließlich Sparse-Bereichen wird getrennt als
`apparent_size_bytes` ausgewiesen. Dadurch kann eine große Sparse-Datei keinen
falschen Terabyte-Verbrauch vortäuschen.

## Bedienung

```bash
python3 scripts/storage_inventory.py
python3 scripts/storage_inventory.py   --state-dir ~/.local/state/heim-pc/storage-inventory
```

Die zweite Form schreibt atomar `latest.json` und eine begrenzte Reihe
zeitgestempelter Snapshots.

## Wirksamkeitsprüfung

Der revisionsgebundene Abschluss der 14-Tage-Prüfung liegt in
`architecture/storage-effectiveness-review-2026-07-29.md`. Das post-gate
Endinventar erfüllt das Mindestfenster, belässt alle Schwellen unverändert,
weist die aktive globale Budgetausnahme ausdrücklich aus und trennt erfolgreiche
Rückgewinnung von dauerhafter Budgeteinhaltung. Der Prüfauftrag kann damit
revisionsgebunden terminalisiert werden; Budgetkonformität wird ausdrücklich
nicht behauptet. Der Bericht erteilt keine Löschfreigabe.

## Grenzen

Das Inventar belegt Größen, Pfade und Budgetzustände zum Messzeitpunkt. Es
belegt nicht, dass ein Worktree entbehrlich, ein Backup ausreichend oder ein
Docker-Volume löschbar ist.


## Automatischer Rust-Target-Lebenszyklus

`config/worktree-target-policy.v1.json` verwaltet ausschließlich das Unterverzeichnis
`target` in ausdrücklich eingetragenen Rust-Worktrees. Quellcode, Git-Metadaten,
Branches und Worktrees sind keine Cleanup-Ziele.

Der Ablauf ist zweistufig:

1. Ein Plan bindet Policy-Hash, Checkout-Lifecycle, Tree-Identität, Alter, Budget
   und einen privilegierten, datensparsamen Prozessreferenz-Snapshot.
2. Apply wiederholt unmittelbar vor der Mutation Checkout-Lifecycle,
   Head/Branch, Prozessreferenzen und vollständigen Tree-Hash. Erst danach wird
   `target` atomar innerhalb desselben Dateisystems in eine private Quarantäne
   verschoben, nochmals identitätsgeprüft und entfernt.

Dirty, retinierte, archivierte, aktive oder unklassifizierbare Checkouts sowie
unvollständige Prozesssicht blockieren fail-closed. Bei 80 GiB gilt Warnbetrieb,
bei 120 GiB Hard-Limit-Betrieb. Im Warnbetrieb müssen Targets sieben Tage, im
Hard-Limit-Betrieb mindestens einen Tag unverändert sein. Pro Lauf gelten
zusätzliche Kandidaten- und Byte-Grenzen. Zwischen Plan und Apply darf der
globale Target-Bestand nur wachsen, solange die Schwellenklasse unverändert
bleibt; eine globale Schrumpfung oder ein Schwellenwechsel blockiert weiterhin
fail-closed. Ausgewählte Targets werden unabhängig davon über ihren vollständigen
Snapshot exakt revalidiert, sodass Wachstum eines unbeteiligten Builds keinen
falschen TOCTOU-Abbruch auslöst.

Der Rootbroker besitzt dabei keine Löschfunktion. Seine Aktion
`observe_process_references` liest nur `cwd`, `exe`, Prozesswurzel und offene
Dateideskriptoren und gibt ausschließlich Treffer innerhalb der angefragten
Target-Wurzeln zurück. Fremde Prozesspfade und Kommandozeilen werden nicht
projiziert.

Die installierte Runtime ist an einen exakten Git-Commit gebunden. Der reguläre
User-Timer läuft einmal täglich. Jeder Plan, Zwischenstand und Abschluss wird als
hashgebundener Receipt unter
`~/.local/state/heim-pc/worktree-target-maintenance` gespeichert.

## Wartungstakt und Speicher-Druckwächter

Schwere Inventur- und Cleanup-Läufe richten sich nach der Änderungsrate ihrer
Sicherheitsvoraussetzungen, nicht nach der Beobachtungsfrequenz. Managed Cargo
läuft regulär zweimal täglich, Rust-Targets einmal täglich. Die SLO-Grenzen des
Wartungsmonitors liegen deshalb bei 14 beziehungsweise 26 Stunden.

`heim-pc-storage-pressure-watch.timer` prüft stündlich ausschließlich die
`statvfs`-Werte des Root-Dateisystems und die letzte private Stichprobe. Er
durchsucht keine Worktrees oder Caches. Ein zusätzlicher schwerer Lauf wird nur
bei mindestens 70 Prozent Belegung, höchstens 500 GiB verfügbarem Speicher oder
einer auf mindestens 32 GiB pro Stunde normierten Wachstumsrate angefordert.
Cargo besitzt danach sechs Stunden, Targets zwölf Stunden Cooldown. Der Wächter
startet Dienste asynchron, erteilt selbst keine Löschfreigabe und ersetzt weder
Lifecycle-, Prozess- noch Evidenzprüfungen der Cleanup-Dienste.
