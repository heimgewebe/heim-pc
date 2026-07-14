---
id: storage-lifecycle
role: norm
status: canonical
last_reviewed: 2026-07-14
depends_on:
  - security
verifies_with:
  - scripts/storage_inventory.py
  - tests/test_storage_inventory.py
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

## Grenzen

Das Inventar belegt Größen, Pfade und Budgetzustände zum Messzeitpunkt. Es
belegt nicht, dass ein Worktree entbehrlich, ein Backup ausreichend oder ein
Docker-Volume löschbar ist.
