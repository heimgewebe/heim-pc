# webmaschine

**Kartografie deines Rechners – ein versioniertes Weltmodell für Heimgewebe**

## Mission

Webmaschine ist die Verbindung zwischen deinem lokalen Dateisystem und dem Heimgewebe-System. Es dient als:

* **Kartografie** deines Rechners (Dateisystem, Repositories, Zonen, Drift)
* **Heimgewebe-taugliche Orientierung** durch Index und Semantik
* **Historie & Drift-Tracking** durch Timeline-Daten
* **Strukturiertes Wissensmodell** – kein Dump-Repo ohne Konzept

## Goldene Regel

> **Klein committen, groß auslagern.**

* Rohdaten → `artifacts/` (CI) oder lokal, nicht in Git-Historie
* Nur kleine, reviewbare, kanonische Artefakte im Repository
* Große Snapshots als GitHub Artifacts oder Release Assets

## Struktur

```
webmaschine/
├─ docs/           # Konzepte & Dokumentation
├─ config/         # Konfiguration (Roots, Excludes, Zonen)
├─ state/          # Aktueller Zustand (klein, KI-lesbar)
├─ timeline/       # Chronologische Historie (komprimierbar)
├─ snapshots/      # Aggregationen & Pointer auf große Daten
└─ .wgx/           # WGX-Integration (Fleet-konform)
```

## Quick Start

1. **Konfiguration anpassen**: `config/webmaschine.yml` mit deinen Root-Pfaden
2. **Zonen definieren**: `config/zones.yml` für semantische Bereiche
3. **Index prüfen**: `state/index.json` gibt KI sofortigen Überblick
4. **Refresh ausführen**: GitHub Actions Workflow `webmaschine-refresh.yml` (manuell/dispatch)

## Mehr erfahren

* [Weltmodell-Konzept](docs/model.md) – Was ist das "Weltmodell"?
* [Zonen & Bedeutungen](docs/zones.md) – Semantische Bereiche
* [Drift-Definition](docs/drift.md) – Was bedeutet Drift und wie wird er erkannt?
* [Sicherheit](docs/security.md) – Token, Pfadgrenzen, Datenpolitik

## WGX-Integration

Dieses Repo ist Fleet-konform und nutzt WGX:

* **Guard**: Lint-Checks (YAML/JSON, actionlint)
* **Smoke**: Konsistenz-Tests (Index lesbar? Pfade valide?)

## Lizenz

Siehe LICENSE-Datei im Repository.