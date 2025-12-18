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

### Initial Setup

1. **Konfiguration anpassen**: `config/webmaschine.yml` mit deinen Root-Pfaden
2. **Zonen definieren**: `config/zones.yml` für semantische Bereiche

### Daten Generieren (Lokal)

⚠️ **Wichtig**: GitHub Actions kann nicht dein lokales Dateisystem scannen!

Echte Kartografie-Daten werden **lokal** erzeugt:

```bash
# Mit repolensd oder ähnlichem Tooling
repolensd export-webmaschine --out /path/to/webmaschine

# Prüfen und committen
cd /path/to/webmaschine
git add state/ snapshots/
git commit -m "chore: update filesystem snapshot"
git push
```

### Validierung (CI)

Der `webmaschine-validate` Workflow prüft automatisch:
* JSON/YAML Struktur-Validität
* Vorhandensein aller erforderlichen Dateien
* Ob Daten noch Placeholder sind (Warnung)

## Mehr erfahren

* [Weltmodell-Konzept](docs/model.md) – Was ist das "Weltmodell"?
* [Zonen & Bedeutungen](docs/zones.md) – Semantische Bereiche
* [Drift-Definition](docs/drift.md) – Was bedeutet Drift und wie wird er erkannt?
* [Sicherheit](docs/security.md) – Token, Pfadgrenzen, Datenpolitik

## WGX-Integration

Dieses Repo ist Fleet-konform und nutzt WGX:

* **Guard**: Lint-Checks (YAML/JSON, actionlint)
* **Smoke**: Konsistenz-Tests (Index lesbar? Pfade valide?)
* **Validate**: Struktur-Validierung und Placeholder-Warnung

*Hinweis: Die aktuellen Workflows sind temporäre Standalone-Implementierungen. Migration zu fleet-standard reusable workflows aus `heimgewebe/wgx` ist geplant.*

## Lizenz

Siehe LICENSE-Datei im Repository.