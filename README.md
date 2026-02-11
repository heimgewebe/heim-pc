# heim-pc

**Kartografie deines Rechners – ein versioniertes Weltmodell für Heimgewebe**

## Mission

Heim-PC ist die Verbindung zwischen deinem lokalen Dateisystem und dem Heimgewebe-System. Es dient als:

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
heim-pc/
├─ docs/           # Konzepte & Dokumentation
├─ config/         # Konfiguration (Roots, Excludes, Zonen)
├─ state/          # Aktueller Zustand (klein, KI-lesbar)
├─ timeline/       # Chronologische Historie (komprimierbar)
├─ snapshots/      # Aggregationen & Pointer auf große Daten
├─ contracts/      # Data contracts & JSON schemas
└─ .wgx/           # WGX-Integration (Fleet-konform)
```

## Quick Start

### Initial Setup

1. **Konfiguration anpassen**: `config/heim-pc.yml` mit deinen Root-Pfaden
2. **Zonen definieren**: `config/zones.yml` für semantische Bereiche

### Daten Generieren (Lokal)

⚠️ **Wichtig**: GitHub Actions kann nicht dein lokales Dateisystem scannen!

Echte Kartografie-Daten werden **lokal** erzeugt:

```bash
# Mit rLens oder ähnlichem Tooling
rlens export-heim-pc --out /path/to/heim-pc

# Prüfen und committen
cd /path/to/heim-pc
git add state/ snapshots/
git commit -m "chore: update filesystem snapshot"
git push
```

### Validierung (CI)

Der `heim-pc-validate` Workflow prüft automatisch:
* JSON/YAML Struktur-Validität
* Vorhandensein aller erforderlichen Dateien
* Ob Daten noch Placeholder sind (Warnung)

## Mehr erfahren

* [Weltmodell-Konzept](docs/model.md) – Was ist das "Weltmodell"? (inkl. Beispiele)
* [Zonen & Bedeutungen](docs/zones.md) – Semantische Bereiche
* [Drift-Definition](docs/drift.md) – Was bedeutet Drift und wie wird er erkannt?
* [Sicherheit](docs/security.md) – Token, Pfadgrenzen, Datenpolitik
* [Contracts](contracts/README.md) – Data schemas & versioning

## WGX-Integration

Dieses Repo ist Fleet-konform und nutzt WGX reusable workflows:

* **Guard**: Lint-Checks (YAML/JSON, actionlint) via `heimgewebe/wgx`
* **Smoke**: Konsistenz-Tests (Index lesbar? Pfade valide?) via `heimgewebe/wgx`
* **Validate**: Struktur-Validierung und Placeholder-Warnung

Workflows referenzieren zentrale WGX-Templates, um Fleet-Drift zu vermeiden.

## Lizenz

Siehe LICENSE-Datei im Repository.
