# heim-pc

**Versioniertes Operatorium-Entrée für den lokalen Rechner – mit Kartografie, Weltmodell und Drift-Orientierung.**

## Mission

`heim-pc` ist die versionierte Empfangshalle für Agenten und Menschen, die am lokalen Rechner-Kontext starten. Es beantwortet zuerst:

* Wo beginnt man?
* Welche Quellen gelten?
* Welche lokalen Flächen bleiben tabu?
* Wo liegt die kanonische Ökosystemkarte?

Die bisherige Kartografie-Rolle bleibt erhalten, wird aber unter diese Entrée-Rolle eingeordnet.

## These / Antithese / Synthese

**These:** Dieses Repository ist der richtige Ort für ein Operatorium-Entrée, weil es bereits das lokale Weltmodell für heim-pc, Repositories, Zonen und Drift beschreibt.

**Antithese:** Es darf nicht zu einer zweiten Ökosystemkarte, einem Home-Spiegel oder einem stillen Inhaltsdump werden.

**Synthese:** `heim-pc` pflegt kleine, reviewbare Einstiegs- und Orientierungsartefakte. Cabinet bleibt der kanonische Ort der Ökosystemkarte. `/home/alex` bekommt nur kurze lokale Pointer.

## Wahrheitsordnung

1. GitHub, CI, PR-Diffs und aktuelle Runtime-Belege sind Primärquellen für gegenwärtigen Zustand.
2. Cabinet ist die kanonische Quelle für die systemweite Ökosystemkarte.
3. `manifest/repo-index.yaml` ist die Quelle für kanonische Dokumente in diesem Repository.
4. `SYSTEM_MAP.md` wird daraus generiert und ist nur die Repo-Dokumentationskarte.
5. Lokale Pointer in `/home/alex` sind Wegweiser, keine versionierte Wahrheit.

## Erster Einstieg

* [AGENTS.md](AGENTS.md) – Agenten-/LLM-Einstieg mit Arbeitsregeln und Stop-Kriterien
* [Operatorium-Entrée](architecture/operatorium-entry.md) – normative Rolle dieses Repositories
* [Home-Entry Runtime Note](runtime/home-entry.md) – lokale Pointer-Logik und Grenzen
* [Software-Inventar](runtime/software-inventory.md) – operatorisch relevante Programme, Dienste und bekannte Caveats
* [SYSTEM_MAP.md](SYSTEM_MAP.md) – generierte Karte der kanonischen heim-pc-Dokumentation
* [Sicherheit](architecture/security.md) – Datenpolitik und Tabuflächen

## Direkter Karten-Pointer

Die systemweite Ökosystemkarte liegt nicht in diesem Repository, sondern in Cabinet:

* Cabinet-Einstieg: `~/repos/cabinet/index.md`
* Karten-Blueprint: `~/repos/cabinet/docs/blueprints/ecosystem-map-v0.md`
* Lesbare Mermaid-Übersicht: `~/repos/cabinet/rendered/ecosystem-map.mmd`
* Generierte Registry-Projektion: `~/repos/cabinet/rendered/ecosystem-registry-map.mmd`

Zum gerenderten Anschauen heute: die `.mmd`-Dateien in einem Editor mit Mermaid-Preview öffnen oder in einen Mermaid-Renderer kopieren. Eine spätere Leitstand-Ansicht ist der passende Dashboard-Ort; Cabinet bleibt Canon.

## Goldene Regel

> **Klein committen, groß auslagern. Privatflächen nicht zur Orientierung opfern.**

* Rohdaten → lokal, CI-Artefakte oder Releases, nicht in Git-Historie
* Nur kleine, reviewbare, kanonische Artefakte im Repository
* Keine Secrets, Browserprofile, Keyrings oder privaten Inhaltsflächen lesen oder ausgeben
* Keine zweite Systemkarte neben Cabinet pflegen

## Struktur

```
heim-pc/
├─ AGENTS.md       # Agenten-/LLM-Entrée
├─ architecture/   # Normatives Wissen (Konzepte, Policies, Security)
├─ runtime/        # Reality/Observations und lokale Betriebsnotizen
├─ manifest/       # Single source of truth für kanonische Dokumente und Checks
├─ config/         # Konfiguration (Roots, Excludes, Zonen)
├─ state/          # Kleiner aktueller Zustand (KI-lesbare reality outputs)
├─ timeline/       # Chronologische Historie (komprimierbar)
├─ snapshots/      # Aggregationen & Pointer auf große Daten
├─ contracts/      # Data contracts & JSON schemas
└─ .wgx/           # WGX-Integration (Fleet-konform)
```

## Kartografie-Rolle

Heim-PC bleibt die Verbindung zwischen lokalem Dateisystem und Heimgewebe-System. Es dient weiterhin als:

* Kartografie des Rechners: Dateisystem, Repositories, Zonen, Drift,
* Heimgewebe-taugliche Orientierung durch Index und Semantik,
* Historie und Drift-Tracking durch Timeline-Daten,
* strukturiertes Wissensmodell statt Dump-Repo.

Diese Rolle ist aber operativ begrenzt: Kartografie bedeutet Metadaten, Struktur und Pointer, nicht private Inhalte.

## Daten generieren (lokal)

GitHub Actions kann nicht das lokale Dateisystem scannen. Echte Kartografie-Daten werden lokal erzeugt und danach klein, geprüft und bewusst versioniert.

```bash
# Beispiel: mit rLens oder ähnlichem Tooling
rlens export-heim-pc --out /path/to/heim-pc

# Prüfen und committen
cd /path/to/heim-pc
git add state/ snapshots/
git commit -m "chore: update filesystem snapshot"
git push
```

## Validierung

Der `heim-pc-validate` Workflow prüft automatisch:

* JSON/YAML-Struktur,
* Unit Tests,
* Syntax- und Contract-Smokes,
* Repo-Index-Konsistenz,
* Dokument-Review-Alter,
* ob `SYSTEM_MAP.md` aus `manifest/repo-index.yaml` regenerierbar und aktuell ist.

## Documentation Zones

The documentation follows a strict zone model governed by `manifest/repo-index.yaml`:

* **`entry`**: top-level agent entry documents.
* **`norm`**: normative knowledge — how things should be.
* **`reality`**: observational knowledge — how things are currently described or observed.

For a complete overview of all canonical documents, their review status, and dependencies, see the auto-generated [SYSTEM_MAP.md](SYSTEM_MAP.md).

## Mehr erfahren

* [Weltmodell-Konzept](architecture/model.md) – Was ist das Weltmodell?
* [Operatorium-Entrée](architecture/operatorium-entry.md) – Wie heim-pc als lokale Empfangshalle funktioniert
* [Zonen & Bedeutungen](architecture/zones.md) – Semantische Bereiche
* [Drift-Definition](architecture/drift-policy.md) – Was bedeutet Drift und wie wird er erkannt?
* [Sicherheit](architecture/security.md) – Datenpolitik, Tabuflächen und Pfadgrenzen
* [Contracts](contracts/README.md) – Data schemas & versioning

## WGX-Integration

Dieses Repo ist Fleet-konform und nutzt WGX reusable workflows:

* **Guard**: Lint-Checks via `heimgewebe/wgx`
* **Smoke**: Konsistenz-Tests über Index, Pfade und Struktur
* **Validate**: Struktur-Validierung und Placeholder-Warnung

Workflows referenzieren zentrale WGX-Templates, um Fleet-Drift zu vermeiden.

## Lizenz

Siehe LICENSE-Datei im Repository.
