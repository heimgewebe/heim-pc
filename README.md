# heim-pc

**Versioniertes Operatorium-Entrée für den lokalen Rechner – maschinenlesbar, mit Kartografie, Weltmodell und Drift-Orientierung.**

## Mission

`heim-pc` ist die versionierte Empfangshalle für Agenten und Menschen, die am lokalen Rechner-Kontext starten. Es beantwortet zuerst:

* Wo beginnt ein Maschinenoperator deterministisch?
* Welche lokalen Repositories und Primärquellen gelten?
* Welche lokalen Flächen bleiben tabu?
* Wo liegt die kanonische Ökosystemkarte?

Die bisherige Kartografie-Rolle bleibt erhalten, wird aber unter diese Entrée-Rolle eingeordnet.

## These / Antithese / Synthese

**These:** Dieses Repository ist der richtige Ort für ein Operatorium-Entrée, weil es bereits das lokale Weltmodell für heim-pc, Repositories, Zonen und Drift beschreibt.

**Antithese:** Es darf nicht zu einer zweiten Ökosystemkarte, einem Home-Spiegel, einem stillen Inhaltsdump oder einem zweiten Runtime-Statusspeicher werden.

**Synthese:** `heim-pc` pflegt kleine, reviewbare Einstiegs-, Locator- und Orientierungsartefakte. Der Systemkatalog bleibt der kanonische Ort stabiler Ökosystemsemantik. Live-Zustand bleibt bei Grabowski, Bureau, GitHub, CI, systemd, Logs und Healthchecks. Das Home-Verzeichnis bekommt nur kurze lokale Projektionen.

## Operator- und Menschenrolle

* ChatGPT über Grabowski ist der Operator für Prüfung und Ausführung.
* Der Mensch liefert Ziel, Bedeutung, Freigaben und Abbruchentscheidungen; er soll nicht als Shell-Ausführer dienen.
* Maschinenlesbare Verträge und frische Primärquellen haben Vorrang vor Prosa.

## Wahrheitsordnung

1. Grabowski-Laufzeitidentität, konkrete Receipts, GitHub, CI, PR-Diffs und aktuelle Runtime-Belege sind Primärquellen für gegenwärtigen Zustand.
2. `manifest/operator-entry.v1.json` ist die kanonische lokale Einstiegskette und Locator-Quelle für heim-pc.
3. Der statische Systemkatalog ist die kanonische Quelle für Systemzwecke, Grenzen, Wahrheitsbesitz, stabile Beziehungen und systemweite Einstiegspunkte.
4. Bureau ist die Primärquelle für Aufgaben, Claims und Receipts.
5. `manifest/repo-index.yaml` ist die Quelle für kanonische Dokumente in diesem Repository.
6. `SYSTEM_MAP.md` wird daraus generiert und ist nur die Repo-Dokumentationskarte.
7. Lokale Pointer im Home-Verzeichnis sind Wegweiser, keine versionierte Wahrheit.
8. `state/index.json` und `state/repos.json` enthalten Placeholder-Daten und sind im Maschinenvertrag ausdrücklich als aktuelle Wahrheit ausgeschlossen.

## Erster Einstieg

* [Maschinenvertrag](manifest/operator-entry.v1.json) – kanonische lokale Einstiegskette, Primärquellen und Checkout-Lokatoren
* [.ai-context.yml](.ai-context.yml) – kompakte maschinenlesbare Rollen- und Einstiegsklassifikation
* [AGENTS.md](AGENTS.md) – Agenten-/LLM-Einstieg mit Arbeitsregeln und Stop-Kriterien
* [Operatorium-Entrée](architecture/operatorium-entry.md) – normative Rolle dieses Repositories
* [Home-Entry Runtime Note](runtime/home-entry.md) – lokale Projektion, Pointer-Logik und Grenzen
* [Software-Inventar](runtime/software-inventory.md) – operatorisch relevante Programme, Dienste und bekannte Caveats
* [Programminventar](runtime/program-inventory-summary.md) – kompakte Übersicht aus Root-/Paket-/Prozessscan; Rohlisten bleiben lokal
* [SYSTEM_MAP.md](SYSTEM_MAP.md) – generierte Karte der kanonischen heim-pc-Dokumentation
* [Sicherheit](architecture/security.md) – Datenpolitik und Tabuflächen

## Kanonischer Maschinenstart

Die versionierte Quelle ist `manifest/operator-entry.v1.json`. Öffentliche Pfade sind als `${HOME}`-Templates formuliert und müssen vor einem Dateizugriff gegen das absolute Home des Operatorprozesses aufgelöst werden. Der Vertrag wird byteidentisch nach `~/.config/heimgewebe/operator-entry.v1.json` projiziert. Zusätzlich werden kurze lokale Pointer als `~/AGENTS.md`, `~/repos/AGENTS.md` und `~/README.md` installiert.

```bash
python3 scripts/install_operator_entry.py                              # nur Plan, keine Mutation
python3 scripts/install_operator_entry.py --apply                      # nur ohne abweichende bestehende Pointer
python3 scripts/install_operator_entry.py --apply --replace-existing   # nach Prüfung des Plans
python3 scripts/check_operator_entry.py --require-installed
```

Der Vertrag enthält absichtlich keine Live-Gesundheit, Taskpriorität, Branchstände oder Merge-Reife. Er nennt nur die Startsequenz, lokale Lokatoren, Primärquellen, ausgeschlossene Scheinquellen und Sicherheitsgrenzen.

Der Installer arbeitet fail-closed: Er sperrt parallele Installationen, bindet Writes an den gelesenen Vorzustand, öffnet die jeweilige letzte Pfadkomponente mit `O_NOFOLLOW`, lehnt erkannte Symlink-Ziele und -Eltern ab und ersetzt abweichende bestehende Pointer nur mit `--replace-existing`. Ein absichtlicher paralleler Austausch eines übergeordneten Verzeichnisses ist damit nicht vollständig ausgeschlossen. Vor dem atomaren Ersetzen werden Backups unter `~/.local/state/heim-pc/operator-entry-backups/` angelegt. Der maschinenlesbare Installationsbeleg liegt unter `~/.local/state/heim-pc/operator-entry-install-receipt.v1.json`. Die vier Dateien werden einzeln atomar geschrieben; eine atomare Gesamttransaktion über alle Dateien wird ausdrücklich nicht behauptet.

Für ChatGPT über Grabowski beginnt jede neue Operatorroute mit:

1. `grabowski_status(view="evidence")` für Runtime-Identität, Integrität und Connector-Warnungen;
2. `grabowski_agent_bootstrap()` für den gebundenen Ausführungsvertrag;
3. `grabowski_context(profile="concise")` für kompakten Operator-Kontext ohne Prosa als Livewahrheit;
4. Lesen des installierten JSON-Vertrags;
5. Auflösen von `${HOME}` gegen das absolute Operator-Home; unaufgelöste Variablen blockieren Dateizugriffe;
6. Klassifikation als Einzelrepo-, systemweiter, Host-, Task- oder Historienfall;
7. gezieltes Lesen der referenzierten Primärquellen und abschließender zielbezogener Live-Read vor Mutation.

## Direkter Systemkatalog-Pointer

Die systemweite stabile Semantik liegt nicht in diesem Repository, sondern im Systemkatalog:

* Agenteneinstieg: `~/repos/systemkatalog/AGENTS.md`
* Lesbare Katalogansicht: `~/repos/systemkatalog/rendered/system-catalog.md`
* Generierte Registry-Karte: `~/repos/systemkatalog/rendered/ecosystem-registry-map.mmd`
* Commit- und hashgebundener Verbraucher-Lieferschein: `~/repos/systemkatalog/rendered/ecosystem-map-artifact-manifest.json`
* Deterministische Abfrage: `python3 ~/repos/systemkatalog/scripts/systemkatalog_query.py system <name>`

Leitstand zeigt die Karte read-only an. Für aktuelle Aufgaben, PRs, CI oder Runtime-Gesundheit gelten weiterhin Bureau, GitHub, CI, Grabowski, systemd, Logs und Healthchecks.

## Gemeinsamer Agenteneinstieg und Drift-Watchdog

`config/agents/repos-root-AGENTS.md` ist die versionierte Vorlage für `~/repos/AGENTS.md`. Sie beginnt beim Host-Maschinenvertrag und verweist nur bei repositoryübergreifenden Systemfragen auf den Systemkatalog. Dadurch wird bei gewöhnlicher Einzelrepo-Arbeit kein unnötiger Gesamtkontext geladen.

Der stündliche `systemkatalog-drift-watch.timer` prüft unabhängig vom GitHub-Zeitplan Organisations-, Fleet- und Primärquellendrift. Er darf keine Semantik schreiben oder mergen. Bei materieller Drift registriert er höchstens einen deduplizierten Bureau-Kandidaten und legt Bericht sowie proposal-only Vorschlag lokal unter `~/.local/state/heim-pc/systemkatalog-drift-watch/` ab.

```bash
python3 scripts/install_systemkatalog_reliability.py          # Plan anzeigen
python3 scripts/install_systemkatalog_reliability.py --apply --enable
```

## Goldene Regel

> **Klein committen, groß auslagern. Privatflächen nicht zur Orientierung opfern.**

* Rohdaten → lokal, CI-Artefakte oder Releases, nicht in Git-Historie
* Nur kleine, reviewbare, kanonische Artefakte im Repository
* Keine Secrets, Browserprofile, Keyrings oder privaten Inhaltsflächen lesen oder ausgeben
* Keine zweite Systemkarte neben dem Systemkatalog pflegen
* Keine Live-Zustände in den statischen Operator-Entry-Vertrag kopieren
* Placeholder-Dateien nicht als Wahrheit behandeln

## Struktur

```text
heim-pc/
├─ .ai-context.yml                    # Maschinenlesbare Rollen- und Einstiegsklassifikation
├─ AGENTS.md                          # Agenten-/LLM-Entrée
├─ architecture/                      # Normatives Wissen (Konzepte, Policies, Security)
├─ runtime/                           # Reality/Observations und lokale Betriebsnotizen
├─ manifest/operator-entry.v1.json    # Kanonischer lokaler Maschinenstart
├─ manifest/repo-index.yaml           # Kanonische Dokumente und Checks
├─ config/agents/                     # Installierbare lokale Pointer
├─ state/                             # Legacy-Fixtures und nur quellengebundene Beobachtungen
├─ timeline/                          # Chronologische Historie (komprimierbar)
├─ snapshots/                         # Aggregationen & Pointer auf große Daten
├─ contracts/                         # Verweis auf zentrale Metarepo-Verträge
└─ .wgx/                              # WGX-Integration (Fleet-konform)
```

## Kartografie-Rolle

Heim-PC bleibt die Verbindung zwischen lokalem Dateisystem und Heimgewebe-System. Es dient weiterhin als:

* Kartografie des Rechners: Dateisystem, Repositories, Zonen, Drift,
* Heimgewebe-taugliche Orientierung durch Zonen, Lokatoren und quellengebundene Inventare,
* Historie und Drift-Tracking durch Timeline-Daten,
* strukturiertes Wissensmodell statt Dump-Repo.

Diese Rolle ist aber operativ begrenzt: Kartografie bedeutet Metadaten, Struktur und Pointer, nicht private Inhalte. Atlas unterscheidet dabei logische Dateilänge von tatsächlich belegten Dateisystemblöcken; keine der beiden Größen ist ein Backup- oder Wiederherstellungsbeleg. Konventionelle Core-Dump-Namen bleiben aus Standardkartierungen ausgeschlossen. Atlas löscht sie nicht und ist keine Speicherbereinigung.

## Zustandsartefakte erzeugen

GitHub Actions kann den lokalen Rechner nicht als Primärquelle beobachten. Volatile Inventare und Driftberichte werden deshalb lokal außerhalb Git erzeugt. Ein Ergebnis darf erst versioniert oder als Operatorwahrheit genutzt werden, wenn Generatorversion, UTC-Zeitpunkt, erlaubte Quellen, Hashbindung, Frischegrenze und ausgeschlossene Behauptungen maschinenlesbar enthalten und getestet sind.

`state/index.json` und `state/repos.json` erfüllen diesen Vertrag derzeit nicht. Sie bleiben Legacy-Fixtures und werden weder durch CI-Frischechecks noch durch die aktive Contract-Validierung als aktuelle Wahrheit behandelt.

## Validierung

Der `heim-pc-validate` Workflow prüft automatisch:

* JSON/YAML-Struktur,
* Unit Tests,
* Syntax- und Contract-Smokes,
* Repo-Index-Konsistenz,
* Dokument-Review-Alter,
* Struktur und statische Grenzen des Operator-Entry-Vertrags,
* Übereinstimmung der kompakten `.ai-context.yml`-Klassifikation,
* `${HOME}`-Resolververtrag und Ausschluss aufgelöster privater Hostpfade aus der öffentlichen Vorlage,
* ob `SYSTEM_MAP.md` aus `manifest/repo-index.yaml` regenerierbar und aktuell ist.

`python3 scripts/check_operator_entry.py --require-installed` prüft zusätzlich lokal, ob der Maschinenvertrag und alle drei Pointer installiert und bytegleich sind. Der persistente Installationsbeleg muss an den aktuellen Vertrags-Hash gebunden sein und die attestierten Zieldateien müssen weiterhin exakt übereinstimmen.

Ein grüner Lauf belegt Struktur- und Projektionskonsistenz. Er belegt nicht automatisch Runtime-Korrektheit, fachliche Vollständigkeit, Connector-Frische oder Merge-Reife.

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
* [Contracts](contracts/README.md) – zentrale Data-Schemas und Versionierung

## WGX-Integration

Dieses Repo ist Fleet-konform und nutzt WGX reusable workflows:

* **Guard**: Lint-Checks via `heimgewebe/wgx`
* **Smoke**: Konsistenz-Tests über Index, Pfade und Struktur
* **Validate**: Struktur-Validierung und Placeholder-Warnung

Workflows referenzieren zentrale WGX-Templates, um Fleet-Drift zu vermeiden.

## Lizenz

Siehe LICENSE-Datei im Repository.
