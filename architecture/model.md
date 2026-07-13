---
id: model
role: norm
status: canonical
last_reviewed: 2026-07-13
depends_on:
  - security
verifies_with:
  - scripts/check_operator_entry.py
---

# Lokales Weltmodell

## Dialektische Einordnung

**These:** Ein kleiner, maschinenlesbarer Hostzustand im Repository kann einem Operator schnelle Orientierung geben.

**Antithese:** Repo-gebundene Zustandsabbilder veralten, duplizieren Livewahrheit und können einen Agenten mit scheinpräzisen, aber falschen Daten fehlleiten.

**Synthese:** `heim-pc` versioniert den statischen Einstieg, Lokatoren, Schemata und Sicherheitsgrenzen. Volatile Zustände werden frisch aus ihren Primärquellen gelesen oder lokal außerhalb Git als quellengebundene Receipts erzeugt. Prosa und Snapshots sind Projektionen, keine zweite Wahrheit.

## Drei Ebenen

### 1. Statischer Host-Einstieg

Kanonisch im Repository:

* `manifest/operator-entry.v1.json` – Einstiegskette, Pfadvorlagen, Wahrheitszuständigkeiten und Grenzen;
* `.ai-context.yml` – kompakte Rollenklassifikation;
* `AGENTS.md` – Arbeits- und Stop-Regeln;
* `config/agents/` – installierbare lokale Pointer;
* `config/zones.yml` – semantische Hostzonen ohne Inhaltsdump.

Diese Ebene darf keine aktuelle Gesundheit, Taskpriorität, Branchstände oder Merge-Reife behaupten.

### 2. Lokale quellengebundene Betriebsartefakte

Außerhalb Git unter `~/.local/state/heim-pc/`:

* Installationsreceipts;
* Driftberichte;
* große oder volatile Inventare;
* Generatorausgaben mit Zeitpunkt, Quelle und Hashbindung.

Ein lokales Artefakt gilt nur für die im Receipt belegte Quelle und den belegten Zeitpunkt.

### 3. Primärquellen für Livezustand

* Grabowski: Laufzeit, Werkzeuge, Leases und Ausführung;
* Bureau: Aufgaben, Claims und Receipts;
* Git und GitHub: Branches, Commits, Pull Requests und Reviews;
* CI: technische Checks am exakten Head;
* systemd, Logs und Healthchecks: Dienste und Runtime;
* Systemkatalog: stabile Ökosystemsemantik, nicht Livegesundheit;
* RepoBrief/Lenskit: quellengebundener Repository-Kontext, nicht ungeprüfte Livewahrheit.

## Status der alten State-Dateien

`state/index.json` und `state/repos.json` sind historische Placeholder-Fixtures. Sie sind:

* kein Agenteneinstieg;
* keine aktive Host- oder Repository-Wahrheit;
* aus der aktiven Contract-Validierung und Frischeprüfung ausgeschlossen;
* im Operator-Entry-Vertrag ausdrücklich als aktuelle Wahrheit gesperrt.

Sie bleiben vorerst nur erhalten, weil bestehende zentrale Schemata und historische Dokumentation darauf verweisen. Eine spätere Entfernung oder ein neuer Generatorpfad benötigt einen eigenen, quellengebundenen Slice.

Andere Dateien unter `state/` dürfen nur dann aktuelle Aussagen tragen, wenn Herkunft, Zeitpunkt und Frischegrenze maschinenlesbar belegt sind.

## Kartografie ohne Inhaltsopfer

Heim-PC darf Struktur, Zonen, Programme, Dienste und technische Metadaten beschreiben. Es darf daraus keinen breiten Home-Scan oder privaten Inhaltsindex ableiten.

Nicht ohne ausdrücklichen Zweck und Autorität erfassen:

* Secrets, Schlüssel, Tokens und Keyrings;
* Browserprofile und Sessions;
* private Inhaltsbäume;
* Agentenverläufe;
* Rohdumps ohne Datenminimierung.

## Generatorvertrag für künftige Zustandsartefakte

Ein neuer Generator gilt erst als kanonisch nutzbar, wenn sein Ergebnis mindestens enthält:

* Schema- und Generatorversion;
* Erzeugungszeitpunkt in UTC;
* konkrete Quellen und erlaubte Scanbereiche;
* Quell- oder Ergebnis-Hashes;
* Frischeklasse oder Ablaufgrenze;
* ausgeschlossene Behauptungen;
* Tests gegen Placeholder, unaufgelöste Pfade, Secrets und ungebundene Momentaufnahmen.

Ohne diese Angaben bleibt das Ergebnis eine nichtkanonische Beobachtung.

## Abgrenzung

`heim-pc` ist kein Backup, kein Sync-Werkzeug, kein Dateimanager, keine Ökosystemdatenbank und kein Runtime-Dashboard. Es ist der private lokale Maschinen-Einstieg mit schmalen, überprüfbaren Pointern zu den jeweiligen Wahrheitsquellen.
