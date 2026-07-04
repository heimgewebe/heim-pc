---
id: home-entry
role: reality
status: canonical
last_reviewed: 2026-07-04
depends_on:
  - operatorium-entry
  - security
verifies_with:
  - scripts/ci/check_repo_index_consistency.py
  - scripts/generate-system-map.py
---

# Home-Entry Runtime Note

## Aktuelle Einordnung

`/home/alex` ist die lokale Landefläche für menschliche Arbeit, Terminal-Einstiege und Agentenstarts. Es soll nicht als versioniertes Vollabbild behandelt werden.

Diese Runtime-Notiz beschreibt die beabsichtigte Betriebsform: kurze lokale Pointer führen zu versionierten Repositories. Die eigentliche Wartung geschieht in diesen Repositories, nicht im Home-Verzeichnis als Ganzes.

## Erwartete Pointer-Form

Ein späterer lokaler Home-Pointer darf knapp sein:

* Verweis auf `~/repos/heim-pc` als Operatorium-Entrée für den lokalen Rechner.
* Verweis auf `~/repos/cabinet` als kanonische Ökosystemkarte.
* Warnung, keine privaten Inhaltsflächen ohne Auftrag und Sicherheitsprüfung zu lesen.

Der Pointer soll kein vollständiges Inhaltsverzeichnis von `/home/alex` sein.

## Bekannte Grenzen

* Home-Dateien sind lokale Betriebsartefakte und nicht automatisch Teil dieses Repositories.
* Der Zustand von `/home/alex/README.md` oder `/home/alex/AGENTS.md` muss vor einer konkreten Home-Pointer-Änderung frisch geprüft werden.
* Diese Notiz beweist nicht, dass lokale Pointer existieren oder aktuell sind.
* Für GitHub-, CI- und Runtime-Status gelten aktuelle Primärquellen, nicht diese Notiz.

## Sicherheitsgrenze

Ohne ausdrücklichen Auftrag und Zweckprüfung dürfen nicht gelesen oder ausgegeben werden:

* Credentials, Schlüssel, Tokens und Keyrings,
* Browserprofile und Sessiondaten,
* private Inhaltsverzeichnisse,
* Agent-Runtime-Historien,
* Roh-Snapshots und große lokale Dumps.

## Betriebslogik

Die richtige Bewegung ist schmal:

1. lokal landen,
2. Pointer lesen,
3. in das passende versionierte Repository wechseln,
4. dort Manifest, System-Map und Sicherheitsregeln prüfen,
5. erst dann konkrete Repo- oder Runtime-Arbeit ausführen.

Wenn diese Kette unterbrochen ist, ist das eine Drift- oder Entrée-Lücke, kein Grund für einen breiten Home-Scan.
