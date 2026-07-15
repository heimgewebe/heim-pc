---
id: agents.entry
role: action
status: canonical
last_reviewed: 2026-07-13
depends_on:
  - operatorium-entry
  - home-entry
  - security
verifies_with:
  - scripts/ci/check_repo_index_consistency.py
  - scripts/check_operator_entry.py
---

# AGENTS.md — heim-pc Operatorium-Entrée

## Zweck

Dieses Dokument ist der Einstieg für Agenten und LLMs, die im Repository `heimgewebe/heim-pc` oder über lokale Pointer in `/home/alex` landen.

`heim-pc` ist das versionierte Operatorium-Entrée für den lokalen Rechner. Es ordnet, wo ein Agent beginnt, welche Quellen gelten, wie lokale Repositories gefunden werden und welche Flächen nicht berührt werden dürfen.

Der kanonische Maschinenvertrag ist `manifest/operator-entry.v1.json`. Die lokale Projektion unter `~/.config/heimgewebe/operator-entry.v1.json` muss byteidentisch sein.

## Operatorrolle

* ChatGPT über Grabowski ist der Operator für Prüfung und Ausführung.
* Der Mensch liefert Ziel, Bedeutung, Freigaben und Abbruchentscheidungen; er wird nicht als Shell-Ausführer benutzt.
* Prosa ist Projektion. Maschinenlesbare Verträge und frische Primärquellen haben Vorrang.

## Wahrheitsordnung

1. Grabowski-Laufzeitidentität, konkrete Receipts, GitHub, CI, PR-Diffs und aktuelle Runtime-Belege sind Primärquellen für gegenwärtigen Zustand.
2. `manifest/operator-entry.v1.json` ist die kanonische lokale Einstiegskette und Locator-Quelle für heim-pc.
3. Der statische Systemkatalog unter `/home/alex/repos/systemkatalog` ist die kanonische Quelle für stabile Ökosystemsemantik und systemweite Orientierung; aktuelle Zustände bleiben bei ihren Primärquellen.
4. Bureau ist die Primärquelle für Aufgaben, Claims und Receipts.
5. `manifest/repo-index.yaml` ist die Quelle für die kanonischen Dokumente in diesem Repository.
6. `SYSTEM_MAP.md` ist daraus generiert und nur eine Repo-Dokumentationskarte, keine zweite Ökosystemkarte.
7. `/home/alex` ist lokale Landefläche mit kurzen Pointern, kein versioniertes Vollabbild und kein Git-Spiegel.
8. `state/index.json` und `state/repos.json` sind derzeit Placeholder-Daten und dürfen keine aktuellen Host- oder Repositoryclaims begründen.

## Erster Leseweg

1. Bei ChatGPT über Grabowski: `grabowski_status(view="evidence")`, `grabowski_agent_bootstrap()` und `grabowski_context(profile="concise")`.
2. `manifest/operator-entry.v1.json` für lokale Lokatoren, Einstiegskette und Wahrheitsauflösung.
3. `README.md` für die Rolle des Repositories.
4. `SYSTEM_MAP.md` für die kanonischen Dokumente dieses Repositories.
5. `architecture/operatorium-entry.md` für die normative Entrée-Architektur.
6. `runtime/home-entry.md` für die lokale Home-Projektion und deren Grenzen.
7. `architecture/security.md` vor jeder Aktion, die lokale Pfade, Runtime-Flächen oder Inhaltsnähe berührt.

## Arbeitsregeln

* Keine privaten Inhalte, Browserprofile, Keyrings, Agent-Runtime-Historien, Tokens, SSH-Schlüssel oder Secret-Flächen lesen oder ausgeben.
* Kein breiter Scan von `/home/alex`; zuerst den installierten Maschinenvertrag und dessen gezielte Lokatoren verwenden.
* Keine Home-Dateien ändern, wenn der Auftrag nur dieses Repository betrifft.
* Keine zweite Systemkarte in `heim-pc` aufbauen; für systemweite Zwecke, Grenzen, Wahrheitszuständigkeiten, Beziehungen und Einstiegspunkte auf den Systemkatalog verweisen.
* Bei gewöhnlicher Einzelrepo-Codearbeit den Systemkatalog nicht pauschal laden.
* `/home/alex/AGENTS.md`, `/home/alex/repos/AGENTS.md`, `/home/alex/README.md` und `~/.config/heimgewebe/operator-entry.v1.json` werden aus den versionierten Quellen durch `scripts/install_operator_entry.py` installiert.
* Keine Behauptung über aktuellen GitHub-, CI-, Task- oder Runtime-Stand ohne frische Prüfung.
* Kleine, reviewbare Dokument- und Vertrags-Slices bevorzugen; große Rohdaten oder Snapshots gehören nicht in die Git-Historie.
* Verwaltete automatisierte Builds müssen über `python3 scripts/managed_build.py plan` beziehungsweise `run` laufen; direkte interaktive Werkzeugaufrufe bleiben unverändert. Pins benötigen Grund und Ablaufzeit und erteilen weder Ausführungs- noch Löschberechtigung.
* Wenn lokaler Zustand, GitHub-Stand und Dokumentation widersprechen, bleibt der Widerspruch sichtbar und wird als Drift behandelt.
* Vor Mutation Branch, Head, Dirty-State, offene PRs, CI, Leases, Worktrees, Tasks und Prozesse prüfen; danach Zielzustand erneut lesen.

## Stop-Kriterien

Stoppe ohne Mutation, wenn:

* Grabowski-Identität, Branch, Head, Status oder Diff nicht lesbar sind.
* die lokale Operator-Entry-Projektion fehlt oder vom versionierten Vertrag abweicht und die Aufgabe von ihr abhängt.
* fremde Änderungen im Working Tree sichtbar sind.
* offene überlappende PRs, Worktrees, Leases, Tasks oder Prozesse existieren.
* ein Auftrag das Repository als vollständigen Spiegel von `/home/alex` behandeln will.
* eine Handlung private Inhaltsflächen, Credentials oder Browser-/Keyring-Daten berühren würde.
* Tests, Validatoren oder Self-Review fehlen, aber PR-Reife behauptet werden müsste.

## Minimalbericht

Am Ende einer Repo-Operation berichten:

* geänderte Dateien,
* geprüfte Quellen,
* Tests und Checks,
* Self-Review-Ergebnis,
* Commit/Push/PR-Status,
* lokale Projektionsprüfung,
* offene Leerstellen,
* Risiko/Nutzen,
* nächste Aktion.
