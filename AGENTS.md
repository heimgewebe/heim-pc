---
id: agents.entry
role: action
status: canonical
last_reviewed: 2026-07-04
depends_on:
  - operatorium-entry
  - home-entry
  - security
verifies_with:
  - scripts/ci/check_repo_index_consistency.py
---

# AGENTS.md — heim-pc Operatorium-Entrée

## Zweck

Dieses Dokument ist der Einstieg für Agenten und LLMs, die im Repository `heimgewebe/heim-pc` oder über lokale Pointer in `/home/alex` landen.

`heim-pc` ist das versionierte Operatorium-Entrée für den lokalen Rechner. Es ordnet, wo ein Agent beginnen soll, welche Quellen gelten und welche Flächen nicht berührt werden dürfen.

## Wahrheitsordnung

1. GitHub, CI, PR-Diffs und aktuelle Runtime-Belege sind Primärquellen für aktuellen Repo- und Betriebszustand.
2. Cabinet bleibt der kanonische Ort für die Ökosystemkarte und systemweite Orientierung.
3. `manifest/repo-index.yaml` ist die Quelle für die kanonischen Dokumente in diesem Repository.
4. `SYSTEM_MAP.md` ist daraus generiert und nur eine Repo-Dokumentationskarte, keine zweite Ökosystemkarte.
5. `/home/alex` ist lokale Landefläche mit kurzen Pointern, kein versioniertes Vollabbild und kein Git-Spiegel.

## Erster Leseweg

1. `README.md` für die Rolle des Repositories.
2. `SYSTEM_MAP.md` für die kanonischen Dokumente dieses Repositories.
3. `architecture/operatorium-entry.md` für die normative Entrée-Architektur.
4. `runtime/home-entry.md` für die lokale Home-Landefläche und deren Grenzen.
5. `architecture/security.md` vor jeder Aktion, die lokale Pfade, Runtime-Flächen oder Inhaltsnähe berührt.

## Arbeitsregeln

* Keine privaten Inhalte, Browserprofile, Keyrings, Agent-Runtime-Historien, Tokens, SSH-Schlüssel oder Secret-Flächen lesen oder ausgeben.
* Keine Home-Dateien ändern, wenn der Auftrag nur dieses Repository betrifft.
* Keine zweite Systemkarte in `heim-pc` aufbauen; dafür auf Cabinet verweisen.
* Keine Behauptung über aktuellen GitHub-, CI- oder Runtime-Stand ohne frische Prüfung.
* Kleine, reviewbare Dokument-Slices bevorzugen; große Rohdaten oder Snapshots gehören nicht in die Git-Historie.
* Wenn lokaler Zustand, GitHub-Stand und Dokumentation widersprechen, bleibt der Widerspruch sichtbar und wird als Drift behandelt.

## Stop-Kriterien

Stoppe ohne Mutation, wenn:

* Branch, Head, Status oder Diff nicht lesbar sind.
* Fremde Änderungen im Working Tree sichtbar sind.
* Offene überlappende PRs existieren.
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
* offene Leerstellen,
* Risiko/Nutzen,
* nächste Aktion.
