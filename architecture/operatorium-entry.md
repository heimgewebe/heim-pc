---
id: operatorium-entry
role: norm
status: canonical
last_reviewed: 2026-07-04
depends_on:
  - model
  - security
  - zones
  - drift-policy
verifies_with:
  - scripts/ci/check_repo_index_consistency.py
  - scripts/generate-system-map.py
---

# Operatorium-Entrée

## These

`heim-pc` ist der richtige Umbaukandidat für ein versioniertes Operatorium-Entrée, weil das Repository bereits als Kartografie- und Weltmodell-Fläche für den lokalen Rechner angelegt ist.

## Antithese

Ein lokales Entrée kann leicht zu viel wollen: eine zweite Systemkarte, ein Home-Spiegel, ein Agenten-Dump oder ein stiller Scan privater Flächen. Dann würde es nicht Orientierung schaffen, sondern neue Drift erzeugen.

## Synthese

`heim-pc` wird als kleine, versionierte Empfangshalle gepflegt. Es erklärt, wo Agenten starten, welche Quellen gelten und welche Grenzen einzuhalten sind. Cabinet bleibt die kanonische Ökosystemkarte. `/home/alex` bleibt lokale Landefläche mit kurzen Pointern.

## Rolle im Ökosystem

`heim-pc` verbindet drei Ebenen:

1. **Lokaler Einstieg:** Agenten können über lokale Pointer aus `/home/alex` hierher geführt werden.
2. **Versionierte Orientierung:** Die Repo-Dokumente beschreiben stabile Regeln, Zonen, Sicherheitsgrenzen und Drift-Mechanik.
3. **Aktuelle Prüfung:** GitHub, CI, PR-Diffs und Runtime-Belege bleiben nötig, wenn Aktualität zählt.

Das Repository ersetzt weder Cabinet noch die aktuelle Runtime.

## Abgrenzung zu Cabinet

Cabinet ist der kanonische Ort der systemweiten Ökosystemkarte. `heim-pc` darf auf diese Karte verweisen, aber keine konkurrierende Karte pflegen.

`SYSTEM_MAP.md` in diesem Repository ist enger geschnitten: Es ist eine generierte Karte der kanonischen heim-pc-Dokumentation aus `manifest/repo-index.yaml` und Frontmatter. Es ist keine vollständige Karte des Heimgewebe-Systems.

## Abgrenzung zu `/home/alex`

`/home/alex` ist eine lokale Landefläche. Dort können kurze Pointer liegen, zum Beispiel ein README oder ein AGENTS-Hinweis. Diese Pointer sollen Agenten zu den richtigen Repositories führen.

`/home/alex` soll nicht als versioniertes Vollabbild gepflegt werden. Private Inhalte, Browserprofile, Keyrings, Credentials, Agent-Runtime-Historien und persönliche Arbeitsflächen bleiben außerhalb des Repo-Entrées.

## Was hier versioniert werden soll

Geeignet für dieses Repository sind:

* normative Einstiegs- und Sicherheitsregeln,
* kleine, reviewbare Runtime-Hinweise,
* Manifest- und System-Map-Metadaten,
* Pointer auf kanonische Quellen,
* Drift- und Zonen-Modelle,
* CI- und Validator-Checks.

Nicht geeignet sind:

* vollständige Home-Snapshots,
* private Dateiinhalte,
* Secrets oder Keymaterial,
* Browser- oder Keyring-Daten,
* Chat- oder Agent-Runtime-Historien,
* eine zweite Ökosystemkarte neben Cabinet.

## Typische Fehlannahmen

**Fehlannahme 1:** Wenn Agenten in `/home/alex` landen, muss `/home/alex` selbst ein Repository werden.

Korrektur: Ein kurzer lokaler Pointer reicht. Versionierte Wahrheit gehört in passende Repositories.

**Fehlannahme 2:** `heim-pc` muss die ganze Systemkarte enthalten.

Korrektur: `heim-pc` beschreibt den lokalen Einstieg. Cabinet bleibt die Karte des größeren Systems.

**Fehlannahme 3:** Ein Agent darf zur Orientierung breit im Home-Verzeichnis suchen.

Korrektur: Orientierung beginnt mit Pointer, Repo-Dokumentation und Manifest. Breitere lokale Prüfung braucht Auftrag, Zweck und Sicherheitsgrenze.

## Pflegeprinzip

Jede Änderung am Entrée soll klein bleiben und drei Fragen beantworten:

1. Welche Orientierung wird verbessert?
2. Welche Quelle wird dadurch klarer oder näher an die Wahrheit gerückt?
3. Welche private oder driftanfällige Fläche wird bewusst nicht berührt?
