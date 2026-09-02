---
id: operatorium-entry
role: norm
status: canonical
last_reviewed: 2026-09-02
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

`heim-pc` wird als kleine, versionierte Empfangshalle gepflegt. Es erklärt, wo Agenten starten, welche Quellen gelten und welche Grenzen einzuhalten sind, und darf einen schmalen host-lokalen Sollvertrag für genau diesen Rechner tragen. Der Systemkatalog bleibt die kanonische Quelle stabiler Ökosystemsemantik. `/home/alex` bleibt lokale Landefläche mit kurzen Pointern.

## Rolle im Ökosystem

`heim-pc` verbindet drei Ebenen:

1. **Lokaler Einstieg:** Agenten können über lokale Pointer aus `/home/alex` hierher geführt werden.
2. **Versionierte Orientierung und Host-Sollvertrag:** Die Repo-Dokumente beschreiben stabile Regeln, Zonen, Sicherheitsgrenzen, Drift-Mechanik sowie die host-lokalen Invarianten und das austauschbare Ziel-Executor-Profil.
3. **Aktuelle Prüfung:** GitHub, CI, PR-Diffs und Runtime-Belege bleiben nötig, wenn Aktualität zählt.

Das Repository ersetzt weder den Systemkatalog noch aktuelle Runtime-Primärquellen.

## Abgrenzung zum Systemkatalog

Der Systemkatalog ist der kanonische Ort für Systemzwecke, Grenzen, Wahrheitsbesitz, stabile Beziehungen und Einstiegspunkte. `heim-pc` darf darauf verweisen und einen unabhängigen Driftalarm betreiben, aber keine konkurrierende Semantik pflegen.

Die `system-constitution` ist deshalb **kein zweiter Systemkatalog**: Sie besitzt ausschließlich den Sollvertrag des einzelnen Heim-PC-Hosts. Sie darf festlegen, wie dieser Host reproduzierbar, sicher, recoverbar und testbar sein soll, aber keine systemweiten Zuständigkeiten oder Zwecke anderer Komponenten neu definieren.

`SYSTEM_MAP.md` in diesem Repository ist enger geschnitten: Es ist eine generierte Karte der kanonischen heim-pc-Dokumentation aus `manifest/repo-index.yaml` und Frontmatter. Es ist keine vollständige Karte des Heimgewebe-Systems.

## Abgrenzung zu `/home/alex`

`/home/alex` ist eine lokale Landefläche. Dort können kurze Pointer liegen, zum Beispiel ein README oder ein AGENTS-Hinweis. Diese Pointer sollen Agenten zu den richtigen Repositories führen.

`/home/alex` soll nicht als versioniertes Vollabbild gepflegt werden. Private Inhalte, Browserprofile, Keyrings, Credentials, Agent-Runtime-Historien und persönliche Arbeitsflächen bleiben außerhalb des Repo-Entrées.

## Was hier versioniert werden soll

Geeignet für dieses Repository sind:

* normative Einstiegs- und Sicherheitsregeln,
* der schmale host-lokale Sollvertrag und austauschbare Executor-Profile,
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
* eine zweite Ökosystemkarte neben dem Systemkatalog.

## Typische Fehlannahmen

**Fehlannahme 1:** Wenn Agenten in `/home/alex` landen, muss `/home/alex` selbst ein Repository werden.

Korrektur: Ein kurzer lokaler Pointer reicht. Versionierte Wahrheit gehört in passende Repositories.

**Fehlannahme 2:** `heim-pc` muss die ganze Systemkarte enthalten.

Korrektur: `heim-pc` beschreibt den lokalen Einstieg. Der Systemkatalog bleibt die stabile Karte des größeren Systems; Leitstand zeigt sie read-only an.

**Fehlannahme 3:** Ein Agent darf zur Orientierung breit im Home-Verzeichnis suchen.

Korrektur: Orientierung beginnt mit Pointer, Repo-Dokumentation und Manifest. Breitere lokale Prüfung braucht Auftrag, Zweck und Sicherheitsgrenze.

## Pflegeprinzip

Jede Änderung am Entrée soll klein bleiben und drei Fragen beantworten:

1. Welche Orientierung wird verbessert?
2. Welche Quelle wird dadurch klarer oder näher an die Wahrheit gerückt?
3. Welche private oder driftanfällige Fläche wird bewusst nicht berührt?
