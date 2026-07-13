# Heimgewebe Repositories – Agenteneinstieg

Diese Datei ist ein lokaler Pointer für Arbeiten unter `/home/alex/repos`. Repository-eigene `AGENTS.md`-Dateien bleiben für die konkrete Arbeit vorrangig.

## Kanonischer Maschinenstart

Lies zuerst den installierten Host-Vertrag unter `/home/alex/.config/heimgewebe/operator-entry.v1.json`. Seine versionierte Quelle liegt in `/home/alex/repos/heim-pc/manifest/operator-entry.v1.json`.

Für ChatGPT über Grabowski beginnt der Live-Check mit `grabowski_status(view="evidence")` und `grabowski_agent_bootstrap()`. ChatGPT über Grabowski ist der Operator; der Mensch liefert Ziel, Bedeutung, Freigaben und Abbruchentscheidungen und soll nicht als Shell-Ausführer benutzt werden.

## Systemweite Orientierung

Konsultiere den kanonischen Systemkatalog unter `/home/alex/repos/systemkatalog`, wenn eine Frage:

- mehrere Repositories oder Systeme betrifft;
- Zweck oder Nicht-Zuständigkeit eines Systems klären muss;
- Wahrheitsbesitz, stabile Beziehungen oder Einstiegspunkte betrifft;
- eine systemweite Architekturannahme benötigt.

Nutze dafür bevorzugt die deterministische Leseoberfläche:

```bash
python3 /home/alex/repos/systemkatalog/scripts/systemkatalog_query.py system <name>
python3 /home/alex/repos/systemkatalog/scripts/systemkatalog_query.py truth-owner <domain>
python3 /home/alex/repos/systemkatalog/scripts/systemkatalog_query.py relations <name>
```

Bei gewöhnlicher Codearbeit in nur einem Repository wird der Systemkatalog nicht pauschal geladen.

## Grenzen

- Der Host-Vertrag und der Systemkatalog beschreiben Einstieg und stabile Semantik; sie sind keine Task-, PR-, CI- oder Runtime-Statussysteme.
- Aktuelle Zustände müssen bei GitHub, CI, Bureau, Grabowski, systemd, Logs oder Healthchecks frisch geprüft werden.
- Private Inhalte, Credentials und lokale Agentenhistorien dürfen nicht aus dem Katalog abgeleitet oder ohne ausdrücklichen Zweck gelesen werden.
- Fremde Dirty-States, Worktrees, Leases, Prozesse, Branches und laufende Arbeiten bleiben unverändert.
